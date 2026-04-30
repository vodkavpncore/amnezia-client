/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bypassrouter_win.h"

// _WINSOCKAPI_ is defined project-wide so <windows.h> skips winsock 1.x.
// winsock2.h must come before any header that pulls ws2def.h transitively.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QScopeGuard>
#include <cstdio>
#include <mutex>

#include "leakdetector.h"
#include "logger.h"
#include "nattable.h"
#include "prefixtrie.h"
#include "windivert_shim.h"

#pragma comment(lib, "iphlpapi.lib")

namespace {

Logger logger("BypassRouter");

// ---------------------------------------------------------------------------
// WinDivert dynamic loader. WinDivert.dll is shipped alongside the service
// executable; we LoadLibrary at runtime to avoid an import-table dependency
// (so the service can launch even if the DLL is missing — bypass simply
// stays disabled in that case).
// ---------------------------------------------------------------------------
struct WinDivertApi {
  HMODULE dll = nullptr;
  PFN_WinDivertOpen WinDivertOpen = nullptr;
  PFN_WinDivertRecv WinDivertRecv = nullptr;
  PFN_WinDivertSend WinDivertSend = nullptr;
  PFN_WinDivertShutdown WinDivertShutdown = nullptr;
  PFN_WinDivertClose WinDivertClose = nullptr;
  PFN_WinDivertHelperCalcChecksums WinDivertHelperCalcChecksums = nullptr;

  bool loaded() const { return dll != nullptr; }
};

WinDivertApi g_wd;
std::once_flag g_wdLoadFlag;

template <typename Fn>
bool resolve(HMODULE dll, const char* name, Fn* out) {
  *out = reinterpret_cast<Fn>(GetProcAddress(dll, name));
  if (!*out) {
    logger.error() << "WinDivert.dll missing export:" << name;
    return false;
  }
  return true;
}

bool ensureWinDivertLoaded() {
  std::call_once(g_wdLoadFlag, []() {
    const QString sidecar =
        QCoreApplication::applicationDirPath() + "/WinDivert.dll";
    g_wd.dll = LoadLibraryW(reinterpret_cast<LPCWSTR>(sidecar.utf16()));
    if (!g_wd.dll) g_wd.dll = LoadLibraryW(L"WinDivert.dll");
    if (!g_wd.dll) {
      logger.error() << "WinDivert.dll not found (searched" << sidecar
                     << "and PATH)";
      return;
    }
    bool ok = true;
    ok &= resolve(g_wd.dll, "WinDivertOpen", &g_wd.WinDivertOpen);
    ok &= resolve(g_wd.dll, "WinDivertRecv", &g_wd.WinDivertRecv);
    ok &= resolve(g_wd.dll, "WinDivertSend", &g_wd.WinDivertSend);
    ok &= resolve(g_wd.dll, "WinDivertShutdown", &g_wd.WinDivertShutdown);
    ok &= resolve(g_wd.dll, "WinDivertClose", &g_wd.WinDivertClose);
    ok &= resolve(g_wd.dll, "WinDivertHelperCalcChecksums",
                  &g_wd.WinDivertHelperCalcChecksums);
    if (!ok) {
      FreeLibrary(g_wd.dll);
      g_wd = {};
    }
  });
  return g_wd.loaded();
}

// ---------------------------------------------------------------------------
// Packet helpers. Operate on raw IPv4 packet bytes; no struct overlays so
// alignment and endianness are explicit.
// ---------------------------------------------------------------------------
constexpr int kIpHdrMin = 20;
constexpr int kProtoOff = 9;
constexpr int kSrcIpOff = 12;
constexpr int kDstIpOff = 16;

inline uint16_t read16be(const uint8_t* p) noexcept {
  return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t read32be(const uint8_t* p) noexcept {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void write16be(uint8_t* p, uint16_t v) noexcept {
  p[0] = uint8_t(v >> 8);
  p[1] = uint8_t(v & 0xff);
}
inline void write32be(uint8_t* p, uint32_t v) noexcept {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v & 0xff);
}

struct ParsedPacket {
  uint8_t proto = 0;
  uint8_t ihl = 0;
  uint32_t srcIp = 0;
  uint32_t dstIp = 0;
  uint16_t srcPort = 0;
  uint16_t dstPort = 0;
  uint8_t tcpFlags = 0;  // valid only when proto == IPPROTO_TCP
  bool valid = false;
};

ParsedPacket parsePacket(const uint8_t* buf, UINT len) noexcept {
  ParsedPacket p;
  if (len < kIpHdrMin) return p;
  if ((buf[0] >> 4) != 4) return p;

  const uint8_t ihl = (buf[0] & 0x0f) * 4;
  if (ihl < kIpHdrMin || len < ihl) return p;

  const uint8_t proto = buf[kProtoOff];
  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return p;

  if (len < UINT(ihl + 4)) return p;

  p.ihl = ihl;
  p.proto = proto;
  p.srcIp = read32be(buf + kSrcIpOff);
  p.dstIp = read32be(buf + kDstIpOff);
  p.srcPort = read16be(buf + ihl + 0);
  p.dstPort = read16be(buf + ihl + 2);

  if (proto == IPPROTO_TCP && len >= UINT(ihl + 14)) {
    p.tcpFlags = buf[ihl + 13];
  }
  p.valid = true;
  return p;
}

// Force WinDivert to recompute IP/TCP/UDP checksums in-place after we have
// mutated the packet. Cheap (~50 ns) and the safe-by-default option.
void recomputeChecksums(uint8_t* buf, UINT len, WINDIVERT_ADDRESS* addr) {
  addr->IPChecksum = 0;
  addr->TCPChecksum = 0;
  addr->UDPChecksum = 0;
  g_wd.WinDivertHelperCalcChecksums(buf, len, addr, /*flags=*/0);
}

// ---------------------------------------------------------------------------
// Interface resolution.
// ---------------------------------------------------------------------------
quint32 ifIndexFromLuid(quint64 luidValue) {
  NET_LUID luid;
  luid.Value = luidValue;
  NET_IFINDEX idx = 0;
  if (ConvertInterfaceLuidToIndex(&luid, &idx) != NO_ERROR) return 0;
  return static_cast<quint32>(idx);
}

bool primaryIPv4ForLuid(quint64 luidValue, uint32_t* outHostOrder) {
  PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
  if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR) return false;
  auto guard = qScopeGuard([table]() { FreeMibTable(table); });

  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const auto& row = table->Table[i];
    if (row.InterfaceLuid.Value != luidValue) continue;
    if (row.Address.si_family != AF_INET) continue;
    if (row.DadState != IpDadStatePreferred) continue;

    const auto& sa = row.Address.Ipv4.sin_addr;
    const uint32_t addr = (uint32_t(sa.S_un.S_un_b.s_b1) << 24) |
                          (uint32_t(sa.S_un.S_un_b.s_b2) << 16) |
                          (uint32_t(sa.S_un.S_un_b.s_b3) << 8) |
                          uint32_t(sa.S_un.S_un_b.s_b4);
    // Skip link-local (169.254.0.0/16) — the OS picks them only as a
    // fallback when DHCP fails.
    if ((addr & 0xffff0000) == 0xa9fe0000) continue;
    *outHostOrder = addr;
    return true;
  }
  return false;
}

}  // namespace

// ===========================================================================
// BypassRouter — public API
// ===========================================================================

BypassRouter::BypassRouter(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(BypassRouter);
}

BypassRouter::~BypassRouter() {
  stop();
  MZ_COUNT_DTOR(BypassRouter);
}

quint32 BypassRouter::luidToIfIndex(quint64 luid) {
  return ifIndexFromLuid(luid);
}

bool BypassRouter::resolvePhysicalInterface(quint64 tunnelLuid,
                                            PhysIface* out) {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR) return false;
  auto guard = qScopeGuard([table]() { FreeMibTable(table); });

  ULONG bestMetric = ULONG_MAX;
  PhysIface best;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const auto& row = table->Table[i];
    if (row.DestinationPrefix.PrefixLength != 0) continue;  // default route
    if (row.InterfaceLuid.Value == tunnelLuid) continue;    // skip tunnel

    MIB_IPINTERFACE_ROW iface;
    InitializeIpInterfaceEntry(&iface);
    iface.InterfaceLuid = row.InterfaceLuid;
    iface.Family = AF_INET;
    if (GetIpInterfaceEntry(&iface) != NO_ERROR) continue;
    if (!iface.Connected) continue;

    const ULONG metric = row.Metric + iface.Metric;
    if (metric < bestMetric) {
      bestMetric = metric;
      best.luid = row.InterfaceLuid.Value;
      best.ifIdx = static_cast<quint32>(row.InterfaceIndex);
    }
  }

  if (best.luid == 0) return false;
  if (!primaryIPv4ForLuid(best.luid, &best.ipv4)) {
    logger.error() << "Physical iface" << best.ifIdx
                   << "has no preferred IPv4 address";
    return false;
  }
  *out = best;
  return true;
}

bool BypassRouter::start(quint64 tunnelLuid) {
  if (m_active.load(std::memory_order_acquire)) return true;

  m_subnetsFilePath = QString::fromUtf8(qgetenv("AMNEZIA_BYPASS_SUBNETS_FILE"));
  if (m_subnetsFilePath.isEmpty()) {
    logger.info() << "AMNEZIA_BYPASS_SUBNETS_FILE not set; bypass disabled";
    return false;
  }
  if (!QFileInfo::exists(m_subnetsFilePath)) {
    logger.error() << "Bypass file does not exist:" << m_subnetsFilePath;
    return false;
  }

  int loaded = 0, rejected = 0;
  auto trie = PrefixTrie::fromFile(m_subnetsFilePath, &loaded, &rejected);
  if (!trie) return false;
  m_trie.store(std::move(trie), std::memory_order_release);

  if (!resolvePhysicalInterface(tunnelLuid, &m_phys)) {
    logger.error() << "No usable physical interface; bypass disabled";
    return false;
  }
  m_tunnelLuid = tunnelLuid;
  m_tunnelIfIdx = luidToIfIndex(tunnelLuid);
  if (m_tunnelIfIdx == 0) {
    logger.error() << "Cannot resolve tunnel ifIdx";
    return false;
  }

  if (!ensureWinDivertLoaded()) return false;

  // Filter narrows what crosses the user/kernel boundary:
  //   * outbound on the WireGuard adapter (tcp or udp) — every candidate
  //     for redirection.
  //   * inbound on the physical NIC where the destination port falls in
  //     our NAT pool — only response packets to flows we redirected.
  char filter[768];
  std::snprintf(filter, sizeof(filter),
                "ip and ("
                "(outbound and ifIdx == %u and (tcp or udp))"
                " or "
                "(inbound and ifIdx == %u and ("
                "(tcp and tcp.DstPort >= %u and tcp.DstPort <= %u)"
                " or "
                "(udp and udp.DstPort >= %u and udp.DstPort <= %u)"
                "))"
                ")",
                m_tunnelIfIdx, m_phys.ifIdx, NatTable::kPoolMin,
                NatTable::kPoolMax, NatTable::kPoolMin, NatTable::kPoolMax);

  m_handle = g_wd.WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK,
                                /*priority=*/0, /*flags=*/0);
  if (m_handle == INVALID_HANDLE_VALUE) {
    logger.error() << "WinDivertOpen failed; GetLastError=" << GetLastError()
                   << "(driver installed? running as SYSTEM?)";
    return false;
  }

  m_active.store(true, std::memory_order_release);
  m_worker = std::thread([this]() { workerLoop(); });

  logger.info() << "Bypass router up:" << loaded << "prefixes, rejected"
                << rejected << "; tunnel ifIdx=" << m_tunnelIfIdx
                << "phys ifIdx=" << m_phys.ifIdx
                << QString("phys ip=%1.%2.%3.%4")
                       .arg((m_phys.ipv4 >> 24) & 0xff)
                       .arg((m_phys.ipv4 >> 16) & 0xff)
                       .arg((m_phys.ipv4 >> 8) & 0xff)
                       .arg(m_phys.ipv4 & 0xff);
  return true;
}

void BypassRouter::stop() {
  // exchange ensures only one caller runs the shutdown sequence.
  if (!m_active.exchange(false, std::memory_order_acq_rel)) return;

  if (m_handle != INVALID_HANDLE_VALUE && g_wd.WinDivertShutdown) {
    g_wd.WinDivertShutdown(m_handle, WINDIVERT_SHUTDOWN_BOTH);
  }
  if (m_worker.joinable()) m_worker.join();
  if (m_handle != INVALID_HANDLE_VALUE) {
    g_wd.WinDivertClose(m_handle);
    m_handle = INVALID_HANDLE_VALUE;
  }
  m_trie.store(nullptr, std::memory_order_release);
  logger.info() << "Bypass router down";
}

void BypassRouter::reloadSubnets() {
  if (!m_active.load(std::memory_order_acquire)) return;
  if (m_subnetsFilePath.isEmpty()) return;

  int loaded = 0, rejected = 0;
  auto fresh = PrefixTrie::fromFile(m_subnetsFilePath, &loaded, &rejected);
  if (!fresh) {
    logger.warning() << "Reload failed; keeping previous trie";
    return;
  }
  m_trie.store(std::move(fresh), std::memory_order_release);
  logger.info() << "Bypass subnets reloaded:" << loaded << "rejected"
                << rejected;
}

// ===========================================================================
// Worker thread
// ===========================================================================

void BypassRouter::workerLoop() {
  // Per-thread state — no synchronisation needed. Only this thread mutates.
  NatTable nat;

  alignas(8) uint8_t buf[65535];
  WINDIVERT_ADDRESS addr;
  UINT recvLen = 0;
  UINT sendLen = 0;
  qint64 lastSweepMs = QDateTime::currentMSecsSinceEpoch();

  while (m_active.load(std::memory_order_acquire)) {
    if (!g_wd.WinDivertRecv(m_handle, buf, sizeof(buf), &recvLen, &addr)) {
      const DWORD err = GetLastError();
      if (err == ERROR_NO_DATA || err == ERROR_OPERATION_ABORTED ||
          err == ERROR_INVALID_HANDLE) {
        break;  // shutdown
      }
      logger.warning() << "WinDivertRecv failed:" << err;
      continue;
    }

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    // Sweep every five seconds. Walks a flat array, very cheap.
    if (nowMs - lastSweepMs > 5000) {
      const int evicted = nat.evictExpired(nowMs);
      if (evicted > 0) {
        logger.debug() << "Evicted" << evicted
                       << "stale NAT entries; live="
                       << static_cast<int>(nat.size());
      }
      lastSweepMs = nowMs;
    }

    const ParsedPacket pkt = parsePacket(buf, recvLen);

    if (pkt.valid) {
      if (addr.Outbound) {
        // Snapshot the trie pointer once per packet — lock-free.
        const auto trie = m_trie.load(std::memory_order_acquire);
        if (trie && trie->contains(pkt.dstIp)) {
          NatTable::OrigKey key{pkt.proto, pkt.srcIp, pkt.srcPort, pkt.dstIp,
                                pkt.dstPort};
          if (auto natPort = nat.outboundLookup(key, nowMs)) {
            // Source rewrite: tun IP/port → phys IP / NAT port.
            write32be(buf + kSrcIpOff, m_phys.ipv4);
            write16be(buf + pkt.ihl + 0, *natPort);
            if (pkt.proto == IPPROTO_TCP) {
              nat.recordTcpFlags(*natPort, pkt.tcpFlags, nowMs);
            }
            // Steer the packet to the physical NIC.
            addr.Network.IfIdx = m_phys.ifIdx;
            addr.Network.SubIfIdx = 0;
            recomputeChecksums(buf, recvLen, &addr);
          }
          // If pool is saturated we let the packet flow to the tunnel —
          // not ideal (it'll be encrypted) but better than dropping.
        }
      } else {
        // Inbound on physical NIC. Match by NAT port; the inbound packet
        // is src=peer (server), dst=phys IP / NAT port.
        const auto* entry = nat.inboundLookup(pkt.proto, pkt.dstPort,
                                              pkt.srcIp, pkt.srcPort);
        if (entry) {
          // Restore destination to the original tunnel-side socket.
          write32be(buf + kDstIpOff, entry->key.origSrcIp);
          write16be(buf + pkt.ihl + 2, entry->key.origSrcPort);
          if (pkt.proto == IPPROTO_TCP) {
            nat.recordTcpFlags(entry->natPort, pkt.tcpFlags, nowMs);
          } else {
            nat.touch(entry->natPort, nowMs);
          }
          // Reinject as if it arrived on the tunnel adapter; the OS will
          // deliver it to the socket bound to the tunnel-side IP.
          addr.Network.IfIdx = m_tunnelIfIdx;
          addr.Network.SubIfIdx = 0;
          recomputeChecksums(buf, recvLen, &addr);
        }
        // No match: not our flow (legitimate inbound that happened to use
        // a port in our pool); pass through unchanged.
      }
    }

    if (!g_wd.WinDivertSend(m_handle, buf, recvLen, &sendLen, &addr)) {
      const DWORD err = GetLastError();
      if (err == ERROR_INVALID_HANDLE) break;
      // Other Send errors are usually transient (e.g. NIC just dropped):
      // discard the packet and keep going.
    }
  }

  logger.debug() << "Worker loop exiting; final NAT size="
                 << static_cast<int>(nat.size());
}
