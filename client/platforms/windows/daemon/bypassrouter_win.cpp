#include "bypassrouter_win.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <QCoreApplication>
#include <QNetworkInterface>
#include <QFileInfo>
#include <QScopeGuard>
#include <QDateTime>

#include "leakdetector.h"
#include "logger.h"

// WinDivert API declarations — dynamic loading to avoid hard dependency
extern "C" {
typedef HANDLE(__cdecl* fn_WinDivertOpen)(const wchar_t* filter,
    WINDIVERT_LAYER layer, INT16 priority, UINT64 flags, LPDWORD err);
typedef BOOL(__cdecl* fn_WinDivertRecv)(HANDLE handle, PVOID pPacket,
    UINT packetLen, PWINDIVERT_ADDRESS pAddr, UINT* recvLen, LPDWORD err);
typedef BOOL(__cdecl* fn_WinDivertSend)(HANDLE handle, PVOID pPacket,
    UINT packetLen, PWINDIVERT_ADDRESS pAddr, UINT* sendLen, LPDWORD err);
typedef BOOL(__cdecl* fn_WinDivertClose)(HANDLE handle);
}

namespace {
Logger logger("BypassRouter");

// ---------------------------------------------------------------------------
// Dynamic WinDivert loader (load once, reuse across instances)
// ---------------------------------------------------------------------------
struct WinDivertAPI {
    HMODULE dll = nullptr;
    fn_WinDivertOpen  pOpen  = nullptr;
    fn_WinDivertRecv  pRecv  = nullptr;
    fn_WinDivertSend  pSend  = nullptr;
    fn_WinDivertClose pClose = nullptr;

    bool ensureLoaded() {
        if (dll) return true;

        // Try application directory first, then system search path
        QString path = QCoreApplication::applicationDirPath() + "/WinDivert.dll";
        dll = LoadLibraryW(reinterpret_cast<LPCWSTR>(path.utf16()));
        if (!dll) {
            dll = LoadLibraryW(L"WinDivert.dll");
        }
        if (!dll) {
            logger.error() << "WinDivert.dll not found";
            return false;
        }

        pOpen  = (fn_WinDivertOpen) GetProcAddress(dll, "WinDivertOpen");
        pRecv  = (fn_WinDivertRecv) GetProcAddress(dll, "WinDivertRecv");
        pSend  = (fn_WinDivertSend) GetProcAddress(dll, "WinDivertSend");
        pClose = (fn_WinDivertClose)GetProcAddress(dll, "WinDivertClose");

        if (!pOpen || !pRecv || !pSend || !pClose) {
            logger.error() << "WinDivert.dll: missing required exports";
            FreeLibrary(dll);
            dll = nullptr;
            return false;
        }
        return true;
    }
};

static WinDivertAPI s_wd;

// IPv4 header constants
static constexpr int IPV4_HDR_MIN_LEN = 20;
static constexpr int IPV4_PROTOCOL_OFF = 9;
static constexpr int IPV4_DST_OFF      = 16;
static constexpr uint8_t IPPROTO_UDP   = 17;
} // namespace

// ===========================================================================
// Construction / destruction
// ===========================================================================

BypassRouter::BypassRouter(QObject* parent) : QObject(parent) {
    MZ_COUNT_CTOR(BypassRouter);
}

BypassRouter::~BypassRouter() {
    MZ_COUNT_DTOR(BypassRouter);
    stop();
}

// ===========================================================================
// Public API
// ===========================================================================

bool BypassRouter::start(quint64 tunnelLuid) {
    if (m_active) return true;

    // --- 1. Resolve subnets file path ---
    m_subnetsFilePath = QString::fromUtf8(qgetenv("AMNEZIA_BYPASS_SUBNETS_FILE"));
    if (m_subnetsFilePath.isEmpty()) {
        logger.info() << "AMNEZIA_BYPASS_SUBNETS_FILE not set — bypass router disabled";
        return false;
    }
    if (!QFileInfo::exists(m_subnetsFilePath)) {
        logger.error() << "Bypass subnets file not found:" << m_subnetsFilePath;
        return false;
    }

    // --- 2. Load prefixes ---
    if (m_trie.loadFromFile(m_subnetsFilePath) < 0) {
        return false;
    }
    if (m_trie.count() == 0) {
        logger.info() << "Bypass file is empty — bypass router disabled";
        return false;
    }

    // --- 3. Load WinDivert ---
    if (!s_wd.ensureLoaded()) return false;

    // --- 4. Find physical interface index ---
    m_tunnelLuid = tunnelLuid;
    m_physicalIfIndex = findPhysicalIfIndex(tunnelLuid);
    if (m_physicalIfIndex == 0) {
        logger.error() << "Cannot determine physical interface index";
        return false;
    }
    logger.info() << "Physical interface index:" << m_physicalIfIndex;

    // --- 5. Open WinDivert ---
    //
    // Filter: outbound IPv4 TCP SYN or UDP
    //   - TCP SYN → first packet of new connection; OS caches route after that
    //   - UDP     → every packet (we cache by dst IP to minimize trie lookups)
    //
    DWORD err = 0;
    HANDLE wdHandle = s_wd.pOpen(
        L"outbound and ip and (tcp.Syn or udp)",
        WINDIVERT_LAYER_NETWORK,
        0, 0, &err);
    if (wdHandle == INVALID_HANDLE_VALUE) {
        logger.error() << "WinDivertOpen failed:" << err
                       << "(is WinDivert64.sys installed?)";
        return false;
    }

    // --- 6. Start background thread ---
    m_running = true;
    m_active = true;
    m_udpCache.clear();

    // Use a lambda-based worker to avoid a separate Worker class.
    // The thread takes ownership of the handle via capture.
    connect(&m_thread, &QThread::started, this,
        [this, wdHandle]() { runLoop(wdHandle); });

    m_thread.start();

    logger.info() << "Bypass router active:" << m_trie.count() << "prefixes";
    return true;
}

void BypassRouter::stop() {
    if (!m_active) return;
    m_running = false;
    m_thread.quit();
    if (!m_thread.wait(5000)) {
        logger.warning() << "Bypass thread did not finish in time";
        m_thread.terminate();
    }
    m_active = false;
    m_udpCache.clear();
    logger.info() << "Bypass router stopped";
}

int BypassRouter::prefixCount() const {
    return m_trie.count();
}

void BypassRouter::reloadSubnets() {
    if (m_subnetsFilePath.isEmpty()) return;
    PrefixTrie newTrie;
    int count = newTrie.loadFromFile(m_subnetsFilePath);
    if (count > 0) {
        m_trie.swapLoad(std::move(newTrie));
        m_udpCache.clear();
        logger.info() << "Bypass subnets reloaded:" << count << "prefixes";
    }
}

// ===========================================================================
// Main packet processing loop (runs in background thread)
// ===========================================================================

void BypassRouter::runLoop(HANDLE wdHandle) {
    constexpr UINT BUF_SIZE = 65535;
    alignas(8) uint8_t packet[BUF_SIZE];
    WINDIVERT_ADDRESS addr;
    UINT recvLen = 0, sendLen = 0;
    DWORD err = 0;

    while (m_running) {
        if (!s_wd.pRecv(wdHandle, packet, BUF_SIZE, &addr, &recvLen, &err)) {
            if (!m_running) break;
            if (err == ERROR_NO_DATA) continue;
            logger.error() << "WinDivertRecv failed:" << err;
            QThread::msleep(10);
            continue;
        }

        // Fast path: parse dst IP (bytes 16..19 of IPv4 header, already in
        // network byte order — but we want host order for trie comparison).
        uint32_t dstIP = 0;
        if (recvLen >= IPV4_HDR_MIN_LEN && (packet[0] & 0xF0) == 0x40) {
            dstIP = (static_cast<uint32_t>(packet[16]) << 24) |
                     (static_cast<uint32_t>(packet[17]) << 16) |
                     (static_cast<uint32_t>(packet[18]) << 8)  |
                      static_cast<uint32_t>(packet[19]);
        }

        bool bypass = false;

        if (dstIP != 0) {
            if (packet[IPV4_PROTOCOL_OFF] == IPPROTO_UDP) {
                // UDP: cache lookup first
                auto it = m_udpCache.constFind(dstIP);
                if (it != m_udpCache.constEnd()) {
                    bypass = *it;
                } else {
                    bypass = m_trie.contains(dstIP);
                    if (m_udpCache.size() < 131072) {
                        m_udpCache.insert(dstIP, bypass);
                    }
                    // If cache is full, just skip caching — trie lookup is still fast
                }
            } else {
                // TCP SYN: direct trie lookup (once per connection)
                bypass = m_trie.contains(dstIP);
            }
        }

        if (bypass) {
            addr.Outbound  = 1;
            addr.IfIdx     = m_physicalIfIndex;
            addr.SubIfIdx  = 0;
        }
        // VPN traffic: addr untouched → proceeds to tunnel interface

        if (!s_wd.pSend(wdHandle, packet, recvLen, &addr, &sendLen, &err)) {
            logger.warning() << "WinDivertSend failed:" << err;
        }
    }

    s_wd.pClose(wdHandle);
}

// ===========================================================================
// Helpers
// ===========================================================================

quint32 BypassRouter::findPhysicalIfIndex(quint64 tunnelLuid) const {
    quint32 bestIfIndex = 0;
    ULONG bestMetric = ULONG_MAX;

    PMIB_IPFORWARD_TABLE2 table = nullptr;
    DWORD result = GetIpForwardTable2(AF_INET, &table);
    if (result != NO_ERROR) {
        logger.error() << "GetIpForwardTable2 failed:" << result;
        return 0;
    }
    auto guard = qScopeGuard([table]() { FreeMibTable(table); });

    for (ULONG i = 0; i < table->NumEntries; i++) {
        const auto* row = &table->Table[i];
        if (row->DestinationPrefix.PrefixLength != 0) continue;  // want default route
        if (row->InterfaceLuid.Value == tunnelLuid) continue;    // skip tunnel

        MIB_IPINTERFACE_ROW ifaceRow;
        InitializeIpInterfaceEntry(&ifaceRow);
        ifaceRow.InterfaceLuid = row->InterfaceLuid;
        ifaceRow.Family = AF_INET;
        if (GetIpInterfaceEntry(&ifaceRow) != NO_ERROR) continue;
        if (!ifaceRow.Connected) continue;

        ULONG metric = row->Metric + ifaceRow.Metric;
        if (metric < bestMetric) {
            bestMetric = metric;
            bestIfIndex = row->InterfaceIndex;
        }
    }

    return bestIfIndex;
}

// Static helpers — inlined for speed

uint32_t BypassRouter::parseDstIPv4(const uint8_t* packet, UINT packetLen) {
    Q_UNUSED(packetLen);
    return (static_cast<uint32_t>(packet[16]) << 24) |
           (static_cast<uint32_t>(packet[17]) << 16) |
           (static_cast<uint32_t>(packet[18]) << 8)  |
            static_cast<uint32_t>(packet[19]);
}

bool BypassRouter::isUDPPacket(const uint8_t* packet, UINT packetLen) {
    Q_UNUSED(packetLen);
    return packet[IPV4_PROTOCOL_OFF] == IPPROTO_UDP;
}
