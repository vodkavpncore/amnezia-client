/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nattable.h"

// winsock2.h pulls in ws2def.h for IPPROTO_TCP/UDP and sets up the
// _WINSOCK2_H sentinel so ws2def's MIGRATION ERROR guard doesn't fire.
// Including ws2def.h directly while the project-wide _WINSOCKAPI_ macro
// is defined would trigger that error.
#include <winsock2.h>

#include "logger.h"

namespace {
Logger logger("NatTable");

constexpr uint8_t kTcpFinRstMask = 0x01 | 0x04;  // FIN | RST
}  // namespace

NatTable::NatTable() {
  m_slots.assign(kPoolSize, Entry{});
  m_byKey.reserve(8192);
}

uint16_t NatTable::allocatePort() {
  // Linear probe from m_nextSlot. Worst case scans the whole pool, which
  // happens only if the pool is full or near-full.
  for (uint32_t i = 0; i < kPoolSize; ++i) {
    const uint32_t idx = (m_nextSlot + i) % kPoolSize;
    if (m_slots[idx].natPort == 0) {
      m_nextSlot = (idx + 1) % kPoolSize;
      return static_cast<uint16_t>(kPoolMin + idx);
    }
  }
  return 0;
}

qint64 NatTable::timeoutFor(const Entry& e) const noexcept {
  switch (e.key.proto) {
    case IPPROTO_TCP:
      return (e.tcpFlagsSeen & kTcpFinRstMask) ? kTcpClosingMs
                                               : kTcpEstablishedMs;
    case IPPROTO_UDP:
      return kUdpMs;
    default:
      return kIcmpMs;
  }
}

std::optional<uint16_t> NatTable::outboundLookup(const OrigKey& key,
                                                 qint64 nowMs) {
  auto it = m_byKey.find(key);
  if (it != m_byKey.end()) {
    Entry& e = m_slots[it->second - kPoolMin];
    e.lastSeenMs = nowMs;
    return e.natPort;
  }

  const uint16_t port = allocatePort();
  if (port == 0) {
    static qint64 lastWarnMs = 0;
    if (nowMs - lastWarnMs > 5000) {
      lastWarnMs = nowMs;
      logger.warning() << "NAT pool saturated (" << m_byKey.size() << "/"
                       << kPoolSize << ") — packet dropped";
    }
    return std::nullopt;
  }

  Entry& e = m_slots[port - kPoolMin];
  e.key = key;
  e.natPort = port;
  e.lastSeenMs = nowMs;
  e.tcpFlagsSeen = 0;
  m_byKey.emplace(key, port);
  return port;
}

const NatTable::Entry* NatTable::inboundLookup(uint8_t proto, uint16_t natPort,
                                               uint32_t peerIp,
                                               uint16_t peerPort) const {
  if (natPort < kPoolMin || natPort > kPoolMax) return nullptr;
  const Entry& e = m_slots[natPort - kPoolMin];
  if (e.natPort == 0) return nullptr;
  if (e.key.proto != proto) return nullptr;
  if (e.key.dstIp != peerIp || e.key.dstPort != peerPort) return nullptr;
  return &e;
}

void NatTable::touch(uint16_t natPort, qint64 nowMs) {
  if (natPort < kPoolMin || natPort > kPoolMax) return;
  Entry& e = m_slots[natPort - kPoolMin];
  if (e.natPort != 0) e.lastSeenMs = nowMs;
}

void NatTable::recordTcpFlags(uint16_t natPort, uint8_t flags, qint64 nowMs) {
  if (natPort < kPoolMin || natPort > kPoolMax) return;
  Entry& e = m_slots[natPort - kPoolMin];
  if (e.natPort == 0) return;
  e.tcpFlagsSeen |= (flags & kTcpFinRstMask);
  e.lastSeenMs = nowMs;
}

int NatTable::evictExpired(qint64 nowMs) {
  int evicted = 0;
  for (uint32_t i = 0; i < kPoolSize; ++i) {
    Entry& e = m_slots[i];
    if (e.natPort == 0) continue;
    if (nowMs - e.lastSeenMs < timeoutFor(e)) continue;

    m_byKey.erase(e.key);
    e = Entry{};
    ++evicted;
  }
  return evicted;
}

void NatTable::clear() {
  std::fill(m_slots.begin(), m_slots.end(), Entry{});
  m_byKey.clear();
  m_nextSlot = 0;
}
