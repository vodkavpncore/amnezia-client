/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Stateful NAT table for the Windows bypass router.
//
// Maps (proto, origSrcIp, origSrcPort, dstIp, dstPort) to a NAT-allocated
// source port from a fixed pool below Windows' ephemeral range. Provides
// fast bidirectional lookup for outbound and inbound translation.
//
// Single-threaded by design: only the BypassRouter worker thread mutates
// or reads the table. Cross-thread access is undefined.
//
// Eviction is sweep-based, called periodically by the worker.

#ifndef NATTABLE_H
#define NATTABLE_H

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include <QtGlobal>

class NatTable {
 public:
  // Pool boundaries. Chosen below Windows' default ephemeral range
  // (49152-65535) to avoid colliding with system-allocated source ports.
  static constexpr uint16_t kPoolMin = 30000;
  static constexpr uint16_t kPoolMax = 49151;
  static constexpr uint32_t kPoolSize = kPoolMax - kPoolMin + 1;

  // Per-flow timeouts in milliseconds.
  static constexpr qint64 kTcpEstablishedMs = 5 * 60 * 1000;
  static constexpr qint64 kTcpClosingMs = 30 * 1000;
  static constexpr qint64 kUdpMs = 60 * 1000;
  static constexpr qint64 kIcmpMs = 30 * 1000;

  struct OrigKey {
    uint8_t proto = 0;
    uint32_t origSrcIp = 0;   // host order
    uint16_t origSrcPort = 0;
    uint32_t dstIp = 0;       // host order
    uint16_t dstPort = 0;

    bool operator==(const OrigKey& o) const noexcept {
      return proto == o.proto && origSrcIp == o.origSrcIp &&
             origSrcPort == o.origSrcPort && dstIp == o.dstIp &&
             dstPort == o.dstPort;
    }
  };

  struct OrigKeyHash {
    size_t operator()(const OrigKey& k) const noexcept {
      // 64-bit mix: low(srcIp,srcPort) ^ rotated high(dstIp,dstPort) ^ proto.
      uint64_t lo = (uint64_t(k.origSrcIp) << 16) | k.origSrcPort;
      uint64_t hi = (uint64_t(k.dstIp) << 16) | k.dstPort;
      hi = (hi << 13) | (hi >> 51);
      uint64_t h = lo ^ hi ^ (uint64_t(k.proto) << 56);
      // splittable64 finalizer
      h ^= h >> 30;
      h *= 0xbf58476d1ce4e5b9ULL;
      h ^= h >> 27;
      h *= 0x94d049bb133111ebULL;
      h ^= h >> 31;
      return static_cast<size_t>(h);
    }
  };

  struct Entry {
    OrigKey key;
    uint16_t natPort = 0;     // 0 marks the slot as free
    qint64 lastSeenMs = 0;
    // OR-mask of TCP flags seen on this flow (FIN=0x01, RST=0x04). Used to
    // shrink the timeout once the connection is closing.
    uint8_t tcpFlagsSeen = 0;
  };

  NatTable();

  // Look up an entry for outbound translation. Returns the NAT port that
  // should be written into the outgoing packet. Allocates a new entry if
  // this 5-tuple is unseen. Returns std::nullopt only when the pool is
  // fully saturated (extremely rare; logs and drops).
  std::optional<uint16_t> outboundLookup(const OrigKey& key, qint64 nowMs);

  // Look up an entry by (proto, natPort, peerIp, peerPort) for inbound
  // translation. peerIp/peerPort are the remote side as observed in the
  // inbound packet (i.e. packet's src). Returns nullptr if no match.
  const Entry* inboundLookup(uint8_t proto, uint16_t natPort, uint32_t peerIp,
                             uint16_t peerPort) const;

  // Refresh lastSeen on an active entry (called from inboundLookup hit).
  void touch(uint16_t natPort, qint64 nowMs);

  // Update TCP flag bitmap for a flow (inbound or outbound TCP packet).
  void recordTcpFlags(uint16_t natPort, uint8_t flags, qint64 nowMs);

  // Sweep expired entries. Call every few seconds from the worker.
  // Returns count evicted.
  int evictExpired(qint64 nowMs);

  // Clear everything (called on stop / reload).
  void clear();

  size_t size() const noexcept { return m_byKey.size(); }

 private:
  // Pick the next free port. Returns 0 if pool is full.
  uint16_t allocatePort();

  qint64 timeoutFor(const Entry& e) const noexcept;

  // entries[port - kPoolMin] is the live entry, or natPort==0 if free.
  // Indexed by port for O(1) reverse lookup; iteration over the array is
  // also fast and predictable for sweep-eviction.
  std::vector<Entry> m_slots;

  std::unordered_map<OrigKey, uint16_t, OrigKeyHash> m_byKey;

  // Round-robin allocator hint to amortize linear scans.
  uint32_t m_nextSlot = 0;
};

#endif  // NATTABLE_H
