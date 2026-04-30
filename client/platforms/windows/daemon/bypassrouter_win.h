/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// WinDivert-based split-tunnel router for Windows.
//
// While the WireGuard adapter advertises a 0.0.0.0/0 route, every IP packet
// the OS routes to the tunnel passes through this router first. Packets
// whose destination falls inside any CIDR loaded from
// AMNEZIA_BYPASS_SUBNETS_FILE are NAT-translated and redirected to the
// physical NIC; everything else flows to the tunnel untouched.
//
// Symmetric inbound translation reverses the NAT for response packets, so
// from the application's perspective the connection still appears to use
// the tunnel-side socket (correct binding, correct local IP).
//
// Why not just add 12k routes? On real machines, a large WFP/NDIS hook
// surface (AV, EDR, third-party firewalls) makes 12k FIB entries cause
// measurable per-packet overhead. WinDivert keeps the FIB clean.
//
// Usage:
//   auto* r = new BypassRouter(parent);
//   r->start(tunnelLuid);   // safe no-op if AMNEZIA_BYPASS_SUBNETS_FILE unset
//   ...
//   r->stop();
//
// All public methods must be called from the same thread (the owner's
// thread, typically the WireGuard daemon thread). Internal worker thread
// is private.

#ifndef BYPASSROUTER_WIN_H
#define BYPASSROUTER_WIN_H

#include <windows.h>

#include <QObject>
#include <QString>
#include <atomic>
#include <memory>
#include <thread>

class PrefixTrie;

class BypassRouter : public QObject {
  Q_OBJECT
  Q_DISABLE_COPY_MOVE(BypassRouter)

 public:
  explicit BypassRouter(QObject* parent = nullptr);
  ~BypassRouter() override;

  // Bring the router up. Looks at AMNEZIA_BYPASS_SUBNETS_FILE; if unset or
  // empty, returns false silently (split-tunnel disabled, nothing to do).
  // tunnelLuid is the LUID of the WireGuard adapter just created.
  bool start(quint64 tunnelLuid);

  // Bring the router down. Idempotent; safe from any state.
  void stop();

  // Reload the bypass list from disk without dropping in-flight connections.
  // Lock-free for the worker (atomic shared_ptr swap on the trie).
  void reloadSubnets();

  bool isActive() const noexcept { return m_active.load(std::memory_order_acquire); }

 private:
  // Worker entry. Runs until shutdown is signalled.
  void workerLoop();

  // Find the LUID, NDIS interface index and primary IPv4 address of the
  // outbound physical interface (default route, lowest metric, not tunnel).
  // Returns false if no usable interface is found.
  struct PhysIface {
    quint64 luid = 0;
    quint32 ifIdx = 0;
    uint32_t ipv4 = 0;  // host byte order
  };
  static bool resolvePhysicalInterface(quint64 tunnelLuid, PhysIface* out);
  static quint32 luidToIfIndex(quint64 luid);

  std::atomic<bool> m_active{false};
  quint64 m_tunnelLuid = 0;
  quint32 m_tunnelIfIdx = 0;
  PhysIface m_phys;
  QString m_subnetsFilePath;

  // The trie is replaced wholesale on reload. Worker reads via load();
  // main thread publishes via store(). C++20 atomic<shared_ptr>.
  std::atomic<std::shared_ptr<const PrefixTrie>> m_trie;

  // WinDivert handle owned by the worker thread once started.
  HANDLE m_handle = INVALID_HANDLE_VALUE;
  std::thread m_worker;
};

#endif  // BYPASSROUTER_WIN_H
