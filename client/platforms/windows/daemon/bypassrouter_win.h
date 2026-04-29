#ifndef BYPASSROUTER_WIN_H
#define BYPASSROUTER_WIN_H

#include <QObject>
#include <QThread>
#include <QString>
#include <QHash>

#include <Windows.h>

#include "prefixtrie.h"

/*
 * WinDivert-based bypass router for Windows.
 *
 * Intercepts outbound packets at the network layer before they reach
 * the WireGuard tunnel interface. Packets whose destination IP matches
 * a CIDR prefix in the bypass trie are redirected to the physical
 * (non-tunnel) network interface. Everything else proceeds to the
 * tunnel normally.
 *
 * Usage:
 *   1. Create BypassRouter
 *   2. Call start() before VPN connection (pass tunnel interface LUID)
 *   3. Call stop() after VPN disconnection
 *
 * Bypass subnets are loaded from the environment variable
 * AMNEZIA_BYPASS_SUBNETS_FILE (path to a text file with one CIDR per line).
 */
class BypassRouter : public QObject {
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(BypassRouter)

public:
    explicit BypassRouter(QObject* parent = nullptr);
    ~BypassRouter();

    /*
     * Start the bypass router.
     * Reads AMNEZIA_BYPASS_SUBNETS_FILE env var, loads CIDR prefixes,
     * starts WinDivert interception in a background thread.
     *
     * Returns true if started successfully.
     * Returns false if no bypass file configured (not an error) or on failure.
     */
    bool start(quint64 tunnelLuid);

    // Stop interception and release WinDivert handle.
    void stop();

    // Whether the bypass router is currently active
    bool isActive() const { return m_active; }

    // Number of loaded bypass prefixes
    int prefixCount() const;

    // Reload subnets from file (hot-reload without stop/start)
    void reloadSubnets();

private:
    // Thread entry point
    void runLoop(HANDLE wdHandle);

    // Find the physical (non-tunnel) interface index from the routing table
    quint32 findPhysicalIfIndex(quint64 tunnelLuid) const;

    // Read destination IPv4 address from raw IP header (network byte order → host)
    static uint32_t parseDstIPv4(const uint8_t* packet, UINT packetLen);

    // Check if packet is UDP (for caching purposes)
    static bool isUDPPacket(const uint8_t* packet, UINT packetLen);

    bool m_active = false;
    quint64 m_tunnelLuid = 0;
    quint32 m_physicalIfIndex = 0;
    QString m_subnetsFilePath;

    PrefixTrie m_trie;

    // UDP dst-ip → bypass decision cache (avoids trie lookup on every UDP packet)
    QHash<uint32_t, bool> m_udpCache;

    QThread m_thread;
    volatile bool m_running = false;
};

#endif // BYPASSROUTER_WIN_H
