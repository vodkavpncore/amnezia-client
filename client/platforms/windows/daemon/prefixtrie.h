#ifndef PREFIX_TRIE_H
#define PREFIX_TRIE_H

#include <QFile>
#include <QByteArray>
#include <QMutex>
#include <cstdint>

/*
 * IPv4 prefix trie (radix tree, 4-bit per level).
 * Insert CIDR subnets, then query individual host IPs in O(32) time.
 * All operations are thread-safe when using swapLoad().
 */
class PrefixTrie {
public:
    PrefixTrie() = default;
    ~PrefixTrie();

    // Non-copyable but movable
    PrefixTrie(const PrefixTrie&) = delete;
    PrefixTrie& operator=(const PrefixTrie&) = delete;
    PrefixTrie(PrefixTrie&& other) noexcept;
    PrefixTrie& operator=(PrefixTrie&& other) noexcept;

    void clear();

    // Insert a CIDR prefix. ip is in host byte order, prefixLen is 0..32.
    void insert(uint32_t ip, int prefixLen);

    // Query: does this host IP fall under any inserted prefix?
    // ip is in host byte order.
    bool contains(uint32_t ip) const;

    // Load from a text file, one CIDR per line (e.g. "10.0.0.0/8").
    // Lines starting with '#' are skipped. Empty lines are skipped.
    // Returns the number of prefixes loaded, or -1 on error.
    int loadFromFile(const QString& path);

    // Atomic swap for hot-reload. Replaces the trie contents in one step.
    void swapLoad(PrefixTrie&& newTrie);

    // Number of prefixes stored
    int count() const { return m_count; }

private:
    static constexpr int CHILDREN = 2;

    struct Node {
        Node* children[CHILDREN] = {};
        bool isEndpoint = false;
    };

    Node* newNode();
    void freeTree(Node* node);

    Node* m_root = nullptr;
    int m_count = 0;
    QMutex m_mutex;
};

#endif // PREFIX_TRIE_H
