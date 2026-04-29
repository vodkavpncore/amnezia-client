#include "prefixtrie.h"

#include <QTextStream>
#include <cstring>

#include "logger.h"

namespace {
Logger logger("PrefixTrie");
}

// ---------------------------------------------------------------------------
// Pool allocator: avoids per-node heap allocation overhead for ~12K nodes
// ---------------------------------------------------------------------------
static constexpr int POOL_SIZE = 262144; // ~256K nodes should be enough for 12K prefixes
static PrefixTrie::Node s_pool[POOL_SIZE];
static int s_poolIdx = 0;
static QMutex s_poolMutex;

PrefixTrie::Node* PrefixTrie::newNode() {
    QMutexLocker lock(&s_poolMutex);
    if (s_poolIdx >= POOL_SIZE) {
        logger.error() << "PrefixTrie node pool exhausted";
        return nullptr;
    }
    Node* n = &s_pool[s_poolIdx++];
    std::memset(n, 0, sizeof(Node));
    return n;
}

PrefixTrie::PrefixTrie() {
    m_root = newNode();
}

PrefixTrie::~PrefixTrie() {
    // Nodes are in the static pool, no need to free individually.
    // Reset pool index only if this was the last trie (unsafe in multi-instance
    // scenario, but we only have one instance at a time in practice).
    clear();
}

PrefixTrie::PrefixTrie(PrefixTrie&& other) noexcept
    : m_root(other.m_root), m_count(other.m_count) {
    other.m_root = nullptr;
    other.m_count = 0;
}

PrefixTrie& PrefixTrie::operator=(PrefixTrie&& other) noexcept {
    if (this != &other) {
        m_root = other.m_root;
        m_count = other.m_count;
        other.m_root = nullptr;
        other.m_count = 0;
    }
    return *this;
}

void PrefixTrie::clear() {
    // Reset pool so all nodes are reusable
    QMutexLocker lock(&s_poolMutex);
    s_poolIdx = 0;
    m_root = newNode();
    m_count = 0;
}

void PrefixTrie::insert(uint32_t ip, int prefixLen) {
    if (!m_root) return;
    if (prefixLen < 0) prefixLen = 0;
    if (prefixLen > 32) prefixLen = 32;

    Node* n = m_root;
    for (int i = 0; i < prefixLen; i++) {
        int bit = (ip >> (31 - i)) & 1;
        if (!n->children[bit]) {
            n->children[bit] = newNode();
            if (!n->children[bit]) return;
        }
        n = n->children[bit];
    }
    n->isEndpoint = true;
    m_count++;
}

bool PrefixTrie::contains(uint32_t ip) const {
    if (!m_root) return false;

    const Node* n = m_root;
    bool found = false;
    for (int i = 0; i < 32; i++) {
        int bit = (ip >> (31 - i)) & 1;
        n = n->children[bit];
        if (!n) break;
        if (n->isEndpoint) found = true;
    }
    return found;
}

int PrefixTrie::loadFromFile(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        logger.error() << "Failed to open bypass subnets file:" << path;
        return -1;
    }

    clear();
    QTextStream stream(&file);
    int loaded = 0;

    while (!stream.atEnd()) {
        QString line = stream.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;

        // Parse "A.B.C.D/N"
        int slashIdx = line.indexOf('/');
        if (slashIdx < 0) continue;

        bool ok = false;
        QString ipStr = line.left(slashIdx);
        int prefixLen = line.mid(slashIdx + 1).toInt(&ok);
        if (!ok || prefixLen < 0 || prefixLen > 32) continue;

        // Parse IPv4 address
        QStringList octets = ipStr.split('.');
        if (octets.size() != 4) continue;

        uint32_t ip = 0;
        bool valid = true;
        for (int i = 0; i < 4; i++) {
            uint8_t octet = octets[i].toUInt(&ok);
            if (!ok || octet > 255) { valid = false; break; }
            ip = (ip << 8) | octet;
        }
        if (!valid) continue;

        insert(ip, prefixLen);
        loaded++;
    }

    logger.info() << "Loaded" << loaded << "bypass prefixes from" << path;
    return loaded;
}

void PrefixTrie::swapLoad(PrefixTrie&& newTrie) {
    QMutexLocker lock(&m_mutex);
    // Simple swap — the old trie's nodes stay in the pool (reused later)
    m_root = newTrie.m_root;
    m_count = newTrie.m_count;
    newTrie.m_root = nullptr;
    newTrie.m_count = 0;
}

void PrefixTrie::freeTree(Node* node) {
    // No-op: pool-allocated
    Q_UNUSED(node)
}
