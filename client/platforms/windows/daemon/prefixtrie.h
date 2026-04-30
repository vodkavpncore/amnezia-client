/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// IPv4 longest-prefix trie.
//
// Designed to hold ~12k CIDR entries and answer host-IP membership queries
// in O(32) bit-walks (~300 ns on commodity hardware).
//
// Built once, then immutable: callers wrap finished tries in
// std::shared_ptr<const PrefixTrie> and atomically swap them on hot reload.
// Lookups are lock-free.

#ifndef PREFIXTRIE_H
#define PREFIXTRIE_H

#include <cstdint>
#include <memory>
#include <vector>

#include <QString>

class PrefixTrie {
 public:
  PrefixTrie();
  ~PrefixTrie();

  PrefixTrie(const PrefixTrie&) = delete;
  PrefixTrie& operator=(const PrefixTrie&) = delete;
  PrefixTrie(PrefixTrie&&) noexcept = default;
  PrefixTrie& operator=(PrefixTrie&&) noexcept = default;

  // Insert one CIDR prefix. ip is in host byte order; prefixLen is 0..32.
  // Out-of-range prefixLen is clamped silently.
  void insert(uint32_t ip, int prefixLen);

  // Returns true if any inserted prefix covers ip (host byte order).
  bool contains(uint32_t ip) const noexcept;

  // Number of distinct prefixes inserted. Counts duplicates as 1.
  int size() const noexcept { return m_size; }

  // Parse one CIDR string ("A.B.C.D/N"). Returns true on success.
  static bool parseCidr(const QString& cidr, uint32_t* ipHost, int* prefixLen);

  // Build a trie from a text file. One CIDR per line.
  // Lines starting with '#' and blank lines are ignored.
  // Returns null on I/O failure or if zero valid prefixes were parsed.
  // outLoaded / outRejected receive parse counts when non-null.
  static std::shared_ptr<const PrefixTrie> fromFile(const QString& path,
                                                    int* outLoaded = nullptr,
                                                    int* outRejected = nullptr);

 private:
  struct Node {
    int32_t child[2] = {-1, -1};
    bool endpoint = false;
  };

  // Append a fresh node and return its index in m_nodes.
  int32_t newNode();

  // Indices instead of pointers: vector resize never invalidates them.
  std::vector<Node> m_nodes;
  int m_size = 0;
};

#endif  // PREFIXTRIE_H
