/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "prefixtrie.h"

#include <QFile>
#include <QStringList>
#include <QTextStream>

#include "logger.h"

namespace {
Logger logger("PrefixTrie");
constexpr int kRootIndex = 0;
}  // namespace

PrefixTrie::PrefixTrie() {
  m_nodes.reserve(1024);
  m_nodes.emplace_back();  // root at index 0
}

PrefixTrie::~PrefixTrie() = default;

int32_t PrefixTrie::newNode() {
  m_nodes.emplace_back();
  return static_cast<int32_t>(m_nodes.size() - 1);
}

void PrefixTrie::insert(uint32_t ip, int prefixLen) {
  if (prefixLen < 0) prefixLen = 0;
  if (prefixLen > 32) prefixLen = 32;

  int32_t cur = kRootIndex;
  for (int i = 0; i < prefixLen; ++i) {
    const int bit = (ip >> (31 - i)) & 1;
    int32_t next = m_nodes[cur].child[bit];
    if (next < 0) {
      next = newNode();
      // m_nodes may have reallocated; re-index cur is fine since cur is an
      // index, not a pointer.
      m_nodes[cur].child[bit] = next;
    }
    cur = next;
  }
  if (!m_nodes[cur].endpoint) {
    m_nodes[cur].endpoint = true;
    ++m_size;
  }
}

bool PrefixTrie::contains(uint32_t ip) const noexcept {
  // Hot path. Avoid bounds checks via .data() and explicit indexing.
  const Node* nodes = m_nodes.data();
  int32_t cur = kRootIndex;
  bool found = false;
  for (int i = 0; i < 32; ++i) {
    const int bit = (ip >> (31 - i)) & 1;
    const int32_t next = nodes[cur].child[bit];
    if (next < 0) break;
    cur = next;
    if (nodes[cur].endpoint) found = true;
  }
  return found;
}

bool PrefixTrie::parseCidr(const QString& cidr, uint32_t* ipHost,
                           int* prefixLen) {
  const int slash = cidr.indexOf('/');
  if (slash <= 0 || slash == cidr.size() - 1) return false;

  bool ok = false;
  const int prefix = QStringView(cidr).mid(slash + 1).toInt(&ok);
  if (!ok || prefix < 0 || prefix > 32) return false;

  const QStringList octets = cidr.left(slash).split('.');
  if (octets.size() != 4) return false;

  uint32_t ip = 0;
  for (const QString& part : octets) {
    const uint v = part.toUInt(&ok);
    if (!ok || v > 255) return false;
    ip = (ip << 8) | v;
  }

  // Mask off host bits so callers can be sloppy ("10.0.0.123/8" works).
  if (prefix < 32) {
    ip &= prefix == 0 ? 0u : (~0u << (32 - prefix));
  }

  *ipHost = ip;
  *prefixLen = prefix;
  return true;
}

std::shared_ptr<const PrefixTrie> PrefixTrie::fromFile(const QString& path,
                                                      int* outLoaded,
                                                      int* outRejected) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    logger.error() << "Cannot open bypass file:" << path << file.errorString();
    return nullptr;
  }

  auto trie = std::make_shared<PrefixTrie>();
  int loaded = 0;
  int rejected = 0;

  QTextStream stream(&file);
  while (!stream.atEnd()) {
    const QString line = stream.readLine().trimmed();
    if (line.isEmpty() || line.startsWith('#')) continue;

    uint32_t ip;
    int prefixLen;
    if (!parseCidr(line, &ip, &prefixLen)) {
      ++rejected;
      continue;
    }
    trie->insert(ip, prefixLen);
    ++loaded;
  }

  if (outLoaded) *outLoaded = loaded;
  if (outRejected) *outRejected = rejected;

  if (loaded == 0) {
    logger.warning() << "Bypass file" << path
                     << "yielded zero valid prefixes (rejected=" << rejected
                     << ")";
    return nullptr;
  }

  logger.info() << "Loaded" << loaded << "bypass prefixes (rejected="
                << rejected << ") from" << path << "; nodes=" << trie->m_nodes.size();
  return trie;
}
