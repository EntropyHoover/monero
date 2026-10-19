// Copyright (c) 2026, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "salvage.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <set>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
  // LMDB on-disk format (see mdb.c); the file is in the native byte order of the writer
  constexpr uint32_t MDB_MAGIC = 0xBEEFC0DE;
  constexpr uint32_t MDB_DATA_VERSION = 1;
  constexpr uint16_t P_BRANCH = 0x01;
  constexpr uint16_t P_LEAF = 0x02;
  constexpr uint16_t P_OVERFLOW = 0x04;
  constexpr uint16_t P_META = 0x08;
  constexpr uint16_t P_LEAF2 = 0x20;
  constexpr uint16_t P_SUBP = 0x40;
  constexpr uint16_t F_BIGDATA = 0x01;
  constexpr uint16_t F_SUBDATA = 0x02;
  constexpr uint16_t F_DUPDATA = 0x04;
  constexpr uint16_t MDB_INTEGERKEY = 0x08;
  constexpr uint16_t MDB_DUPSORT = 0x04;
  constexpr uint16_t MDB_DUPFIXED = 0x10;
  constexpr size_t PAGEHDRSZ = 16;
  constexpr size_t NODESIZE = 8;
  constexpr size_t TREE_INFO_SIZE = 48;
  constexpr size_t META_SIZE = 152; // page header + MDB_meta
  constexpr uint64_t P_INVALID = ~(uint64_t)0;
  constexpr unsigned MAX_DEPTH = 32;
  constexpr size_t CACHE_PAGES = 16384;

  template<typename T> T native(const uint8_t *p)
  {
    T v;
    memcpy(&v, p, sizeof(v));
    return v;
  }

  cryptonote::lmdb_salvage::tree_info parse_tree_info(const uint8_t *p)
  {
    cryptonote::lmdb_salvage::tree_info t;
    t.pad = native<uint32_t>(p);
    t.flags = native<uint16_t>(p + 4);
    t.depth = native<uint16_t>(p + 6);
    t.branch_pages = native<uint64_t>(p + 8);
    t.leaf_pages = native<uint64_t>(p + 16);
    t.overflow_pages = native<uint64_t>(p + 24);
    t.entries = native<uint64_t>(p + 32);
    t.root = native<uint64_t>(p + 40);
    return t;
  }

  std::string page_str(uint64_t pgno)
  {
    return "page " + std::to_string(pgno);
  }

  // a bounded window onto a page or an inline duplicate sub-page
  struct view
  {
    const uint8_t *base;
    size_t size;
    uint64_t pgno;
    uint16_t pad, flags, lower, upper;

    size_t count() const { return (lower - PAGEHDRSZ) / 2; }
  };

  view make_view(const uint8_t *base, size_t size, uint64_t pgno)
  {
    using cryptonote::lmdb_salvage::read_error;
    if (size < PAGEHDRSZ)
      throw read_error(page_str(pgno) + ": sub-page is smaller than a page header");
    view v{base, size, pgno, native<uint16_t>(base + 8), native<uint16_t>(base + 10), native<uint16_t>(base + 12), native<uint16_t>(base + 14)};
    if (v.lower < PAGEHDRSZ || v.lower > v.upper || v.upper > size || (v.lower - PAGEHDRSZ) % 2)
      throw read_error(page_str(pgno) + ": corrupt free space bounds");
    if (v.flags & P_LEAF2)
    {
      if (!(v.flags & P_LEAF) || v.pad == 0 || PAGEHDRSZ + v.count() * (size_t)v.pad > size)
        throw read_error(page_str(pgno) + ": corrupt fixed-size record layout");
    }
    return v;
  }

  const uint8_t *leaf2_key(const view &v, size_t i)
  {
    return v.base + PAGEHDRSZ + i * v.pad;
  }
}

namespace cryptonote
{
namespace lmdb_salvage
{
  bool tree_info::empty() const
  {
    return root == P_INVALID;
  }

  struct file_reader::page
  {
    uint64_t pgno;
    uint16_t flags;
    std::vector<uint8_t> raw;
    mutable int order_checked = 0; // 1: exact 8 byte keys ascending, 2: 8 byte key prefixes ascending
  };

  struct file_reader::node
  {
    uint16_t flags;
    const uint8_t *key;
    size_t key_size;
    const uint8_t *data;
    size_t data_size; // with F_BIGDATA: size of the value on the overflow pages
    uint64_t child;   // branch pages only
  };

  file_reader::file_reader(const std::string &path):
#ifdef _WIN32
    m_handle(INVALID_HANDLE_VALUE),
#else
    m_fd(-1),
#endif
    m_page_size(0), m_file_size(0), m_snapshot{}
  {
#ifdef _WIN32
    // FILE_SHARE_READ only: fails if a monerod still has the file open for writing
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
      throw read_error("Failed to open " + path + " (error " + std::to_string(GetLastError()) + "); is it in use by another process?");
    m_handle = h;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size))
      throw read_error("Failed to get the size of " + path);
    m_file_size = size.QuadPart;
#else
    m_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (m_fd < 0)
      throw read_error("Failed to open " + path + ": " + strerror(errno));
    struct stat st;
    if (fstat(m_fd, &st) != 0)
    {
      const int err = errno;
      ::close(m_fd);
      throw read_error("Failed to stat " + path + ": " + strerror(err));
    }
    m_file_size = st.st_size;
#endif

    try
    {
      read_snapshots(path);
    }
    catch (...)
    {
#ifdef _WIN32
      CloseHandle((HANDLE)m_handle);
      m_handle = INVALID_HANDLE_VALUE;
#else
      ::close(m_fd);
      m_fd = -1;
#endif
      throw;
    }
  }

  void file_reader::read_snapshots(const std::string &path)
  {
    // meta page 0 records the page size, meta page 1 follows it
    snapshot s;
    if (read_meta(0, 0, s))
    {
      m_snapshots.push_back(s);
      if (read_meta(1, m_page_size, s))
        m_snapshots.push_back(s);
    }
    else
    {
      for (uint32_t ps: {4096u, 8192u, 16384u, 32768u, 65536u, 1024u, 2048u})
      {
        if (read_meta(1, ps, s))
        {
          m_page_size = ps;
          m_snapshots.push_back(s);
          break;
        }
      }
    }
    if (m_snapshots.empty())
    {
      // both headers destroyed: the pages themselves may still be there for a page_scan
      if (!guess_page_size())
        throw read_error(path + " has no readable LMDB meta page and no recognizable LMDB pages: not a database");
      select_whole_file();
      return;
    }
    std::sort(m_snapshots.begin(), m_snapshots.end(), [](const snapshot &a, const snapshot &b) { return a.txnid > b.txnid; });
    select(m_snapshots.front());
  }

  bool file_reader::guess_page_size()
  {
    // every page written by LMDB starts with its own page number
    uint32_t best = 0;
    uint64_t best_hits = 0;
    for (uint32_t ps: {4096u, 8192u, 16384u, 32768u, 65536u})
    {
      const uint64_t pages = std::min<uint64_t>(m_file_size / ps, 4096);
      uint64_t hits = 0;
      for (uint64_t p = 2; p < pages; ++p)
      {
        uint64_t pgno;
        try { read_at(p * ps, &pgno, sizeof(pgno), p); }
        catch (const read_error&) { break; }
        hits += pgno == p;
      }
      if (hits > best_hits)
      {
        best_hits = hits;
        best = ps;
      }
    }
    if (best_hits < 16)
      return false;
    m_page_size = best;
    return true;
  }

  void file_reader::select_whole_file()
  {
    m_snapshot = snapshot{};
    m_snapshot.meta_page = ~0u;
    m_snapshot.last_pgno = file_pages() ? file_pages() - 1 : 0;
    m_snapshot.main_tree = tree_info{0, 0, 0, 0, 0, 0, 0, P_INVALID};
  }

  file_reader::~file_reader()
  {
#ifdef _WIN32
    if (m_handle != INVALID_HANDLE_VALUE)
      CloseHandle((HANDLE)m_handle);
#else
    if (m_fd >= 0)
      ::close(m_fd);
#endif
  }

  void file_reader::read_at(uint64_t offset, void *buf, size_t size, uint64_t pgno) const
  {
    if (offset + size > m_file_size)
      throw read_error(page_str(pgno) + " lies beyond the end of the file (the file holds " + std::to_string(m_page_size ? file_pages() : 0) +
        " pages): the database file is truncated");
    size_t done = 0;
    while (done < size)
    {
#ifdef _WIN32
      OVERLAPPED ov{};
      const uint64_t at = offset + done;
      ov.Offset = (DWORD)at;
      ov.OffsetHigh = (DWORD)(at >> 32);
      DWORD got = 0;
      const DWORD want = (DWORD)std::min<size_t>(size - done, 1u << 30);
      if (!ReadFile((HANDLE)m_handle, (char*)buf + done, want, &got, &ov))
      {
        const DWORD err = GetLastError();
        if (err == ERROR_HANDLE_EOF)
          throw read_error(page_str(pgno) + " lies beyond the end of the file: the database file is truncated");
        throw read_error("I/O error reading " + page_str(pgno) + " (error " + std::to_string(err) + ")");
      }
#else
      const ssize_t got = pread(m_fd, (char*)buf + done, size - done, offset + done);
      if (got < 0)
      {
        if (errno == EINTR)
          continue;
        throw read_error("I/O error reading " + page_str(pgno) + ": " + strerror(errno));
      }
#endif
      if (got == 0)
        throw read_error(page_str(pgno) + " lies beyond the end of the file: the database file is truncated");
      done += got;
    }
  }

  bool file_reader::read_meta(unsigned index, uint32_t page_size, snapshot &s)
  {
    uint8_t b[META_SIZE];
    const uint64_t offset = (uint64_t)index * page_size;
    if (offset + META_SIZE > m_file_size)
      return false;
    try { read_at(offset, b, sizeof(b), index); }
    catch (const read_error&) { return false; }
    if (!(native<uint16_t>(b + 10) & P_META) || native<uint32_t>(b + 16) != MDB_MAGIC || native<uint32_t>(b + 20) != MDB_DATA_VERSION)
      return false;
    const tree_info free_tree = parse_tree_info(b + 40);
    const uint32_t ps = free_tree.pad;
    if (ps < 512 || ps > 65536 || (ps & (ps - 1)) || (index > 0 && ps != page_size))
      return false;
    s.meta_page = index;
    s.main_tree = parse_tree_info(b + 88);
    s.last_pgno = native<uint64_t>(b + 136);
    s.txnid = native<uint64_t>(b + 144);
    if (s.last_pgno < 1 || (!s.main_tree.empty() && (s.main_tree.root < 2 || s.main_tree.root > s.last_pgno)))
      return false;
    if (index == 0)
      m_page_size = ps;
    return true;
  }

  void file_reader::select(const snapshot &s)
  {
    m_snapshot = s;
  }

  file_reader::page_ptr file_reader::load(uint64_t pgno)
  {
    const auto it = m_cache.find(pgno);
    if (it != m_cache.end())
    {
      m_lru.splice(m_lru.begin(), m_lru, it->second);
      return *it->second;
    }

    if (pgno < 2)
      throw read_error(page_str(pgno) + " is a meta page, but a tree refers to it");
    if (pgno > m_snapshot.last_pgno)
      throw read_error(page_str(pgno) + " is past the last page of the snapshot (" + std::to_string(m_snapshot.last_pgno) + ")");

    auto p = std::make_shared<page>();
    p->raw.resize(m_page_size);
    read_at(pgno * m_page_size, p->raw.data(), m_page_size, pgno);
    const uint8_t *b = p->raw.data();
    p->pgno = native<uint64_t>(b);
    p->flags = native<uint16_t>(b + 10);
    if (p->pgno != pgno)
      throw read_error(page_str(pgno) + " holds the header of page " + std::to_string(p->pgno) + ": it was never written or was overwritten");
    const uint16_t kind = p->flags & (P_BRANCH | P_LEAF | P_OVERFLOW | P_META);
    if (kind != P_BRANCH && kind != P_LEAF)
      throw read_error(page_str(pgno) + " is not a branch or leaf page (flags " + std::to_string(p->flags) + ")");
    make_view(b, m_page_size, pgno);

    m_lru.push_front(p);
    m_cache[pgno] = m_lru.begin();
    if (m_lru.size() > CACHE_PAGES)
    {
      m_cache.erase(m_lru.back()->pgno);
      m_lru.pop_back();
    }
    return p;
  }

  file_reader::node file_reader::get_node(const uint8_t *base, size_t size, uint16_t page_flags, size_t index, uint64_t pgno) const
  {
    const view v = make_view(base, size, pgno);
    if (index >= v.count())
      throw read_error(page_str(pgno) + ": node index out of range");
    const size_t off = native<uint16_t>(base + PAGEHDRSZ + 2 * index);
    if (off < v.upper || off + NODESIZE > size)
      throw read_error(page_str(pgno) + ": node offset out of bounds");
    const uint16_t lo = native<uint16_t>(base + off), hi = native<uint16_t>(base + off + 2);
    node n;
    n.flags = native<uint16_t>(base + off + 4);
    n.key_size = native<uint16_t>(base + off + 6);
    n.key = base + off + NODESIZE;
    if (off + NODESIZE + n.key_size > size)
      throw read_error(page_str(pgno) + ": key extends past the page");
    n.data = n.key + n.key_size;
    n.child = 0;
    if (page_flags & P_BRANCH)
    {
      n.child = lo | ((uint64_t)hi << 16) | ((uint64_t)n.flags << 32);
      n.data_size = 0;
      return n;
    }
    n.data_size = lo | ((size_t)hi << 16);
    const size_t in_page = (n.flags & F_BIGDATA) ? sizeof(uint64_t) : n.data_size;
    if (off + NODESIZE + n.key_size + in_page > size)
      throw read_error(page_str(pgno) + ": value extends past the page");
    if ((n.flags & F_SUBDATA) && !(n.flags & F_BIGDATA) && n.data_size != TREE_INFO_SIZE)
      throw read_error(page_str(pgno) + ": corrupt sub-database record");
    return n;
  }

  std::string file_reader::read_overflow(uint64_t pgno, uint64_t size)
  {
    if (pgno < 2 || pgno > m_snapshot.last_pgno)
      throw read_error("overflow " + page_str(pgno) + " is outside the snapshot");
    uint8_t hdr[PAGEHDRSZ];
    read_at(pgno * m_page_size, hdr, sizeof(hdr), pgno);
    if (native<uint64_t>(hdr) != pgno || !(native<uint16_t>(hdr + 10) & P_OVERFLOW))
      throw read_error("overflow " + page_str(pgno) + " has a wrong header: it was never written or was overwritten");
    const uint64_t npages = native<uint32_t>(hdr + 12);
    if (npages == 0 || pgno + npages - 1 > m_snapshot.last_pgno)
      throw read_error("overflow " + page_str(pgno) + " has a corrupt page count");
    if (size + PAGEHDRSZ > npages * m_page_size)
      throw read_error("overflow " + page_str(pgno) + " is smaller than the value stored on it");
    if ((pgno + npages) * m_page_size > m_file_size)
      throw read_error("overflow pages " + std::to_string(pgno) + "-" + std::to_string(pgno + npages - 1) +
        " extend beyond the end of the file (the file holds " + std::to_string(file_pages()) + " pages): the database file is truncated");
    std::string out(size, '\0');
    if (size)
      read_at(pgno * m_page_size + PAGEHDRSZ, &out[0], size, pgno);
    return out;
  }

  std::string file_reader::node_value(const node &n, uint64_t pgno)
  {
    if (n.flags & F_DUPDATA)
    {
      // first duplicate
      if (n.flags & F_SUBDATA)
      {
        const tree_info sub = parse_tree_info(n.data);
        if (sub.empty())
          throw read_error(page_str(pgno) + ": empty duplicate sub-tree");
        uint64_t p = sub.root;
        for (unsigned level = 1; ; ++level)
        {
          if (level > sub.depth || level > MAX_DEPTH)
            throw read_error(page_str(p) + ": duplicate sub-tree deeper than recorded");
          const page_ptr pg = load(p);
          if (pg->flags & P_BRANCH)
          {
            p = get_node(pg->raw.data(), m_page_size, pg->flags, 0, p).child;
            continue;
          }
          const view v = make_view(pg->raw.data(), m_page_size, p);
          if (v.count() == 0)
            throw read_error(page_str(p) + ": empty leaf");
          if (pg->flags & P_LEAF2)
            return std::string((const char*)leaf2_key(v, 0), v.pad);
          const node first = get_node(pg->raw.data(), m_page_size, pg->flags, 0, p);
          return std::string((const char*)first.key, first.key_size);
        }
      }
      const view sv = make_view(n.data, n.data_size, pgno);
      if (!(sv.flags & P_SUBP) || sv.count() == 0)
        throw read_error(page_str(pgno) + ": corrupt duplicate sub-page");
      if (sv.flags & P_LEAF2)
        return std::string((const char*)leaf2_key(sv, 0), sv.pad);
      const node first = get_node(n.data, n.data_size, sv.flags, 0, pgno);
      return std::string((const char*)first.key, first.key_size);
    }
    if (n.flags & F_SUBDATA)
      throw read_error(page_str(pgno) + ": unexpected sub-database where a value was expected");
    if (n.flags & F_BIGDATA)
      return read_overflow(native<uint64_t>(n.data), n.data_size);
    return std::string((const char*)n.data, n.data_size);
  }

  file_reader::page_ptr file_reader::find_leaf(const tree_info &tree, uint64_t key, bool by_prefix)
  {
    if (tree.empty())
      return nullptr;
    const int mode = by_prefix ? 2 : 1;
    uint64_t pgno = tree.root;
    for (unsigned level = 1; ; ++level)
    {
      if (level > tree.depth || level > MAX_DEPTH)
        throw read_error(page_str(pgno) + " is deeper than the recorded tree depth " + std::to_string(tree.depth) + ": stale branch page");
      const page_ptr pg = load(pgno);
      const view v = make_view(pg->raw.data(), m_page_size, pgno);
      const size_t n = v.count();
      if (n == 0)
        throw read_error(page_str(pgno) + ": empty page inside a tree");

      // keys must be ascending; check once per page, the cache keeps the result
      if (pg->order_checked != mode)
      {
        uint64_t prev = 0;
        const bool branch = pg->flags & P_BRANCH;
        for (size_t i = branch ? 1 : 0; i < n; ++i)
        {
          const uint8_t *k;
          size_t ks;
          if (pg->flags & P_LEAF2)
          {
            k = leaf2_key(v, i);
            ks = v.pad;
          }
          else
          {
            const node nd = get_node(pg->raw.data(), m_page_size, pg->flags, i, pgno);
            k = nd.key;
            ks = nd.key_size;
          }
          if (by_prefix ? ks < 8 : ks != 8)
            throw read_error(page_str(pgno) + ": unexpected key size " + std::to_string(ks));
          const uint64_t kv = native<uint64_t>(k);
          if (i > (branch ? 1u : 0u) && kv <= prev)
            throw read_error(page_str(pgno) + ": keys out of order");
          prev = kv;
        }
        pg->order_checked = mode;
      }

      if (!(pg->flags & P_BRANCH))
      {
        if (level != tree.depth)
          throw read_error(page_str(pgno) + " is a leaf at level " + std::to_string(level) + " of a tree of depth " + std::to_string(tree.depth) + ": stale page");
        return pg;
      }

      // last child whose separator key is <= key; node 0 covers everything below key 1
      size_t lo = 1, hi = n;
      while (lo < hi)
      {
        const size_t mid = (lo + hi) / 2;
        const node nd = get_node(pg->raw.data(), m_page_size, pg->flags, mid, pgno);
        if (native<uint64_t>(nd.key) <= key)
          lo = mid + 1;
        else
          hi = mid;
      }
      pgno = get_node(pg->raw.data(), m_page_size, pg->flags, lo - 1, pgno).child;
    }
  }

  bool file_reader::search_leaf(const uint8_t *base, size_t size, uint64_t pgno, uint64_t key, node &out, std::string *leaf2_key_out) const
  {
    const view v = make_view(base, size, pgno);
    size_t lo = 0, hi = v.count();
    while (lo < hi)
    {
      const size_t mid = (lo + hi) / 2;
      uint64_t k;
      if (v.flags & P_LEAF2)
      {
        if (v.pad < 8)
          throw read_error(page_str(pgno) + ": record too small for its key");
        k = native<uint64_t>(leaf2_key(v, mid));
      }
      else
      {
        const node nd = get_node(base, size, v.flags, mid, pgno);
        if (nd.key_size < 8)
          throw read_error(page_str(pgno) + ": key too small");
        k = native<uint64_t>(nd.key);
        if (k == key)
        {
          out = nd;
          return true;
        }
      }
      if (k == key)
      {
        if (leaf2_key_out)
          leaf2_key_out->assign((const char*)leaf2_key(v, mid), v.pad);
        out = node{};
        return true;
      }
      if (k < key)
        lo = mid + 1;
      else
        hi = mid;
    }
    return false;
  }

  bool file_reader::get_u64(const tree_info &tree, uint64_t key, std::string &value)
  {
    const page_ptr pg = find_leaf(tree, key, false);
    if (!pg)
      return false;
    if (pg->flags & P_LEAF2)
      throw read_error(page_str(pg->pgno) + ": fixed-size record page where key/value nodes were expected");
    node n;
    if (!search_leaf(pg->raw.data(), m_page_size, pg->pgno, key, n, nullptr))
      return false;
    value = node_value(n, pg->pgno);
    return true;
  }

  bool file_reader::get_dup_by_u64_prefix(const tree_info &tree, uint64_t key, uint64_t dup_prefix, std::string &value)
  {
    const page_ptr pg = find_leaf(tree, key, false);
    if (!pg)
      return false;
    if (pg->flags & P_LEAF2)
      throw read_error(page_str(pg->pgno) + ": fixed-size record page where key/value nodes were expected");
    node n;
    if (!search_leaf(pg->raw.data(), m_page_size, pg->pgno, key, n, nullptr))
      return false;

    if (!(n.flags & F_DUPDATA))
    {
      const std::string single = node_value(n, pg->pgno);
      if (single.size() < 8 || native<uint64_t>((const uint8_t*)single.data()) != dup_prefix)
        return false;
      value = single;
      return true;
    }

    // fixed-size duplicates come back through record, others as the node key
    std::string record;
    node dn;
    if (n.flags & F_SUBDATA)
    {
      const tree_info sub = parse_tree_info(n.data);
      const page_ptr leaf = find_leaf(sub, dup_prefix, true);
      if (!leaf || !search_leaf(leaf->raw.data(), m_page_size, leaf->pgno, dup_prefix, dn, &record))
        return false;
      value = record.empty() ? std::string((const char*)dn.key, dn.key_size) : record;
      return true;
    }
    const view sv = make_view(n.data, n.data_size, pg->pgno);
    if (!(sv.flags & P_SUBP))
      throw read_error(page_str(pg->pgno) + ": corrupt duplicate sub-page");
    if (!search_leaf(n.data, n.data_size, pg->pgno, dup_prefix, dn, &record))
      return false;
    value = record.empty() ? std::string((const char*)dn.key, dn.key_size) : record;
    return true;
  }

  void file_reader::walk(uint64_t root, unsigned level, unsigned max_level, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors, bool &stop, bool dup_tree)
  {
    struct item { uint64_t pgno; unsigned level; };
    std::vector<item> stack{{root, level}};
    std::set<uint64_t> seen;
    while (!stack.empty() && !stop)
    {
      const item it = stack.back();
      stack.pop_back();
      if (!seen.insert(it.pgno).second)
      {
        errors.push_back(page_str(it.pgno) + " is referenced twice in one tree");
        continue;
      }
      try
      {
        if (it.level > max_level || it.level > MAX_DEPTH)
          throw read_error(page_str(it.pgno) + " is deeper than the recorded tree depth: stale branch page");
        const page_ptr pg = load(it.pgno);
        const view v = make_view(pg->raw.data(), m_page_size, it.pgno);
        if (pg->flags & P_BRANCH)
        {
          for (size_t i = v.count(); i-- > 0; )
            stack.push_back({get_node(pg->raw.data(), m_page_size, pg->flags, i, it.pgno).child, it.level + 1});
          continue;
        }
        if (it.level != max_level)
          throw read_error(page_str(it.pgno) + " is a leaf above the bottom of its tree: stale page");
        if (pg->flags & P_LEAF2)
        {
          for (size_t i = 0; i < v.count() && !stop; ++i)
            stop = !f(std::string(), std::string((const char*)leaf2_key(v, i), v.pad));
          continue;
        }
        for (size_t i = 0; i < v.count() && !stop; ++i)
        {
          try
          {
            const node n = get_node(pg->raw.data(), m_page_size, pg->flags, i, it.pgno);
            if (dup_tree)
              stop = !f(std::string(), std::string((const char*)n.key, n.key_size));
            else
              visit_leaf_node(n, it.pgno, f, errors, stop);
          }
          catch (const read_error &e)
          {
            errors.push_back(e.what());
          }
        }
      }
      catch (const read_error &e)
      {
        errors.push_back(e.what());
      }
    }
  }

  void file_reader::visit_leaf_node(const node &n, uint64_t pgno, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors, bool &stop)
  {
    const std::string key((const char*)n.key, n.key_size);
    if (!(n.flags & F_DUPDATA))
    {
      stop = !f(key, (n.flags & F_SUBDATA) ? std::string((const char*)n.data, n.data_size) : node_value(n, pgno));
      return;
    }
    const auto dup = [&](const std::string&, const std::string &value) { return f(key, value); };
    if (n.flags & F_SUBDATA)
    {
      const tree_info sub = parse_tree_info(n.data);
      if (!sub.empty())
        walk(sub.root, 1, sub.depth, dup, errors, stop, true);
      return;
    }
    const view sv = make_view(n.data, n.data_size, pgno);
    if (!(sv.flags & P_SUBP))
      throw read_error(page_str(pgno) + ": corrupt duplicate sub-page");
    for (size_t i = 0; i < sv.count() && !stop; ++i)
    {
      if (sv.flags & P_LEAF2)
        stop = !f(key, std::string((const char*)leaf2_key(sv, i), sv.pad));
      else
      {
        const node dn = get_node(n.data, n.data_size, sv.flags, i, pgno);
        stop = !f(key, std::string((const char*)dn.key, dn.key_size));
      }
    }
  }

  void file_reader::for_each(const tree_info &tree, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors)
  {
    if (tree.empty())
      return;
    bool stop = false;
    walk(tree.root, 1, tree.depth, f, errors, stop, false);
  }

  std::map<std::string, tree_info> file_reader::named_trees()
  {
    std::map<std::string, tree_info> out;
    std::vector<std::string> errors;
    // named databases are F_SUBDATA records in the main tree; their value is the 48 byte tree description
    for_each(m_snapshot.main_tree, [&](const std::string &name, const std::string &value) {
      if (value.size() == TREE_INFO_SIZE)
        out[name] = parse_tree_info((const uint8_t*)value.data());
      return true;
    }, errors);
    if (!errors.empty())
      throw read_error("the table directory of the snapshot is damaged: " + errors.front());
    return out;
  }

  blockchain_reader::blockchain_reader(const std::string &data_file):
    m_file(data_file), m_blocks{}, m_block_info{}, m_hf_versions{}, m_txs_pruned{}, m_txs_prunable{}, m_txs_prunable_hash{},
    m_txpool_meta{}, m_txpool_blob{}, m_alt_blocks{}, m_schema_version(0), m_pruning_seed(0)
  {
  }

  void blockchain_reader::select_snapshot(const snapshot &s)
  {
    m_file.select(s);
    const std::map<std::string, tree_info> trees = m_file.named_trees();
    const auto table = [&](const char *name, uint16_t expected_flags, tree_info &t) {
      const auto it = trees.find(name);
      if (it == trees.end())
        throw read_error(std::string("table ") + name + " is missing from the snapshot");
      if (it->second.flags != expected_flags)
        throw read_error(std::string("table ") + name + " has unexpected flags " + std::to_string(it->second.flags));
      t = it->second;
    };
    const auto optional_table = [&](const char *name, tree_info &t) {
      const auto it = trees.find(name);
      t = it == trees.end() ? tree_info{0, 0, 0, 0, 0, 0, 0, P_INVALID} : it->second;
    };
    table("blocks", MDB_INTEGERKEY, m_blocks);
    table("block_info", MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, m_block_info);
    table("hf_versions", MDB_INTEGERKEY, m_hf_versions);
    table("txs_pruned", MDB_INTEGERKEY, m_txs_pruned);
    table("txs_prunable", MDB_INTEGERKEY, m_txs_prunable);
    table("txs_prunable_hash", MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, m_txs_prunable_hash);
    tree_info properties;
    table("properties", 0, properties);
    optional_table("txpool_meta", m_txpool_meta);
    optional_table("txpool_blob", m_txpool_blob);
    optional_table("alt_blocks", m_alt_blocks);

    // property keys are stored with their terminating NUL
    m_schema_version = 0;
    m_pruning_seed = 0;
    std::vector<std::string> errors;
    m_file.for_each(properties, [&](const std::string &key, const std::string &value) {
      if (key == std::string("version", sizeof("version")) && value.size() == sizeof(uint32_t))
        memcpy(&m_schema_version, value.data(), sizeof(uint32_t));
      else if (key == std::string("pruning_seed", sizeof("pruning_seed")) && value.size() == sizeof(uint32_t))
        memcpy(&m_pruning_seed, value.data(), sizeof(uint32_t));
      return true;
    }, errors);
    if (!errors.empty())
      throw read_error("the properties table is damaged: " + errors.front());
  }

  std::string blockchain_reader::fingerprint() const
  {
    std::string fp;
    for (const tree_info *t: {&m_blocks, &m_block_info, &m_hf_versions, &m_txs_pruned, &m_txs_prunable, &m_txs_prunable_hash})
      fp += std::to_string(t->root) + ":" + std::to_string(t->entries) + ";";
    return fp + std::to_string(m_schema_version) + ":" + std::to_string(m_pruning_seed);
  }

  bool blockchain_reader::get_block_blob(uint64_t height, std::string &blob)
  {
    return m_file.get_u64(m_blocks, height, blob);
  }

  bool blockchain_reader::get_block_info(uint64_t height, block_info_record &bi)
  {
    std::string value;
    if (!m_file.get_dup_by_u64_prefix(m_block_info, 0, height, value))
      return false;
    if (value.size() != sizeof(bi))
      throw read_error("block_info record for height " + std::to_string(height) + " has size " + std::to_string(value.size()));
    memcpy(&bi, value.data(), sizeof(bi));
    return true;
  }

  bool blockchain_reader::get_hard_fork_version(uint64_t height, uint8_t &version)
  {
    std::string value;
    if (!m_file.get_u64(m_hf_versions, height, value))
      return false;
    if (value.size() != 1)
      throw read_error("hf_versions record for height " + std::to_string(height) + " has size " + std::to_string(value.size()));
    version = value[0];
    return true;
  }

  bool blockchain_reader::get_tx_pruned_blob(uint64_t tx_id, std::string &blob)
  {
    return m_file.get_u64(m_txs_pruned, tx_id, blob);
  }

  bool blockchain_reader::get_tx_prunable_blob(uint64_t tx_id, std::string &blob)
  {
    return m_file.get_u64(m_txs_prunable, tx_id, blob);
  }

  bool blockchain_reader::get_tx_prunable_hash(uint64_t tx_id, crypto::hash &hash)
  {
    std::string value;
    if (!m_file.get_u64(m_txs_prunable_hash, tx_id, value))
      return false;
    if (value.size() != sizeof(hash))
      throw read_error("txs_prunable_hash record for tx id " + std::to_string(tx_id) + " has size " + std::to_string(value.size()));
    memcpy(&hash, value.data(), sizeof(hash));
    return true;
  }

  void blockchain_reader::for_each_txpool_tx(const std::function<void(const crypto::hash&, const std::string&, const std::string&)> &f, std::vector<std::string> &errors)
  {
    std::unordered_map<crypto::hash, std::string> metas;
    m_file.for_each(m_txpool_meta, [&](const std::string &key, const std::string &value) {
      if (key.size() == sizeof(crypto::hash))
        metas[*reinterpret_cast<const crypto::hash*>(key.data())] = value;
      else
        errors.push_back("txpool_meta key of size " + std::to_string(key.size()));
      return true;
    }, errors);
    m_file.for_each(m_txpool_blob, [&](const std::string &key, const std::string &value) {
      if (key.size() != sizeof(crypto::hash))
      {
        errors.push_back("txpool_blob key of size " + std::to_string(key.size()));
        return true;
      }
      const crypto::hash &txid = *reinterpret_cast<const crypto::hash*>(key.data());
      const auto it = metas.find(txid);
      if (it != metas.end())
        f(txid, it->second, value);
      return true;
    }, errors);
  }

  void blockchain_reader::for_each_alt_block(const std::function<void(const crypto::hash&, const std::string&)> &f, std::vector<std::string> &errors)
  {
    m_file.for_each(m_alt_blocks, [&](const std::string &key, const std::string &value) {
      if (key.size() == sizeof(crypto::hash))
        f(*reinterpret_cast<const crypto::hash*>(key.data()), value);
      else
        errors.push_back("alt_blocks key of size " + std::to_string(key.size()));
      return true;
    }, errors);
  }

  namespace
  {
    constexpr uint64_t INLINE_DUPS = 1ull << 63;
    // keys further apart than this start a new run, so that a sparse leaf (output amounts, or a
    // pruned txs_prunable leaf spanning a gap between stripes) is not looked at for every key
    constexpr uint64_t RUN_GAP = 64;
    const std::string VERSION_KEY("version", sizeof("version"));
    const std::string PRUNING_SEED_KEY("pruning_seed", sizeof("pruning_seed"));

    // fixed-size duplicates of 96 bytes are block_info records or RingCT output_amounts records, whose
    // indexes are consecutive too but whose other fields are key bytes: block weights fit 32 bits,
    // heights are consecutive, generated coins never decrease and cumulative difficulty always grows
    bool looks_like_block_info(const view &v)
    {
      if (v.pad != sizeof(block_info_record) || v.count() == 0)
        return false;
      block_info_record prev;
      for (size_t i = 0; i < v.count(); ++i)
      {
        block_info_record r;
        memcpy(&r, leaf2_key(v, i), sizeof(r));
        if (r.weight >> 32 || r.long_term_weight >> 32)
          return false;
        if (i > 0 && (r.height != prev.height + 1 || r.coins_generated < prev.coins_generated ||
            (r.cumulative_difficulty_high == prev.cumulative_difficulty_high ? r.cumulative_difficulty_low <= prev.cumulative_difficulty_low :
              r.cumulative_difficulty_high < prev.cumulative_difficulty_high)))
          return false;
        prev = r;
      }
      return true;
    }

    bool find_record(const view &v, uint64_t height, block_info_record &out)
    {
      size_t lo = 0, hi = v.count();
      while (lo < hi)
      {
        const size_t mid = (lo + hi) / 2;
        const uint64_t h = native<uint64_t>(leaf2_key(v, mid));
        if (h == height)
        {
          memcpy(&out, leaf2_key(v, mid), sizeof(out));
          return true;
        }
        if (h < height)
          lo = mid + 1;
        else
          hi = mid;
      }
      return false;
    }
  }

  page_scan::page_scan(file_reader &file, const std::atomic<bool> &stop):
    m_file(file)
  {
    m_file.select_whole_file();
    const uint32_t ps = m_file.page_size();
    const uint64_t pages = m_file.file_pages();
    constexpr uint64_t CHUNK = 256;
    std::vector<uint8_t> buf(CHUNK * ps);
    for (uint64_t first = 2; first < pages; first += CHUNK)
    {
      if (stop)
      {
        m_interrupted = true;
        return;
      }
      const uint64_t n = std::min(CHUNK, pages - first);
      try
      {
        m_file.read_at(first * ps, buf.data(), n * ps, first);
      }
      catch (const read_error&)
      {
        // an unreadable stretch: fall back to single pages so only the bad ones are lost
        for (uint64_t i = 0; i < n; ++i)
        {
          try
          {
            m_file.read_at((first + i) * ps, buf.data() + i * ps, ps, first + i);
          }
          catch (const read_error&)
          {
            memset(buf.data() + i * ps, 0, ps);
          }
        }
      }
      for (uint64_t i = 0; i < n; ++i)
        scan_page(buf.data() + i * ps, first + i);
    }
    const auto by_min = [](const run &a, const run &b) { return a.min < b.min; };
    std::sort(m_runs.begin(), m_runs.end(), by_min);
    std::sort(m_info_runs.begin(), m_info_runs.end(), by_min);
  }

  void page_scan::scan_page(const uint8_t *base, uint64_t pgno)
  {
    const uint32_t ps = m_file.page_size();
    if (native<uint64_t>(base) != pgno)
      return;
    const uint16_t flags = native<uint16_t>(base + 10);
    if ((flags & (P_BRANCH | P_LEAF | P_OVERFLOW | P_META)) != P_LEAF)
      return;
    try
    {
      const view v = make_view(base, ps, pgno);
      if (v.count() == 0)
        return;
      if (flags & P_LEAF2)
      {
        if (looks_like_block_info(v))
        {
          const uint64_t lo = native<uint64_t>(leaf2_key(v, 0)), hi = native<uint64_t>(leaf2_key(v, v.count() - 1));
          m_info_runs.push_back({lo, hi, pgno});
          m_height_bound = std::max(m_height_bound, hi + 1);
        }
        return;
      }
      ++m_leaf_pages;

      std::vector<uint64_t> keys;
      bool integer_keys = true;
      for (size_t i = 0; i < v.count(); ++i)
      {
        const file_reader::node n = m_file.get_node(base, ps, flags, i, pgno);
        const std::string key((const char*)n.key, n.key_size);
        if (!(n.flags & (F_DUPDATA | F_SUBDATA | F_BIGDATA)) && n.data_size == sizeof(uint32_t) && (key == VERSION_KEY || key == PRUNING_SEED_KEY))
        {
          (key == VERSION_KEY ? m_versions : m_seeds).insert(native<uint32_t>(n.data));
          integer_keys = false;
          continue;
        }
        if (n.key_size != sizeof(uint64_t))
        {
          integer_keys = false;
          continue;
        }
        const uint64_t k = native<uint64_t>(n.key);
        if ((n.flags & F_DUPDATA) && !(n.flags & F_SUBDATA) && k == 0)
        {
          // a small table keeps its block_info duplicates inline, in a sub-page of the zero key
          const view sv = make_view(n.data, n.data_size, pgno);
          if ((sv.flags & P_LEAF2) && looks_like_block_info(sv))
          {
            const uint64_t lo = native<uint64_t>(leaf2_key(sv, 0)), hi = native<uint64_t>(leaf2_key(sv, sv.count() - 1));
            m_info_runs.push_back({lo, hi, pgno | INLINE_DUPS});
            m_height_bound = std::max(m_height_bound, hi + 1);
          }
          continue;
        }
        if (n.flags & (F_DUPDATA | F_SUBDATA))
          continue;
        if (!keys.empty() && k <= keys.back())
          integer_keys = false;
        keys.push_back(k);
      }
      if (!integer_keys || keys.empty())
        return;
      size_t start = 0;
      for (size_t i = 1; i <= keys.size(); ++i)
      {
        if (i == keys.size() || keys[i] - keys[i - 1] > RUN_GAP)
        {
          m_runs.push_back({keys[start], keys[i - 1], pgno});
          start = i;
        }
      }
    }
    catch (const read_error&)
    {
      // not a usable leaf
    }
  }

  void page_scan::advance(const std::vector<run> &runs, cursor &c, uint64_t key)
  {
    if (key < c.key)
      c = cursor{};
    c.key = key;
    while (c.next < runs.size() && runs[c.next].min <= key)
      c.active.push_back(c.next++);
    c.active.erase(std::remove_if(c.active.begin(), c.active.end(), [&](size_t i) { return runs[i].max < key; }), c.active.end());
  }

  void page_scan::values(cursor &c, uint64_t key, std::vector<std::string> &out)
  {
    out.clear();
    advance(m_runs, c, key);
    for (size_t i: c.active)
    {
      try
      {
        const file_reader::page_ptr pg = m_file.load(m_runs[i].pgno);
        file_reader::node n;
        if (m_file.search_leaf(pg->raw.data(), m_file.page_size(), pg->pgno, key, n, nullptr) && !(n.flags & (F_DUPDATA | F_SUBDATA)))
          out.push_back(m_file.node_value(n, pg->pgno));
      }
      catch (const read_error&)
      {
        // a candidate that cannot be read is no candidate
      }
    }
  }

  void page_scan::block_infos(cursor &c, uint64_t height, std::vector<block_info_record> &out)
  {
    out.clear();
    advance(m_info_runs, c, height);
    for (size_t i: c.active)
    {
      try
      {
        const uint64_t pgno = m_info_runs[i].pgno & ~INLINE_DUPS;
        const file_reader::page_ptr pg = m_file.load(pgno);
        block_info_record r;
        if (!(m_info_runs[i].pgno & INLINE_DUPS))
        {
          const view v = make_view(pg->raw.data(), m_file.page_size(), pgno);
          if ((pg->flags & P_LEAF2) && v.pad == sizeof(r) && find_record(v, height, r))
            out.push_back(r);
          continue;
        }
        file_reader::node n;
        if (m_file.search_leaf(pg->raw.data(), m_file.page_size(), pgno, 0, n, nullptr) && (n.flags & F_DUPDATA) && !(n.flags & F_SUBDATA))
        {
          const view sv = make_view(n.data, n.data_size, pgno);
          if ((sv.flags & P_LEAF2) && sv.pad == sizeof(r) && find_record(sv, height, r))
            out.push_back(r);
        }
      }
      catch (const read_error&)
      {
      }
    }
  }
}
}
