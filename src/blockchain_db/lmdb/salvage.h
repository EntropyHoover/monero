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

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto/hash.h"

/*
 * Read-only access to a damaged LMDB blockchain database.
 *
 * LMDB itself reads its data file through mmap, so a page that is missing
 * (truncated file) or unreadable (I/O error) kills the process with SIGBUS,
 * and a garbage page can send it reading far outside the page. Everything
 * here instead fetches pages with positioned reads into private buffers and
 * validates every header field, node offset and size before using it, so all
 * of those failures surface as read_error.
 *
 * Structural validation cannot tell a stale-but-well-formed page from a
 * current one; callers must verify the content they read (block and
 * transaction hashes).
 */

namespace cryptonote
{
namespace lmdb_salvage
{
  //! The DB schema version this reader understands (db_lmdb.cpp asserts it matches VERSION)
  constexpr uint32_t SUPPORTED_SCHEMA_VERSION = 5;

  class read_error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  //! On-disk MDB_db record: the description of one B-tree
  struct tree_info
  {
    uint32_t pad; //!< record size of fixed-size duplicates
    uint16_t flags;
    uint16_t depth;
    uint64_t branch_pages;
    uint64_t leaf_pages;
    uint64_t overflow_pages;
    uint64_t entries;
    uint64_t root;

    bool empty() const;
  };

  //! One of the two LMDB meta pages, i.e. one committed state of the database
  struct snapshot
  {
    unsigned meta_page;
    uint64_t txnid;
    uint64_t last_pgno;
    tree_info main_tree;
  };

  //! Low level page reader for an LMDB data file (64-bit page numbers, little endian)
  class file_reader
  {
  public:
    explicit file_reader(const std::string &path);
    ~file_reader();
    file_reader(const file_reader&) = delete;
    file_reader &operator=(const file_reader&) = delete;

    uint32_t page_size() const { return m_page_size; }
    uint64_t file_size() const { return m_file_size; }
    uint64_t file_pages() const { return m_file_size / m_page_size; }

    //! the readable meta pages, newest first; empty if both are destroyed (the page size is then guessed)
    const std::vector<snapshot> &snapshots() const { return m_snapshots; }

    //! use this snapshot for all further lookups
    void select(const snapshot &s);
    const snapshot &selected() const { return m_snapshot; }
    //! allow any page of the file, for reading pages found by a page_scan rather than through a tree
    void select_whole_file();

    //! the named sub-databases of the selected snapshot
    std::map<std::string, tree_info> named_trees();

    //! value of an integer (uint64) key; for duplicate keys, the first value
    bool get_u64(const tree_info &tree, uint64_t key, std::string &value);

    //! for a duplicate-sorted key, the duplicate whose first 8 bytes equal dup_prefix (as uint64)
    bool get_dup_by_u64_prefix(const tree_info &tree, uint64_t key, uint64_t dup_prefix, std::string &value);

    //! visit every key/value pair of a tree, in order; damaged subtrees are skipped
    //! and described in errors; return false from f to stop early
    void for_each(const tree_info &tree, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors);

  private:
    friend class page_scan;
    struct page;
    struct node;
    typedef std::shared_ptr<const page> page_ptr;

    void read_at(uint64_t offset, void *buf, size_t size, uint64_t pgno) const;
    bool read_meta(unsigned index, uint32_t page_size, snapshot &s);
    void read_snapshots(const std::string &path);
    bool guess_page_size();
    page_ptr load(uint64_t pgno);
    node get_node(const uint8_t *base, size_t size, uint16_t page_flags, size_t index, uint64_t pgno) const;
    std::string node_value(const node &n, uint64_t pgno);
    std::string read_overflow(uint64_t pgno, uint64_t size);
    page_ptr find_leaf(const tree_info &tree, uint64_t key, bool by_prefix);
    bool search_leaf(const uint8_t *base, size_t size, uint64_t pgno, uint64_t key, node &out, std::string *leaf2_key) const;
    void walk(uint64_t pgno, unsigned level, unsigned max_level, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors, bool &stop, bool dup_tree);
    void visit_leaf_node(const node &n, uint64_t pgno, const std::function<bool(const std::string&, const std::string&)> &f, std::vector<std::string> &errors, bool &stop);

#ifdef _WIN32
    void *m_handle;
#else
    int m_fd;
#endif
    uint32_t m_page_size;
    uint64_t m_file_size;
    std::vector<snapshot> m_snapshots;
    snapshot m_snapshot;

    // small LRU cache: lookups by consecutive keys keep hitting the same branch and leaf pages
    std::list<page_ptr> m_lru;
    std::unordered_map<uint64_t, std::list<page_ptr>::iterator> m_cache;
  };

  //! On-disk block_info record (mdb_block_info_4, schema version 5)
  struct block_info_record
  {
    uint64_t height;
    uint64_t timestamp;
    uint64_t coins_generated;
    uint64_t weight;
    uint64_t cumulative_difficulty_low;
    uint64_t cumulative_difficulty_high;
    crypto::hash hash;
    uint64_t cumulative_rct_outputs;
    uint64_t long_term_weight;
  };
  static_assert(sizeof(block_info_record) == 96, "block_info_record must match mdb_block_info_4");

  /**
   * Chain records found by reading every page of the data file instead of walking
   * trees: the fallback for a file whose meta, table directory or root pages are
   * lost or stale, which in an MDB_NOSYNC power loss is the likely case, since every
   * commit rewrites them. Every valid leaf page counts, whichever tree or stale
   * version of a tree it belongs to, so a key can have several values from several
   * tables; callers must tell them apart by content and hashes.
   */
  class page_scan
  {
  public:
    //! reads the whole file once; stop is polled as it goes
    page_scan(file_reader &file, const std::atomic<bool> &stop);

    //! lookup state; keys looked up through one cursor should not decrease
    struct cursor
    {
      size_t next = 0;
      uint64_t key = 0;
      std::vector<size_t> active;
    };

    //! every value stored under this integer key in any leaf page
    void values(cursor &c, uint64_t key, std::vector<std::string> &out);
    //! every block_info record for this height
    void block_infos(cursor &c, uint64_t height, std::vector<block_info_record> &out);

    bool interrupted() const { return m_interrupted; }
    uint64_t leaf_pages() const { return m_leaf_pages; }
    uint64_t block_info_pages() const { return m_info_runs.size(); }
    //! one past the highest height of any block_info record found
    uint64_t height_bound() const { return m_height_bound; }
    //! values of the properties records found (stale versions included)
    const std::set<uint32_t> &schema_versions() const { return m_versions; }
    const std::set<uint32_t> &pruning_seeds() const { return m_seeds; }

  private:
    struct run
    {
      uint64_t min, max;
      uint64_t pgno; //!< INLINE_DUPS bit: block_info duplicates inline in a leaf node, not a LEAF2 page
    };
    void scan_page(const uint8_t *base, uint64_t pgno);
    void advance(const std::vector<run> &runs, cursor &c, uint64_t key);

    file_reader &m_file;
    std::vector<run> m_runs;      //!< integer keys of leaf pages, split into dense runs
    std::vector<run> m_info_runs; //!< heights of block_info leaf pages
    uint64_t m_leaf_pages = 0;
    uint64_t m_height_bound = 0;
    std::set<uint32_t> m_versions, m_seeds;
    bool m_interrupted = false;
  };

  //! Monero schema accessors on top of file_reader; only height and tx id keyed
  //! tables are used for chain data, since hash keyed indexes are scattered
  //! across the whole file and are rebuilt rather than trusted
  class blockchain_reader
  {
  public:
    explicit blockchain_reader(const std::string &data_file);

    const file_reader &file() const { return m_file; }
    file_reader &file() { return m_file; }
    const std::vector<snapshot> &snapshots() const { return m_file.snapshots(); }

    //! opens the tables of a snapshot; throws read_error if they cannot be located
    void select_snapshot(const snapshot &s);

    //! identifies the chain data a snapshot points at; equal fingerprints mean equal content
    std::string fingerprint() const;

    uint32_t schema_version() const { return m_schema_version; }
    uint32_t pruning_seed() const { return m_pruning_seed; }
    uint64_t recorded_block_count() const { return m_blocks.entries; }
    uint64_t recorded_tx_count() const { return m_txs_pruned.entries; }

    bool get_block_blob(uint64_t height, std::string &blob);
    bool get_block_info(uint64_t height, block_info_record &bi);
    bool get_hard_fork_version(uint64_t height, uint8_t &version);
    bool get_tx_pruned_blob(uint64_t tx_id, std::string &blob);
    bool get_tx_prunable_blob(uint64_t tx_id, std::string &blob);
    bool get_tx_prunable_hash(uint64_t tx_id, crypto::hash &hash);

    //! every txpool entry found in both txpool tables (meta, blob)
    void for_each_txpool_tx(const std::function<void(const crypto::hash&, const std::string&, const std::string&)> &f, std::vector<std::string> &errors);
    //! every alternative block entry (alt_block_data_t followed by the block blob)
    void for_each_alt_block(const std::function<void(const crypto::hash&, const std::string&)> &f, std::vector<std::string> &errors);

  private:
    file_reader m_file;
    tree_info m_blocks, m_block_info, m_hf_versions, m_txs_pruned, m_txs_prunable, m_txs_prunable_hash;
    tree_info m_txpool_meta, m_txpool_blob, m_alt_blocks;
    uint32_t m_schema_version;
    uint32_t m_pruning_seed;
  };
}
}
