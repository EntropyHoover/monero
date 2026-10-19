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

#include "db_reconstruct.h"

#include <algorithm>
#include <boost/filesystem.hpp>
#include <chrono>
#include <ctime>
#include <deque>
#include <iomanip>
#include <memory>
#include <sstream>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/salvage.h"
#include "common/pruning.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "hardforks/hardforks.h"
#include "misc_log_ex.h"
#include "rolling_median.h"
#include "string_tools.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.reconstruct"

namespace fs = boost::filesystem;

namespace
{
  using namespace cryptonote;
  using lmdb_salvage::read_error;

  const char *const NEW_DB_DIR = "lmdb.reconstruct";
  constexpr uint64_t BATCH_BLOCKS = 1000;
  constexpr uint64_t BATCH_BYTES = 256 * 1024 * 1024;

  const char *network_name(network_type nettype)
  {
    switch (nettype)
    {
      case MAINNET: return "mainnet";
      case TESTNET: return "testnet";
      case STAGENET: return "stagenet";
      default: return "unknown";
    }
  }

  crypto::hash genesis_hash(network_type nettype)
  {
    block bl;
    generate_genesis_block(bl, get_config(nettype).GENESIS_TX, get_config(nettype).GENESIS_NONCE);
    return get_block_hash(bl);
  }

  bool detect_network(lmdb_salvage::blockchain_reader &reader, network_type &nettype, std::string &error)
  {
    std::string blob;
    try
    {
      if (!reader.get_block_blob(0, blob))
      {
        error = "the genesis block is missing";
        return false;
      }
    }
    catch (const read_error &e)
    {
      error = std::string("the genesis block is unreadable: ") + e.what();
      return false;
    }
    block b;
    crypto::hash hash;
    if (!parse_and_validate_block_from_blob(blob, b, hash))
    {
      error = "the genesis block does not parse";
      return false;
    }
    for (network_type n: {MAINNET, TESTNET, STAGENET})
    {
      if (hash == genesis_hash(n))
      {
        nettype = n;
        return true;
      }
    }
    error = "genesis block " + epee::string_tools::pod_to_hex(hash) + " belongs to no known network";
    return false;
  }

  // same hard fork setup as Blockchain::init
  std::unique_ptr<HardFork> make_hard_fork(BlockchainDB &db, network_type nettype)
  {
    std::unique_ptr<HardFork> hf;
    const hardfork_t *forks;
    size_t num_forks;
    if (nettype == TESTNET)
    {
      hf.reset(new HardFork(db, 1, testnet_hard_fork_version_1_till));
      forks = testnet_hard_forks;
      num_forks = num_testnet_hard_forks;
    }
    else if (nettype == STAGENET)
    {
      hf.reset(new HardFork(db, 1, 0));
      forks = stagenet_hard_forks;
      num_forks = num_stagenet_hard_forks;
    }
    else
    {
      hf.reset(new HardFork(db, 1, mainnet_hard_fork_version_1_till));
      forks = mainnet_hard_forks;
      num_forks = num_mainnet_hard_forks;
    }
    for (size_t n = 0; n < num_forks; ++n)
      hf->add_fork(forks[n].version, forks[n].height, forks[n].threshold, forks[n].time);
    hf->init();
    return hf;
  }

  difficulty_type make_difficulty(uint64_t low, uint64_t high)
  {
    difficulty_type d = high;
    d <<= 64;
    d |= low;
    return d;
  }

  std::string gib(uint64_t bytes)
  {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << bytes / (1024.0 * 1024.0 * 1024.0) << " GiB";
    return ss.str();
  }

  //! true if some process holds the LMDB lock of the database (monerod keeps it while running)
  bool db_in_use(const fs::path &db_dir)
  {
#ifdef _WIN32
    // the reader opens data.mdb without write sharing, which fails while a writer has it open
    return false;
#else
    const int fd = ::open((db_dir / CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME).string().c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      return false;
    struct flock fl{};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 1;
    const bool locked = fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK;
    ::close(fd);
    return locked;
#endif
  }

  void sync_directory(const fs::path &dir)
  {
#ifndef _WIN32
    const int fd = ::open(dir.string().c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
    {
      if (fsync(fd) != 0)
        MWARNING("Failed to sync directory " << dir.string());
      ::close(fd);
    }
#endif
  }

  // the old database may have been deliberately private; keep its access rights
  void copy_permissions(const fs::path &from, const fs::path &to)
  {
    boost::system::error_code ec;
    const fs::file_status st = fs::status(from, ec);
    if (!ec && fs::exists(to, ec))
      fs::permissions(to, st.permissions(), ec);
    if (ec)
      MWARNING("Failed to copy the permissions of " << from.string() << " to " << to.string() << ": " << ec.message());
  }

  //! compiled-in fast sync data: for each 512-block chunk, the hash of its block hashes and of its block weights
  typedef std::vector<std::pair<crypto::hash, crypto::hash>> chunk_hashes;

  chunk_hashes load_chunk_hashes(const block_hashes_callback &get_block_hashes, network_type nettype)
  {
    chunk_hashes chunks;
    if (!get_block_hashes)
      return chunks;
    const epee::span<const unsigned char> data = get_block_hashes(nettype);
    if (data.size() < 4)
      return chunks;
    const unsigned char *p = data.data();
    const uint64_t n = p[0] | (p[1] << 8) | (p[2] << 16) | ((uint64_t)p[3] << 24);
    if (data.size() != 4 + n * 2 * sizeof(crypto::hash))
    {
      MWARNING("Ignoring the compiled-in block hashes: unexpected size");
      return chunks;
    }
    p += 4;
    chunks.resize(n);
    for (auto &chunk: chunks)
    {
      memcpy(chunk.first.data, p, sizeof(crypto::hash));
      memcpy(chunk.second.data, p + sizeof(crypto::hash), sizeof(crypto::hash));
      p += 2 * sizeof(crypto::hash);
    }
    return chunks;
  }

  //! weight of a pruned transaction, if its prunable part has a deterministic size
  bool pruned_transaction_weight(const transaction &tx, size_t pruned_size, uint64_t &weight)
  {
    const uint8_t type = tx.rct_signatures.type;
    if (tx.vin.empty() || tx.vin[0].type() != typeid(txin_to_key) || boost::get<txin_to_key>(tx.vin[0]).key_offsets.empty())
      return false;
    // Bulletproof2, CLSAG and Bulletproof+: see get_pruned_transaction_weight
    if (type == rct::RCTTypeBulletproof2 || type == rct::RCTTypeCLSAG || type == rct::RCTTypeBulletproofPlus)
    {
      try
      {
        weight = get_pruned_transaction_weight(tx);
      }
      catch (const std::exception&)
      {
        return false;
      }
      return weight != std::numeric_limits<uint64_t>::max();
    }
    // before Bulletproofs, range proofs and MLSAGs have a fixed size given the input, output and ring counts,
    // so a zero-filled prunable part of that shape serializes to the size of the real one; with no
    // Bulletproof clawback, the weight is the size of the whole blob
    if (type != rct::RCTTypeFull && type != rct::RCTTypeSimple)
      return false;
    const size_t inputs = tx.vin.size(), outputs = tx.vout.size(), mixin = boost::get<txin_to_key>(tx.vin[0]).key_offsets.size() - 1;
    rct::rctSigPrunable prunable;
    prunable.rangeSigs.resize(outputs);
    prunable.MGs.resize(type == rct::RCTTypeSimple ? inputs : 1);
    for (rct::mgSig &mg: prunable.MGs)
      mg.ss.assign(mixin + 1, rct::keyV(type == rct::RCTTypeSimple ? 2 : inputs + 1));
    std::ostringstream ss;
    binary_archive<true> ar(ss);
    if (!prunable.serialize_rctsig_prunable(ar, type, inputs, outputs, mixin) || !ar.good())
      return false;
    weight = pruned_size + ss.str().size();
    return true;
  }

  struct scan_result
  {
    uint64_t height = 0; //!< blocks verified (and written, if writing)
    uint64_t txs = 0;
    uint64_t pruned_txs = 0;
    crypto::hash top_hash = crypto::null_hash;
    std::string failure; //!< why the scan stopped early, if it did
    bool interrupted = false;
    uint64_t unverified_weights = 0; //!< blocks whose stored weight could be neither recomputed nor checked
    uint64_t first_unverified_weight = 0;
  };

  /**
   * Where the scanner reads chain records from. Every lookup returns candidates:
   * the tables of one snapshot give at most one value per key, a page scan gives
   * every value that any leaf page holds under the key (stale versions and other
   * tables' values included). The scanner keeps the candidate that verifies.
   */
  class chain_source
  {
  public:
    virtual ~chain_source() = default;
    virtual uint32_t pruning_seed() const = 0;
    //! the block count the database had, which decides its pruning tip window
    virtual uint64_t recorded_height() const = 0;
    //! whether a missing hf_versions record ends the scan (a page scan takes the version from the block)
    virtual bool needs_hard_fork_records() const = 0;
    virtual void blocks(uint64_t height, std::vector<blobdata> &out) = 0;
    virtual void block_infos(uint64_t height, std::vector<lmdb_salvage::block_info_record> &out) = 0;
    virtual void hard_fork_versions(uint64_t height, std::vector<uint8_t> &out) = 0;
    virtual void pruned_txs(uint64_t tx_id, std::vector<blobdata> &out) = 0;
    virtual void prunable_txs(uint64_t tx_id, std::vector<blobdata> &out) = 0;
    virtual void prunable_hashes(uint64_t tx_id, std::vector<crypto::hash> &out) = 0;
  };

  //! the tables of the snapshot selected in the reader
  class snapshot_source: public chain_source
  {
  public:
    explicit snapshot_source(lmdb_salvage::blockchain_reader &reader): m_reader(reader) {}
    uint32_t pruning_seed() const override { return m_reader.pruning_seed(); }
    uint64_t recorded_height() const override { return m_reader.recorded_block_count(); }
    bool needs_hard_fork_records() const override { return true; }
    void blocks(uint64_t height, std::vector<blobdata> &out) override { one(out, [&](blobdata &v) { return m_reader.get_block_blob(height, v); }); }
    void block_infos(uint64_t height, std::vector<lmdb_salvage::block_info_record> &out) override
    {
      one(out, [&](lmdb_salvage::block_info_record &v) { return m_reader.get_block_info(height, v); });
    }
    void hard_fork_versions(uint64_t height, std::vector<uint8_t> &out) override { one(out, [&](uint8_t &v) { return m_reader.get_hard_fork_version(height, v); }); }
    void pruned_txs(uint64_t tx_id, std::vector<blobdata> &out) override { one(out, [&](blobdata &v) { return m_reader.get_tx_pruned_blob(tx_id, v); }); }
    void prunable_txs(uint64_t tx_id, std::vector<blobdata> &out) override { one(out, [&](blobdata &v) { return m_reader.get_tx_prunable_blob(tx_id, v); }); }
    void prunable_hashes(uint64_t tx_id, std::vector<crypto::hash> &out) override { one(out, [&](crypto::hash &v) { return m_reader.get_tx_prunable_hash(tx_id, v); }); }

  private:
    template<typename T, typename F> static void one(std::vector<T> &out, F get)
    {
      out.clear();
      T v;
      if (get(v))
        out.push_back(std::move(v));
    }
    lmdb_salvage::blockchain_reader &m_reader;
  };

  //! every leaf page of the file, found by a page scan
  class page_scan_source: public chain_source
  {
  public:
    page_scan_source(lmdb_salvage::page_scan &scan, uint32_t pruning_seed): m_scan(scan), m_pruning_seed(pruning_seed) {}
    uint32_t pruning_seed() const override { return m_pruning_seed; }
    uint64_t recorded_height() const override { return m_scan.height_bound(); }
    bool needs_hard_fork_records() const override { return false; }
    void blocks(uint64_t height, std::vector<blobdata> &out) override { out = values(m_heights, height); }
    void block_infos(uint64_t height, std::vector<lmdb_salvage::block_info_record> &out) override { m_scan.block_infos(m_info_cursor, height, out); }
    void hard_fork_versions(uint64_t height, std::vector<uint8_t> &out) override
    {
      out.clear();
      for (const blobdata &v: values(m_heights, height))
        if (v.size() == 1)
          out.push_back(v[0]);
    }
    void pruned_txs(uint64_t tx_id, std::vector<blobdata> &out) override { out = values(m_txs, tx_id); }
    void prunable_txs(uint64_t tx_id, std::vector<blobdata> &out) override { out = values(m_txs, tx_id); }
    void prunable_hashes(uint64_t tx_id, std::vector<crypto::hash> &out) override
    {
      out.clear();
      for (const blobdata &v: values(m_txs, tx_id))
        if (v.size() == sizeof(crypto::hash))
          out.push_back(*reinterpret_cast<const crypto::hash*>(v.data()));
    }

  private:
    // the scanner asks for the same key several times in a row (block, then hf version; pruned, prunable, hash)
    struct lookup
    {
      lmdb_salvage::page_scan::cursor cursor;
      uint64_t key = UINT64_MAX;
      std::vector<blobdata> values;
    };
    const std::vector<blobdata> &values(lookup &l, uint64_t key)
    {
      if (l.key != key)
      {
        m_scan.values(l.cursor, key, l.values);
        // stale copies of a leaf repeat the same values
        std::sort(l.values.begin(), l.values.end());
        l.values.erase(std::unique(l.values.begin(), l.values.end()), l.values.end());
        l.key = key;
      }
      return l.values;
    }

    lmdb_salvage::page_scan &m_scan;
    const uint32_t m_pruning_seed;
    lookup m_heights, m_txs;
    lmdb_salvage::page_scan::cursor m_info_cursor;
  };

  // whether pruned + prunable is the transaction with this hash, without parsing the prunable part
  bool hashes_to(const transaction &base, const blobdata &pruned, const blobdata &prunable, const crypto::hash &expected)
  {
    crypto::hash hash;
    if (base.version < 2)
    {
      const blobdata blob = pruned + prunable;
      crypto::cn_fast_hash(blob.data(), blob.size(), hash);
      return hash == expected;
    }
    return get_pruned_transaction_hash(base, crypto::cn_fast_hash(prunable.data(), prunable.size()), hash) && hash == expected;
  }

  /**
   * Walks the damaged chain from genesis. Each block must parse, link to its
   * parent, and match its stored metadata; every transaction is read by its
   * sequential id and must hash to the value the block commits to. Weight,
   * long term weight, generated coins, cumulative difficulty, RingCT output
   * counts and the hard fork version are recomputed with the consensus
   * formulas and compared to the stored values, so the metadata copied into
   * the new database is checked, not trusted. The weight of a block whose
   * pruned transactions do not allow recomputing it is checked against the
   * compiled-in hashes of its 512-block chunk, as fast sync does.
   */
  class chain_scanner
  {
  public:
    //! fallback, if given, is asked once for a second source when source fails or ends; the blocks verified so far
    //! are valid whatever source supplied them, so the scan just goes on from there
    chain_scanner(chain_source &source, network_type nettype, const chunk_hashes &chunks, const std::atomic<bool> &stop,
        std::function<chain_source*()> fallback = nullptr):
      m_source(&source), m_fallback(std::move(fallback)), m_stop(stop), m_genesis(genesis_hash(nettype)), m_chunks(chunks),
      m_pruning_seed(source.pruning_seed()), m_recorded_height(source.recorded_height()), m_long_term_weights(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE)
    {
    }

    //! verify blocks [0, limit), and add each verified block to db when given; a fallback source may extend limit
    scan_result run(uint64_t limit, BlockchainDB *db);

  private:
    struct verified_block
    {
      uint64_t height;
      block blk;
      blobdata blob;
      crypto::hash hash;
      lmdb_salvage::block_info_record bi;
      uint8_t hf_version;
      difficulty_type cumulative_difficulty;
      std::vector<std::pair<transaction, blobdata>> txs;
      uint64_t pruned_txs;
      uint64_t bytes;
      enum { weight_checked, weight_unknown, weight_mismatch } weight_status; //!< recomputed, not recomputable, recomputed and different
    };

    bool verify(uint64_t height, verified_block &vb, std::string &failure);
    bool find_block(uint64_t height, verified_block &vb, std::string &failure);
    void accept(uint64_t height, const verified_block &vb);
    bool switch_to_fallback(uint64_t height, uint64_t &end);

    chain_source *m_source;
    std::function<chain_source*()> m_fallback;
    const std::atomic<bool> &m_stop;
    const crypto::hash m_genesis;
    const chunk_hashes &m_chunks;
    const uint32_t m_pruning_seed;
    uint64_t m_recorded_height;

    crypto::hash m_prev_hash = crypto::null_hash;
    uint64_t m_prev_coins = 0;
    difficulty_type m_prev_cumulative_difficulty = 0;
    uint64_t m_cumulative_rct_outputs = 0;
    uint64_t m_next_tx_id = 0;
    // difficulty window, as Blockchain::get_difficulty_for_next_block builds it (genesis excluded)
    std::deque<uint64_t> m_timestamps;
    std::deque<difficulty_type> m_cumulative_difficulties;
    // long term weights of the previous blocks, as Blockchain::get_long_term_block_weight_median sees them
    epee::misc_utils::rolling_median_t<uint64_t> m_long_term_weights;
  };

  // the parent hash a block blob names, read without parsing the block: three varints, then prev_id
  bool blob_prev_id(const blobdata &blob, crypto::hash &prev_id)
  {
    size_t pos = 0;
    for (int field = 0; field < 3; ++field)
    {
      for (int i = 0; ; ++i)
      {
        if (pos >= blob.size() || i >= 10)
          return false;
        if (!((uint8_t)blob[pos++] & 0x80))
          break;
      }
    }
    if (pos + sizeof(crypto::hash) > blob.size())
      return false;
    memcpy(prev_id.data, blob.data() + pos, sizeof(prev_id));
    return true;
  }

  //! mutes the parse errors of cryptonote_basic while a page scan offers values that are no blocks or transactions
  struct quiet_parsing
  {
    const std::string saved = mlog_get_categories();
    quiet_parsing() { mlog_set_categories("+cn:FATAL"); }
    ~quiet_parsing() { mlog_set_categories(saved.c_str()); }
  };

  //! the stored block for this height that parses, links to its parent and pays its coinbase at this height
  bool chain_scanner::find_block(uint64_t height, verified_block &vb, std::string &failure)
  {
    const std::string at = " at height " + std::to_string(height);
    std::vector<blobdata> blobs;
    m_source->blocks(height, blobs);
    std::string why = "block is missing";
    struct candidate { blobdata blob; block blk; crypto::hash hash; };
    std::vector<candidate> found;
    const crypto::hash parent = height ? m_prev_hash : crypto::null_hash;
    for (blobdata &blob: blobs)
    {
      candidate c;
      crypto::hash prev_id;
      if (!blob_prev_id(blob, prev_id) || prev_id != parent)
      {
        if (why == "block is missing")
          why = "block does not link to its parent";
        continue;
      }
      if (!parse_and_validate_block_from_blob(blob, c.blk, c.hash))
      {
        if (why == "block is missing")
          why = "block does not parse";
        continue;
      }
      if (height == 0 ? c.hash != m_genesis : c.blk.prev_id != m_prev_hash)
      {
        why = "block does not link to its parent";
        continue;
      }
      const transaction &miner_tx = c.blk.miner_tx;
      if (miner_tx.vin.size() != 1 || miner_tx.vin[0].type() != typeid(txin_gen) || boost::get<txin_gen>(miner_tx.vin[0]).height != height)
      {
        why = "coinbase transaction is not for this height";
        continue;
      }
      if (std::none_of(found.begin(), found.end(), [&](const candidate &f) { return f.hash == c.hash; }))
      {
        c.blob = std::move(blob);
        found.push_back(std::move(c));
      }
    }
    if (found.size() > 1)
    {
      // a reorganization can leave the replaced block behind in a stale page: keep the one the next block builds on
      std::vector<blobdata> next;
      m_source->blocks(height + 1, next);
      found.erase(std::remove_if(found.begin(), found.end(), [&](const candidate &c) {
        return std::none_of(next.begin(), next.end(), [&](const blobdata &n) {
          crypto::hash prev_id;
          block b;
          return blob_prev_id(n, prev_id) && prev_id == c.hash && parse_and_validate_block_from_blob(n, b) && b.prev_id == c.hash;
        });
      }), found.end());
      if (found.size() != 1)
      {
        failure = "several different blocks are stored for this height, and the next block does not tell which one is current" + at;
        return false;
      }
    }
    if (found.empty())
    {
      failure = why + at;
      return false;
    }
    vb.blob = std::move(found[0].blob);
    vb.blk = std::move(found[0].blk);
    vb.hash = found[0].hash;
    return true;
  }

  bool chain_scanner::verify(uint64_t height, verified_block &vb, std::string &failure)
  {
    const std::string at = " at height " + std::to_string(height);
    try
    {
      std::vector<uint8_t> versions;
      m_source->hard_fork_versions(height, versions);
      if (!find_block(height, vb, failure))
        return false;
      // HardFork::add records a version only for a block whose major version is the one in force
      if (versions.empty() && m_source->needs_hard_fork_records())
      {
        failure = "hard fork version is missing" + at;
        return false;
      }
      if (!versions.empty() && std::find(versions.begin(), versions.end(), vb.blk.major_version) == versions.end())
      {
        failure = "hard fork version in the metadata disagrees with the block's major version" + at;
        return false;
      }
      vb.hf_version = vb.blk.major_version;
      const transaction &miner_tx = vb.blk.miner_tx;

      // a pruned database keeps the prunable data of its own stripe, beyond the tip window it had when pruning
      const bool stripe_kept = m_pruning_seed && height + CRYPTONOTE_PRUNING_TIP_BLOCKS < m_recorded_height &&
        tools::has_unpruned_block(height, m_recorded_height, m_pruning_seed);

      vb.txs.clear();
      vb.pruned_txs = 0;
      vb.bytes = vb.blob.size();
      uint64_t weight = get_transaction_weight(miner_tx);
      bool weight_computable = true;
      bool estimated_weight = false; // includes pruned transactions weighed by get_pruned_transaction_weight
      uint64_t fees = 0;
      uint64_t rct_outputs = miner_tx.version >= 2 ? miner_tx.vout.size() : 0;
      const crypto::hash miner_tx_hash = get_transaction_hash(miner_tx);

      // the coinbase transaction comes first, then the block's list, at consecutive ids
      std::vector<blobdata> pruned_candidates, prunable_candidates;
      std::vector<crypto::hash> prunable_hashes;
      for (size_t i = 0; i <= vb.blk.tx_hashes.size(); ++i)
      {
        const uint64_t tx_id = m_next_tx_id + i;
        const crypto::hash &expected = i == 0 ? miner_tx_hash : vb.blk.tx_hashes[i - 1];
        const std::string tx_at = "transaction id " + std::to_string(tx_id) + at;
        m_source->pruned_txs(tx_id, pruned_candidates);
        if (pruned_candidates.empty())
        {
          failure = tx_at + " is missing";
          return false;
        }
        m_source->prunable_txs(tx_id, prunable_candidates);
        // a coinbase (and any RCTTypeNull or signature-less transaction) is complete without a prunable record
        const bool stored_empty = std::find(prunable_candidates.begin(), prunable_candidates.end(), blobdata()) != prunable_candidates.end();
        if (!stored_empty)
          prunable_candidates.push_back(blobdata());

        // full: the stored prunable part completes the committed hash; pruned (a pruned database only): the
        // stored prunable hash does. --sync-pruned-blocks stores a downloaded pruned transaction with an empty
        // prunable record until the next pruning pass, which therefore matches the pruned case
        transaction tx;
        blobdata blob;
        bool found = false, pruned = false, parsed = false;
        // with several stored prunable parts (a page scan), hash before parsing
        const bool hash_first = std::count_if(prunable_candidates.begin(), prunable_candidates.end(), [](const blobdata &b) { return !b.empty(); }) > 1;
        for (const blobdata &candidate: pruned_candidates)
        {
          transaction base;
          if (!parse_and_validate_tx_base_from_blob(candidate, base, false, true))
            continue;
          parsed = true;
          for (const blobdata &prunable: prunable_candidates)
          {
            if (hash_first && !prunable.empty() && !hashes_to(base, candidate, prunable, expected))
              continue;
            blobdata full_blob = candidate + prunable;
            crypto::hash tx_hash;
            if (parse_and_validate_tx_from_blob(full_blob, tx, tx_hash) && tx_hash == expected)
            {
              blob = std::move(full_blob);
              found = true;
              break;
            }
          }
          if (found)
            break;
          // pruning never touches v1 transactions
          if (!m_pruning_seed || base.version < 2)
            continue;
          m_source->prunable_hashes(tx_id, prunable_hashes);
          for (const crypto::hash &prunable_hash: prunable_hashes)
          {
            crypto::hash tx_hash;
            if (get_pruned_transaction_hash(base, prunable_hash, tx_hash) && tx_hash == expected)
            {
              tx = std::move(base);
              blob = candidate;
              found = pruned = true;
              break;
            }
          }
          if (found)
            break;
        }
        if (!found)
        {
          if (!parsed)
            failure = tx_at + " does not parse";
          else if (!m_pruning_seed && prunable_candidates.size() == 1 && prunable_candidates[0].empty())
            failure = "prunable data of " + tx_at + " is missing from an unpruned database";
          else
            failure = tx_at + " does not match the hash committed to by the block";
          return false;
        }
        if (pruned)
        {
          if (stripe_kept)
          {
            failure = "prunable data of " + tx_at + " is missing, but this database keeps that block's pruning stripe";
            return false;
          }
          // pruning never deletes a record in the tip window; there, only --sync-pruned-blocks leaves a transaction
          // pruned, and it stores an empty prunable record for it
          if (height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= m_recorded_height && !stored_empty)
          {
            failure = "prunable data of " + tx_at + " is missing in the tip window, where it is never pruned";
            return false;
          }
          ++vb.pruned_txs;
          uint64_t tx_weight;
          if (i > 0 && pruned_transaction_weight(tx, blob.size(), tx_weight))
          {
            weight += tx_weight;
            estimated_weight = true;
          }
          else if (i > 0)
            weight_computable = false;
        }
        if (i == 0)
          continue; // the coinbase is written from the block itself

        uint64_t fee;
        if (!get_tx_fee(tx, fee) || fees + fee < fees)
        {
          failure = "fee of " + tx_at + " is invalid";
          return false;
        }
        fees += fee;
        if (!tx.pruned)
          weight += get_transaction_weight(tx, blob.size());
        for (const tx_out &out: tx.vout)
          if (out.amount == 0)
            ++rct_outputs;
        vb.bytes += blob.size();
        vb.txs.emplace_back(std::move(tx), std::move(blob));
      }

      // every hard fork credits exactly the coinbase outputs minus the fees (see Blockchain::validate_miner_transaction)
      uint64_t money_in_use = 0;
      for (const tx_out &out: miner_tx.vout)
      {
        if (money_in_use + out.amount < money_in_use)
        {
          failure = "coinbase outputs overflow" + at;
          return false;
        }
        money_in_use += out.amount;
      }
      if (money_in_use < fees)
      {
        failure = "coinbase pays out less than the fees" + at;
        return false;
      }
      const uint64_t reward = money_in_use - fees;
      const uint64_t prev_coins = height ? m_prev_coins : 0;
      const uint64_t coins = reward < MONEY_SUPPLY - prev_coins ? prev_coins + reward : MONEY_SUPPLY;
      const difficulty_type cumulative_difficulty = next_difficulty(
        std::vector<uint64_t>(m_timestamps.begin(), m_timestamps.end()),
        std::vector<difficulty_type>(m_cumulative_difficulties.begin(), m_cumulative_difficulties.end()),
        vb.hf_version < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2) + (height ? m_prev_cumulative_difficulty : 0);

      // the stored metadata: every field must be what the consensus rules derive (a page scan may offer stale copies)
      std::vector<lmdb_salvage::block_info_record> infos;
      m_source->block_infos(height, infos);
      std::string why = "block metadata is missing";
      for (const lmdb_salvage::block_info_record &bi: infos)
      {
        if (bi.height != height || bi.hash != vb.hash || bi.timestamp != vb.blk.timestamp)
        {
          why = "block metadata does not describe the block";
          continue;
        }
        if (bi.coins_generated != coins)
        {
          why = "generated coins in the block metadata disagree with the coinbase";
          continue;
        }
        // a block with pruned transactions was weighed from the fast sync weight list when it was synced; its
        // weight is recomputed where the pruned transactions allow it, and otherwise (or if the recomputation
        // differs) left to the compiled-in chunk hashes
        if (weight_computable && !estimated_weight && bi.weight != weight)
        {
          why = "block weight in the metadata disagrees with the transactions";
          continue;
        }
        // long term weight, as Blockchain::get_next_long_term_block_weight computes it when the block is added
        uint64_t long_term_weight = bi.weight;
        if (vb.hf_version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT && m_long_term_weights.size() > 0)
        {
          const uint64_t effective_median = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, m_long_term_weights.median());
          uint64_t limit;
          if (vb.hf_version >= HF_VERSION_2021_SCALING)
          {
            long_term_weight = std::max<uint64_t>(long_term_weight, effective_median * 10 / 17);
            limit = effective_median + effective_median * 7 / 10;
          }
          else
            limit = effective_median + effective_median * 2 / 5;
          long_term_weight = std::min<uint64_t>(long_term_weight, limit);
        }
        if (bi.long_term_weight != long_term_weight)
        {
          why = "long term block weight in the metadata disagrees with the consensus rule";
          continue;
        }
        if (make_difficulty(bi.cumulative_difficulty_low, bi.cumulative_difficulty_high) != cumulative_difficulty)
        {
          why = "cumulative difficulty in the block metadata disagrees with the difficulty rules";
          continue;
        }
        if (bi.cumulative_rct_outputs != m_cumulative_rct_outputs + rct_outputs)
        {
          why = "RingCT output count in the block metadata disagrees with the transactions";
          continue;
        }
        vb.bi = bi;
        vb.cumulative_difficulty = cumulative_difficulty;
        vb.weight_status = !weight_computable ? verified_block::weight_unknown : bi.weight == weight ? verified_block::weight_checked : verified_block::weight_mismatch;
        return true;
      }
      failure = why + at;
      return false;
    }
    catch (const read_error &e)
    {
      failure = std::string("unreadable data") + at + ": " + e.what();
      return false;
    }
  }

  void chain_scanner::accept(uint64_t height, const verified_block &vb)
  {
    m_prev_hash = vb.hash;
    m_prev_coins = vb.bi.coins_generated;
    m_prev_cumulative_difficulty = vb.cumulative_difficulty;
    m_cumulative_rct_outputs = vb.bi.cumulative_rct_outputs;
    m_next_tx_id += 1 + vb.blk.tx_hashes.size();
    m_long_term_weights.insert(vb.bi.long_term_weight);
    if (height > 0)
    {
      m_timestamps.push_back(vb.blk.timestamp);
      m_cumulative_difficulties.push_back(vb.cumulative_difficulty);
      while (m_timestamps.size() > static_cast<uint64_t>(DIFFICULTY_BLOCKS_COUNT))
      {
        m_timestamps.pop_front();
        m_cumulative_difficulties.pop_front();
      }
    }
  }

  bool chain_scanner::switch_to_fallback(uint64_t height, uint64_t &end)
  {
    if (!m_fallback)
      return false;
    chain_source *source = m_fallback();
    m_fallback = nullptr;
    if (!source)
      return false;
    m_source = source;
    m_recorded_height = std::max(m_recorded_height, source->recorded_height());
    end = std::max(end, source->recorded_height());
    MGINFO("  continuing from height " << height << " with the chain records of the page scan (up to height " << end << ")");
    return height < end;
  }

  scan_result chain_scanner::run(uint64_t limit, BlockchainDB *db)
  {
    scan_result result;
    bool batch_open = false;
    uint64_t batch_blocks = 0, batch_bytes = 0;
    auto last_report = std::chrono::steady_clock::now();
    const auto start = last_report;

    // verified blocks are released (written) in order; a block whose weight is not checked yet holds back
    // itself and everything after it until its 512-block chunk matches the compiled-in hashes
    std::deque<verified_block> pending;
    uint64_t unchecked_from = UINT64_MAX; // first block of the current chunk with an unchecked weight
    bool chunk_mismatch = false;
    std::vector<crypto::hash> chunk_block_hashes;
    std::vector<uint64_t> chunk_block_weights;
    const auto release = [&](uint64_t below) {
      while (!pending.empty() && pending.front().height < below)
      {
        const verified_block &vb = pending.front();
        if (db)
        {
          if (!batch_open)
          {
            db->batch_start(BATCH_BLOCKS, BATCH_BYTES);
            batch_open = true;
            batch_blocks = batch_bytes = 0;
          }
          db->add_block(std::make_pair(vb.blk, vb.blob), vb.bi.weight, vb.bi.long_term_weight, vb.cumulative_difficulty, vb.bi.coins_generated, vb.txs);
          const uint8_t computed_version = db->get_hard_fork_version(vb.height);
          if (computed_version != vb.hf_version)
            throw std::runtime_error("hard fork version mismatch at height " + std::to_string(vb.height) + ": the damaged database recorded " +
              std::to_string(vb.hf_version) + ", the rebuilt one computed " + std::to_string(computed_version));
          batch_bytes += vb.bytes;
          if (++batch_blocks >= BATCH_BLOCKS || batch_bytes >= BATCH_BYTES)
          {
            db->batch_stop();
            batch_open = false;
          }
        }
        result.height = vb.height + 1;
        result.txs += 1 + vb.blk.tx_hashes.size();
        result.pruned_txs += vb.pruned_txs;
        result.top_hash = vb.hash;
        pending.pop_front();
      }
    };

    uint64_t end = limit;
    for (uint64_t height = 0; height < end || switch_to_fallback(height, end); ++height)
    {
      if (m_stop)
      {
        result.interrupted = true;
        break;
      }
      verified_block vb;
      if (!verify(height, vb, result.failure))
      {
        std::string failure;
        if (!switch_to_fallback(height, end) || height >= end || !verify(height, vb, failure))
        {
          if (!failure.empty())
            result.failure += "; the page scan also fails: " + failure;
          break;
        }
        result.failure.clear();
      }
      accept(height, vb);
      vb.height = height;

      if (height % HASH_OF_HASHES_STEP == 0)
      {
        chunk_block_hashes.clear();
        chunk_block_weights.clear();
      }
      chunk_block_hashes.push_back(vb.hash);
      chunk_block_weights.push_back(vb.bi.weight);
      if (vb.weight_status != verified_block::weight_checked)
      {
        if (height / HASH_OF_HASHES_STEP < m_chunks.size())
        {
          if (unchecked_from == UINT64_MAX)
            unchecked_from = height;
        }
        else if (vb.weight_status == verified_block::weight_mismatch)
        {
          result.failure = "block weight in the metadata disagrees with the pruned transactions at height " + std::to_string(height) +
            ", and no compiled-in block weights cover it";
          break;
        }
        else
        {
          // testnet and stagenet have no compiled-in weights; without them only pre-Bulletproof and
          // Bulletproof2+ pruned transactions can be weighed, so the stored weight has to be taken
          if (!result.unverified_weights++)
            result.first_unverified_weight = height;
        }
      }
      pending.push_back(std::move(vb));

      if (unchecked_from != UINT64_MAX && chunk_block_hashes.size() == HASH_OF_HASHES_STEP)
      {
        // same check as Blockchain::prevalidate_block_hashes
        const uint64_t chunk = height / HASH_OF_HASHES_STEP;
        crypto::hash hashes_hash, weights_hash;
        crypto::cn_fast_hash(chunk_block_hashes.data(), chunk_block_hashes.size() * sizeof(crypto::hash), hashes_hash);
        crypto::cn_fast_hash(chunk_block_weights.data(), chunk_block_weights.size() * sizeof(uint64_t), weights_hash);
        if (chunk >= m_chunks.size() || hashes_hash != m_chunks[chunk].first || weights_hash != m_chunks[chunk].second)
        {
          result.failure = "the weight of block " + std::to_string(unchecked_from) + " cannot be recomputed from its pruned transactions, and " +
            (chunk >= m_chunks.size() ? std::string("no compiled-in block weights cover it") :
            "blocks " + std::to_string(chunk * HASH_OF_HASHES_STEP) + "-" + std::to_string(height) + " disagree with the compiled-in block hashes and weights");
          chunk_mismatch = true;
          break;
        }
        unchecked_from = UINT64_MAX;
      }
      release(unchecked_from);

      const auto now = std::chrono::steady_clock::now();
      if (now - last_report >= std::chrono::seconds(10))
      {
        const double secs = std::chrono::duration<double>(now - start).count();
        MGINFO("  " << (db ? "rebuilt" : "verified") << " " << result.height << " / " << limit << " blocks (" << (uint64_t)(result.height / secs) << " blocks/s)");
        last_report = now;
      }
    }

    if (!result.interrupted)
    {
      if (unchecked_from != UINT64_MAX && !chunk_mismatch)
        result.failure = "the weight of block " + std::to_string(unchecked_from) + " cannot be recomputed from its pruned transactions, and the 512-block chunk "
          "of compiled-in block weights that covers it is incomplete" + (result.failure.empty() ? std::string() : " because the chain ends early: " + result.failure);
      release(unchecked_from);
    }
    if (batch_open)
    {
      if (result.interrupted)
        db->batch_abort();
      else
        db->batch_stop();
    }
    return result;
  }

  // the new database and its directory, removed again unless installed
  struct new_db_guard
  {
    fs::path dir;
    std::unique_ptr<BlockchainDB> db;
    std::unique_ptr<HardFork> hf;
    bool keep = false;

    //! close and remove the new database
    void discard()
    {
      if (db && db->is_open())
      {
        try { db->batch_abort(); } catch (...) {}
        db->close();
      }
      db.reset();
      hf.reset();
      if (!dir.empty() && fs::exists(dir))
      {
        fs::remove_all(dir);
        MGINFO("Removed the incomplete database " << dir.string());
      }
    }

    ~new_db_guard()
    {
      try
      {
        if (keep)
        {
          if (db && db->is_open())
            db->close();
        }
        else
          discard();
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to clean up " << dir.string() << ": " << e.what());
      }
    }
  };

  std::string timestamp_suffix()
  {
    const std::time_t now = std::time(nullptr);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &tm);
    return buf;
  }

  void copy_txpool_and_alt_blocks(lmdb_salvage::blockchain_reader &reader, BlockchainDB &db)
  {
    std::vector<std::string> errors;
    uint64_t txpool_copied = 0, txpool_skipped = 0, alt_copied = 0, alt_skipped = 0;
    db.batch_start();
    reader.for_each_txpool_tx([&](const crypto::hash &txid, const std::string &meta_blob, const std::string &blob) {
      txpool_tx_meta_t meta;
      transaction tx;
      crypto::hash hash = crypto::null_hash;
      bool ok = meta_blob.size() == sizeof(meta);
      if (ok)
      {
        memcpy(&meta, meta_blob.data(), sizeof(meta));
        if (meta.pruned)
          ok = meta.prunable_hash_valid && parse_and_validate_tx_base_from_blob(blob, tx, false, true) && get_pruned_transaction_hash(tx, meta.prunable_hash, hash);
        else
          ok = parse_and_validate_tx_from_blob(blob, tx, hash);
      }
      if (!ok || hash != txid)
      {
        ++txpool_skipped;
        return;
      }
      // cached verification results refer to the old chain tip, which may be gone: force a fresh check
      meta.max_used_block_id = crypto::null_hash;
      meta.max_used_block_height = 0;
      meta.last_failed_id = crypto::null_hash;
      meta.last_failed_height = 0;
      meta.valid_input_verification_id = crypto::null_hash;
      db.add_txpool_tx(txid, blob, meta);
      ++txpool_copied;
    }, errors);
    reader.for_each_alt_block([&](const crypto::hash &id, const std::string &value) {
      alt_block_data_t data;
      block b;
      crypto::hash hash = crypto::null_hash;
      if (value.size() <= sizeof(data))
      {
        ++alt_skipped;
        return;
      }
      memcpy(&data, value.data(), sizeof(data));
      const std::string blob = value.substr(sizeof(data));
      const bool ok = parse_and_validate_block_from_blob(blob, b, hash) && hash == id && b.miner_tx.vin.size() == 1 &&
        b.miner_tx.vin[0].type() == typeid(txin_gen) && boost::get<txin_gen>(b.miner_tx.vin[0]).height == data.height;
      if (!ok)
      {
        ++alt_skipped;
        return;
      }
      db.add_alt_block(id, data, blob);
      ++alt_copied;
    }, errors);
    db.batch_stop();
    MGINFO("Carried over " << txpool_copied << " txpool transactions and " << alt_copied << " alternative blocks" <<
      (txpool_skipped + alt_skipped ? " (skipped " + std::to_string(txpool_skipped) + " transactions and " + std::to_string(alt_skipped) + " blocks that failed verification)" : ""));
    for (const std::string &e: errors)
      MWARNING("  unreadable txpool/alternative block data: " << e);
  }
}

namespace cryptonote
{
  bool reconstruct_blockchain_db(const fs::path &data_dir, const std::atomic<bool> &stop, const block_hashes_callback &get_block_hashes)
  {
    const fs::path old_dir = data_dir / "lmdb";
    const fs::path data_file = old_dir / CRYPTONOTE_BLOCKCHAINDATA_FILENAME;
    const fs::path new_dir = data_dir / NEW_DB_DIR;

    MGINFO("Reconstructing the blockchain database in " << old_dir.string());
    boost::system::error_code ec;
    if (!fs::is_regular_file(data_file, ec))
    {
      MERROR("No blockchain database found at " << data_file.string());
      return false;
    }
    if (fs::exists(new_dir, ec))
    {
      MERROR(new_dir.string() << " already exists, probably from an interrupted reconstruction. Remove it and try again.");
      return false;
    }
    if (db_in_use(old_dir))
    {
      MERROR("The database is in use by another process. Stop monerod first.");
      return false;
    }

    std::unique_ptr<lmdb_salvage::blockchain_reader> reader;
    try
    {
      reader.reset(new lmdb_salvage::blockchain_reader(data_file.string()));
    }
    catch (const read_error &e)
    {
      MERROR("Cannot read the damaged database: " << e.what());
      return false;
    }
    // the new database will need at most as much space as the old one uses
    uint64_t used_pages = 0;
    for (const lmdb_salvage::snapshot &s: reader->snapshots())
      used_pages = std::max(used_pages, s.last_pgno + 1);
    if (used_pages == 0)
      used_pages = reader->file().file_pages();
    const uint64_t used_bytes = used_pages * reader->file().page_size();
    MGINFO("Damaged database: " << gib(used_bytes) << " in use, page size " << reader->file().page_size() << ", " << reader->snapshots().size() << " readable snapshot(s)");
    if (reader->file().file_size() < used_bytes)
      MGINFO_YELLOW("The data file is " << (used_bytes - reader->file().file_size()) << " bytes shorter than its contents: it was truncated, the newest data never reached the disk");

    // do not start unless a second database of the same size fits next to the damaged one
    const fs::space_info space = fs::space(data_dir, ec);
    if (ec)
    {
      MERROR("Cannot determine the free space in " << data_dir.string() << ": " << ec.message());
      return false;
    }
    if (space.available < used_bytes)
    {
      MERROR("Not enough free space: the new database needs up to " << gib(used_bytes) << " next to the damaged one, but only " <<
        gib(space.available) << " is available in " << data_dir.string());
      return false;
    }
    MGINFO("Free space: " << gib(space.available) << " available, up to " << gib(used_bytes) << " needed");

    // pick the snapshots worth scanning; identical ones are scanned once
    struct candidate { lmdb_salvage::snapshot snapshot; network_type nettype; uint64_t recorded; };
    std::vector<candidate> candidates;
    std::vector<std::string> fingerprints;
    uint64_t recorded_blocks = 0;
    for (const lmdb_salvage::snapshot &s: reader->snapshots())
    {
      try
      {
        reader->select_snapshot(s);
      }
      catch (const read_error &e)
      {
        MWARNING("Snapshot of transaction " << s.txnid << " is unusable: " << e.what());
        continue;
      }
      if (reader->schema_version() != lmdb_salvage::SUPPORTED_SCHEMA_VERSION)
      {
        MWARNING("Snapshot of transaction " << s.txnid << " is unusable: it has schema version " << reader->schema_version() <<
          ", but only version " << lmdb_salvage::SUPPORTED_SCHEMA_VERSION << " can be reconstructed by this monerod");
        continue;
      }
      const std::string fp = reader->fingerprint();
      if (std::find(fingerprints.begin(), fingerprints.end(), fp) != fingerprints.end())
        continue;
      network_type nettype;
      std::string error;
      if (!detect_network(*reader, nettype, error))
      {
        MWARNING("Snapshot of transaction " << s.txnid << " is unusable: " << error);
        continue;
      }
      fingerprints.push_back(fp);
      candidates.push_back({s, nettype, reader->recorded_block_count()});
      recorded_blocks = std::max(recorded_blocks, reader->recorded_block_count());
    }

    new_db_guard guard;
    scan_result result;
    network_type nettype = UNDEFINED;
    uint32_t pruning_seed = 0;
    uint64_t snapshot_height = 0; // recorded height of the snapshot used, 0 if none
    lmdb_salvage::snapshot chosen_snapshot{};
    // a fresh new database, filled from source
    const auto rebuild = [&](chain_source &source, uint64_t limit, network_type net, uint32_t seed, std::function<chain_source*()> fallback) {
      guard.discard();
      guard.dir = new_dir;
      guard.db.reset(new_db());
      guard.db->open(new_dir.string(), DBF_FAST);
      guard.db->set_batch_transactions(true);
      if (seed)
        guard.db->prune_blockchain(seed);
      guard.hf = make_hard_fork(*guard.db, net);
      guard.db->set_hard_fork(guard.hf.get());
      MGINFO("Rebuilding into " << new_dir.string());
      const chunk_hashes chunks = load_chunk_hashes(get_block_hashes, net);
      return chain_scanner(source, net, chunks, stop, std::move(fallback)).run(limit, guard.db.get());
    };

    // The trees hang off pages that every commit rewrites, so after a power loss they are the most likely
    // to be stale or missing while the leaves below them survive. When the snapshot's tables fail or end,
    // every leaf page of the file is looked at instead, and the scan goes on from where it stopped.
    std::unique_ptr<lmdb_salvage::page_scan> scan;
    std::unique_ptr<page_scan_source> scan_source;
    std::unique_ptr<quiet_parsing> quiet;
    const auto run_page_scan = [&]() {
      MGINFO("Scanning all " << reader->file().file_pages() << " pages of the file for chain records outside the snapshot's trees");
      scan.reset(new lmdb_salvage::page_scan(reader->file(), stop));
      if (scan->interrupted())
        return false;
      MGINFO("Page scan: " << scan->leaf_pages() << " leaf pages and " << scan->block_info_pages() << " block metadata pages, metadata up to height " <<
        (scan->height_bound() ? scan->height_bound() - 1 : 0));
      quiet.reset(new quiet_parsing());
      return true;
    };

    try
    {
      if (candidates.empty())
      {
        // nothing readable through the trees: schema version, pruning seed and network from the page scan alone
        MWARNING("No snapshot of the damaged database has a readable chain");
        if (!run_page_scan())
        {
          MGINFO("Interrupted, the damaged database was left untouched");
          return false;
        }
        const std::set<uint32_t> &versions = scan->schema_versions();
        if (versions.empty())
          MWARNING("No properties record survived; assuming schema version " << lmdb_salvage::SUPPORTED_SCHEMA_VERSION << " and no pruning");
        else if (!versions.count(lmdb_salvage::SUPPORTED_SCHEMA_VERSION))
        {
          MERROR("The database has schema version " << *versions.rbegin() << ", but only version " << lmdb_salvage::SUPPORTED_SCHEMA_VERSION <<
            " can be reconstructed by this monerod");
          return false;
        }
        const std::set<uint32_t> &seeds = scan->pruning_seeds();
        if (seeds.size() > 1)
          MWARNING("Properties records with different pruning seeds survived; treating the database as unpruned");
        pruning_seed = seeds.size() == 1 ? *seeds.begin() : 0;
        page_scan_source probe(*scan, pruning_seed);
        std::vector<blobdata> genesis;
        probe.blocks(0, genesis);
        for (const blobdata &blob: genesis)
        {
          block b;
          crypto::hash hash;
          for (network_type n: {MAINNET, TESTNET, STAGENET})
            if (parse_and_validate_block_from_blob(blob, b, hash) && hash == genesis_hash(n))
              nettype = n;
        }
        if (nettype == UNDEFINED)
        {
          MERROR("The page scan found no genesis block of a known network; nothing can be recovered");
          return false;
        }
        MGINFO("Using the chain records found by the page scan: " << network_name(nettype) << ", " <<
          (pruning_seed ? "pruned (seed " + std::to_string(pruning_seed) + ")" : std::string("not pruned")));
        page_scan_source source(*scan, pruning_seed);
        result = rebuild(source, scan->height_bound(), nettype, pruning_seed, nullptr);
      }
      else
      {
        // with differing snapshots, keep the one with the longer verified chain
        size_t chosen = 0;
        uint64_t limit = UINT64_MAX;
        if (candidates.size() > 1)
        {
          uint64_t best = 0;
          for (size_t i = 0; i < candidates.size(); ++i)
          {
            reader->select_snapshot(candidates[i].snapshot);
            MGINFO("Verifying the snapshot of transaction " << candidates[i].snapshot.txnid << " (" << reader->recorded_block_count() << " blocks recorded)");
            snapshot_source source(*reader);
            const chunk_hashes chunks = load_chunk_hashes(get_block_hashes, candidates[i].nettype);
            const scan_result r = chain_scanner(source, candidates[i].nettype, chunks, stop).run(reader->recorded_block_count(), nullptr);
            if (r.interrupted)
            {
              MGINFO("Interrupted, nothing was changed");
              return false;
            }
            MGINFO("  " << r.height << " blocks verified" << (r.failure.empty() ? "" : ", then " + r.failure));
            if (r.height > best)
            {
              best = r.height;
              chosen = i;
            }
          }
          limit = best;
        }
        chosen_snapshot = candidates[chosen].snapshot;
        reader->select_snapshot(chosen_snapshot);
        nettype = candidates[chosen].nettype;
        pruning_seed = reader->pruning_seed();
        snapshot_height = reader->recorded_block_count();
        limit = std::min(limit, snapshot_height);
        MGINFO("Using the snapshot of transaction " << chosen_snapshot.txnid << ": " << network_name(nettype) << ", " <<
          snapshot_height << " blocks and " << reader->recorded_tx_count() << " transactions recorded, " <<
          (pruning_seed ? "pruned (seed " + std::to_string(pruning_seed) + ")" : std::string("not pruned")));
        snapshot_source source(*reader);
        result = rebuild(source, limit, nettype, pruning_seed, [&]() -> chain_source* {
          if (!run_page_scan())
            return nullptr;
          scan_source.reset(new page_scan_source(*scan, pruning_seed));
          return scan_source.get();
        });
      }
      quiet.reset();
      if (result.interrupted)
      {
        MGINFO("Interrupted, the damaged database was left untouched");
        return false;
      }
      if (scan)
        recorded_blocks = std::max(recorded_blocks, scan->height_bound());

      if (result.height == 0)
      {
        MERROR("Not even the genesis block could be recovered: " << (result.failure.empty() ? std::string("no usable chain data") : result.failure));
        return false;
      }

      // the txpool and alternative blocks belong to the snapshot's tip; a chain extended past it may contain their txs
      if (snapshot_height && result.height <= snapshot_height)
      {
        reader->select_snapshot(chosen_snapshot);
        copy_txpool_and_alt_blocks(*reader, *guard.db);
      }
      if (pruning_seed)
        guard.db->update_pruning();
      guard.db->close();
    }
    catch (const std::exception &e)
    {
      MERROR("Reconstruction failed: " << e.what());
      return false;
    }

    // re-open the result to make sure it is what monerod will see
    try
    {
      std::unique_ptr<BlockchainDB> check(new_db());
      check->open(new_dir.string(), DBF_RDONLY);
      const bool good = check->height() == result.height && check->top_block_hash() == result.top_hash &&
        check->get_blockchain_pruning_seed() == pruning_seed && check->get_tx_count() == result.txs;
      check->close();
      if (!good)
      {
        MERROR("The rebuilt database does not hold the expected chain");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      MERROR("The rebuilt database cannot be opened: " << e.what());
      return false;
    }

    const uint64_t damaged_size = reader->file().file_size();
    reader.reset();

    copy_permissions(old_dir, new_dir);
    copy_permissions(data_file, new_dir / CRYPTONOTE_BLOCKCHAINDATA_FILENAME);
    copy_permissions(old_dir / CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME, new_dir / CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME);

    fs::path damaged_dir = data_dir / ("lmdb.damaged-" + timestamp_suffix());
    for (int n = 1; fs::exists(damaged_dir, ec); ++n)
      damaged_dir = data_dir / ("lmdb.damaged-" + timestamp_suffix() + "-" + std::to_string(n));
    fs::rename(old_dir, damaged_dir, ec);
    if (ec)
    {
      MERROR("Failed to move the damaged database to " << damaged_dir.string() << ": " << ec.message());
      return false;
    }
    fs::rename(new_dir, old_dir, ec);
    if (ec)
    {
      MERROR("Failed to move the rebuilt database into place: " << ec.message());
      boost::system::error_code ec2;
      fs::rename(damaged_dir, old_dir, ec2);
      if (ec2)
        MERROR("Also failed to move the damaged database back from " << damaged_dir.string() << ": " << ec2.message());
      return false;
    }
    guard.keep = true;
    sync_directory(data_dir);

    MGINFO_GREEN("Blockchain database reconstructed: " << result.height << " of " << recorded_blocks << " recorded blocks recovered (top block " <<
      result.height - 1 << " " << epee::string_tools::pod_to_hex(result.top_hash) << "), " << result.txs << " transactions" <<
      (result.pruned_txs ? " (" + std::to_string(result.pruned_txs) + " pruned)" : std::string()));
    if (!result.failure.empty())
      MGINFO("Recovery stopped at the first unusable block: " << result.failure);
    if (result.unverified_weights)
      MGINFO_YELLOW("The weights of " << result.unverified_weights << " blocks with pruned transactions (the first at height " << result.first_unverified_weight <<
        ") could not be checked: this network has no compiled-in block weights, so the stored ones were kept");
    MGINFO("The damaged database was kept as " << damaged_dir.string() << "; delete it once the node runs fine to free " << gib(damaged_size));
    if (nettype == MAINNET)
      MGINFO("Start monerod with --data-dir " << data_dir.string() << " to resume syncing");
    else
    {
      const char *net = network_name(nettype);
      if (data_dir.filename() == net)
        MGINFO("Start monerod with --" << net << " --data-dir " << data_dir.parent_path().string() << " to resume syncing");
      else
        MGINFO_YELLOW("This is a " << net << " database; monerod --" << net << " looks for it in a \"" << net << "\" subdirectory of its --data-dir");
    }
    return true;
  }
}
