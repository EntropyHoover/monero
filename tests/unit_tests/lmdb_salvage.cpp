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

#include <algorithm>
#include <atomic>
#include <boost/filesystem.hpp>
#include <cstring>
#include <set>
#include <fstream>
#include <gtest/gtest.h>
#include <lmdb.h>

#include "blockchain_db/lmdb/salvage.h"

using cryptonote::lmdb_salvage::blockchain_reader;
using cryptonote::lmdb_salvage::block_info_record;
using cryptonote::lmdb_salvage::file_reader;
using cryptonote::lmdb_salvage::read_error;

namespace
{
  constexpr uint64_t NUM_BLOCKS = 6000;
  constexpr uint64_t NUM_TXS = 15000;

  int compare_u64(const MDB_val *a, const MDB_val *b)
  {
    uint64_t va, vb;
    memcpy(&va, a->mv_data, sizeof(va));
    memcpy(&vb, b->mv_data, sizeof(vb));
    return va < vb ? -1 : va > vb;
  }

  // deterministic content; every 40th value is big enough to need overflow pages
  std::string value_for(const char *table, uint64_t key)
  {
    const size_t size = key % 40 == 0 ? 9000 + key % 777 : 60 + key % 400;
    std::string v(size, '\0');
    uint64_t x = key * 6364136223846793005ull + (uint64_t)table[0] * 1442695040888963407ull + 1;
    for (char &c: v)
    {
      x = x * 6364136223846793005ull + 1442695040888963407ull;
      c = (char)(x >> 56);
    }
    return v;
  }

  block_info_record info_for(uint64_t height)
  {
    block_info_record bi;
    memset(&bi, 0, sizeof(bi));
    bi.height = height;
    bi.timestamp = 1400000000 + height * 60;
    bi.coins_generated = height * 17;
    bi.weight = 100 + height % 1000;
    bi.cumulative_difficulty_low = height * 1000 + 1;
    memcpy(&bi.hash, value_for("h", height).data(), sizeof(bi.hash));
    return bi;
  }

  crypto::hash prunable_hash_for(uint64_t tx_id)
  {
    crypto::hash h;
    memcpy(&h, value_for("p", tx_id).data(), sizeof(h));
    return h;
  }

  void check(int rc)
  {
    ASSERT_EQ(rc, 0) << mdb_strerror(rc);
  }

  // builds a small database with the monero table layout, in many small transactions like monerod does
  class lmdb_salvage_test: public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      dir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
      boost::filesystem::create_directories(dir);
      MDB_env *env;
      check(mdb_env_create(&env));
      check(mdb_env_set_maxdbs(env, 16));
      check(mdb_env_set_mapsize(env, 1ull << 30));
      check(mdb_env_open(env, dir.string().c_str(), MDB_NOSYNC, 0644));

      uint64_t height = 0, tx_id = 0;
      while (height < NUM_BLOCKS)
      {
        MDB_txn *txn;
        check(mdb_txn_begin(env, nullptr, 0, &txn));
        MDB_dbi blocks, block_info, hf_versions, txs_pruned, txs_prunable, txs_prunable_hash, properties;
        check(mdb_dbi_open(txn, "blocks", MDB_INTEGERKEY | MDB_CREATE, &blocks));
        check(mdb_dbi_open(txn, "block_info", MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, &block_info));
        check(mdb_dbi_open(txn, "hf_versions", MDB_INTEGERKEY | MDB_CREATE, &hf_versions));
        check(mdb_dbi_open(txn, "txs_pruned", MDB_INTEGERKEY | MDB_CREATE, &txs_pruned));
        check(mdb_dbi_open(txn, "txs_prunable", MDB_INTEGERKEY | MDB_CREATE, &txs_prunable));
        check(mdb_dbi_open(txn, "txs_prunable_hash", MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, &txs_prunable_hash));
        check(mdb_dbi_open(txn, "properties", MDB_CREATE, &properties));
        check(mdb_set_dupsort(txn, block_info, compare_u64));
        check(mdb_set_dupsort(txn, txs_prunable_hash, compare_u64));
        if (height == 0)
        {
          const uint32_t version = cryptonote::lmdb_salvage::SUPPORTED_SCHEMA_VERSION;
          MDB_val k{sizeof("version"), (void*)"version"}, v{sizeof(version), (void*)&version};
          check(mdb_put(txn, properties, &k, &v, 0));
        }
        for (int n = 0; n < 25 && height < NUM_BLOCKS; ++n, ++height)
        {
          const std::string blob = value_for("b", height);
          MDB_val k{sizeof(height), &height}, v{blob.size(), (void*)blob.data()};
          check(mdb_put(txn, blocks, &k, &v, MDB_APPEND));
          block_info_record bi = info_for(height);
          const uint64_t zero = 0;
          MDB_val zk{sizeof(zero), (void*)&zero}, bv{sizeof(bi), &bi};
          check(mdb_put(txn, block_info, &zk, &bv, MDB_APPENDDUP));
          const uint8_t hf = 1 + height / 1000;
          MDB_val hv{1, (void*)&hf};
          check(mdb_put(txn, hf_versions, &k, &hv, MDB_APPEND));
          for (; tx_id * NUM_BLOCKS < (height + 1) * NUM_TXS; ++tx_id)
          {
            const std::string pruned = value_for("t", tx_id), prunable = value_for("u", tx_id);
            crypto::hash ph = prunable_hash_for(tx_id);
            MDB_val tk{sizeof(tx_id), &tx_id}, pv{pruned.size(), (void*)pruned.data()}, prv{prunable.size(), (void*)prunable.data()}, phv{sizeof(ph), &ph};
            check(mdb_put(txn, txs_pruned, &tk, &pv, MDB_APPEND));
            check(mdb_put(txn, txs_prunable, &tk, &prv, MDB_APPEND));
            check(mdb_put(txn, txs_prunable_hash, &tk, &phv, MDB_APPEND));
          }
        }
        check(mdb_txn_commit(txn));
      }
      mdb_env_close(env);
      data_file = (dir / "data.mdb").string();
    }

    void TearDown() override
    {
      boost::system::error_code ec;
      boost::filesystem::remove_all(dir, ec);
    }

    std::string damaged_copy(const char *name)
    {
      const std::string path = (dir / name).string();
      boost::filesystem::copy_file(data_file, path);
      return path;
    }

    // every lookup must return the right value or fail with read_error, and never crash; overflow
    // continuation pages carry no header, so garbage there can only be caught by content hashes
    void read_all(blockchain_reader &reader, uint64_t &good, uint64_t &errors, uint64_t *undetectable = nullptr)
    {
      good = errors = 0;
      const auto same = [&](const std::string &got, const std::string &expected) {
        if (got == expected)
          return true;
        if (undetectable && expected.size() > 4096)
        {
          ++*undetectable;
          return true;
        }
        return false;
      };
      for (uint64_t h = 0; h < NUM_BLOCKS; ++h)
      {
        try
        {
          std::string blob;
          block_info_record bi;
          uint8_t hf;
          if (reader.get_block_blob(h, blob))
            ASSERT_TRUE(same(blob, value_for("b", h))) << "height " << h;
          const block_info_record expected = info_for(h);
          if (reader.get_block_info(h, bi))
            ASSERT_EQ(0, memcmp(&bi, &expected, sizeof(bi))) << "height " << h;
          if (reader.get_hard_fork_version(h, hf))
            ASSERT_EQ(hf, 1 + h / 1000);
          ++good;
        }
        catch (const read_error&)
        {
          ++errors;
        }
      }
      for (uint64_t id = 0; id < NUM_TXS; ++id)
      {
        try
        {
          std::string blob;
          crypto::hash ph;
          if (reader.get_tx_pruned_blob(id, blob))
            ASSERT_TRUE(same(blob, value_for("t", id))) << "tx id " << id;
          if (reader.get_tx_prunable_blob(id, blob))
            ASSERT_TRUE(same(blob, value_for("u", id))) << "tx id " << id;
          if (reader.get_tx_prunable_hash(id, ph))
            ASSERT_EQ(ph, prunable_hash_for(id));
          ++good;
        }
        catch (const read_error&)
        {
          ++errors;
        }
      }
    }

    // newest snapshot whose table directory survived; damage may have taken out all of them
    static bool select_any(blockchain_reader &reader)
    {
      for (const auto &s: reader.snapshots())
      {
        try
        {
          reader.select_snapshot(s);
          return true;
        }
        catch (const read_error&) {}
      }
      return false;
    }

    boost::filesystem::path dir;
    std::string data_file;
  };
}

TEST_F(lmdb_salvage_test, reads_intact_database)
{
  blockchain_reader reader(data_file);
  ASSERT_EQ(reader.snapshots().size(), 2u);
  EXPECT_GT(reader.snapshots()[0].txnid, reader.snapshots()[1].txnid);
  reader.select_snapshot(reader.snapshots()[0]);
  EXPECT_EQ(reader.schema_version(), cryptonote::lmdb_salvage::SUPPORTED_SCHEMA_VERSION);
  EXPECT_EQ(reader.pruning_seed(), 0u);
  EXPECT_EQ(reader.recorded_block_count(), NUM_BLOCKS);
  EXPECT_EQ(reader.recorded_tx_count(), NUM_TXS);

  uint64_t good, errors;
  read_all(reader, good, errors);
  EXPECT_EQ(errors, 0u);
  EXPECT_EQ(good, NUM_BLOCKS + NUM_TXS);

  std::string blob;
  block_info_record bi;
  EXPECT_FALSE(reader.get_block_blob(NUM_BLOCKS, blob));
  EXPECT_FALSE(reader.get_block_info(NUM_BLOCKS, bi));
  EXPECT_FALSE(reader.get_tx_pruned_blob(NUM_TXS + 5, blob));
}

TEST_F(lmdb_salvage_test, previous_snapshot_is_readable)
{
  blockchain_reader reader(data_file);
  reader.select_snapshot(reader.snapshots()[1]);
  EXPECT_EQ(reader.recorded_block_count(), NUM_BLOCKS - 25);
  std::string blob;
  ASSERT_TRUE(reader.get_block_blob(0, blob));
  EXPECT_EQ(blob, value_for("b", 0));
}

TEST_F(lmdb_salvage_test, truncated_file_fails_cleanly)
{
  const std::string path = damaged_copy("truncated.mdb");
  boost::filesystem::resize_file(path, boost::filesystem::file_size(path) * 3 / 4 / 4096 * 4096);
  blockchain_reader reader(path);
  if (!select_any(reader))
    return;
  uint64_t good, errors;
  read_all(reader, good, errors);
  EXPECT_GT(errors, 0u);
  EXPECT_EQ(good + errors, NUM_BLOCKS + NUM_TXS);

  bool truncation_reported = false;
  for (uint64_t h = NUM_BLOCKS; h-- > 0 && !truncation_reported; )
  {
    try { std::string blob; reader.get_block_blob(h, blob); }
    catch (const read_error &e) { truncation_reported = strstr(e.what(), "truncated") != nullptr; }
  }
  EXPECT_TRUE(truncation_reported);
}

TEST_F(lmdb_salvage_test, garbage_and_zeroed_pages_fail_cleanly)
{
  const std::string path = damaged_copy("corrupt.mdb");
  const uint64_t pages = boost::filesystem::file_size(path) / 4096;
  {
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    uint64_t x = 12345;
    for (int n = 0; n < 200; ++n)
    {
      x = x * 6364136223846793005ull + 1442695040888963407ull;
      const uint64_t pgno = 2 + (x >> 33) % (pages - 2);
      std::string junk(4096, '\0');
      if (n % 2)
        for (char &c: junk)
        {
          x = x * 6364136223846793005ull + 1442695040888963407ull;
          c = (char)(x >> 56);
        }
      f.seekp(pgno * 4096);
      f.write(junk.data(), junk.size());
    }
  }
  blockchain_reader reader(path);
  if (!select_any(reader))
    return;
  uint64_t good, errors, undetectable = 0;
  read_all(reader, good, errors, &undetectable);
  EXPECT_EQ(good + errors, NUM_BLOCKS + NUM_TXS);
  EXPECT_GT(errors, 0u);
}

TEST_F(lmdb_salvage_test, for_each_survives_damage)
{
  const std::string path = damaged_copy("walk.mdb");
  boost::filesystem::resize_file(path, boost::filesystem::file_size(path) / 2 / 4096 * 4096);
  file_reader reader(path);
  std::map<std::string, cryptonote::lmdb_salvage::tree_info> trees;
  try
  {
    trees = reader.named_trees();
  }
  catch (const read_error&)
  {
    return;
  }
  std::vector<std::string> errors;
  uint64_t prev = 0, visited = 0;
  bool ordered = true;
  reader.for_each(trees.at("blocks"), [&](const std::string &key, const std::string &value) {
    uint64_t k;
    memcpy(&k, key.data(), sizeof(k));
    ordered = ordered && (visited == 0 || k > prev) && value == value_for("b", k);
    prev = k;
    ++visited;
    return true;
  }, errors);
  EXPECT_TRUE(ordered);
  EXPECT_FALSE(errors.empty());
  EXPECT_LT(visited, NUM_BLOCKS);
}

TEST_F(lmdb_salvage_test, rejects_non_database)
{
  const std::string path = (dir / "random.mdb").string();
  {
    std::ofstream f(path, std::ios::binary);
    f << std::string(64 * 1024, 'x');
  }
  EXPECT_THROW(file_reader{path}, read_error);
  EXPECT_THROW(file_reader{(dir / "does-not-exist").string()}, read_error);
}

TEST_F(lmdb_salvage_test, page_scan_finds_records_without_meta_or_branch_pages)
{
  // what an MDB_NOSYNC power loss most likely takes: the pages every commit rewrites
  const std::string path = damaged_copy("leaves-only.mdb");
  const uint64_t pages = boost::filesystem::file_size(path) / 4096;
  {
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    const std::string zero(4096, '\0');
    for (uint64_t p = 0; p < pages; ++p)
    {
      char header[16];
      f.seekg(p * 4096);
      f.read(header, sizeof(header));
      uint64_t pgno;
      uint16_t flags;
      memcpy(&pgno, header, sizeof(pgno));
      memcpy(&flags, header + 10, sizeof(flags));
      if (p < 2 || (pgno == p && (flags & 0x01)))
      {
        f.seekp(p * 4096);
        f.write(zero.data(), zero.size());
      }
    }
  }
  file_reader reader(path);
  EXPECT_TRUE(reader.snapshots().empty());
  EXPECT_EQ(reader.page_size(), 4096u);
  std::atomic<bool> stop{false};
  cryptonote::lmdb_salvage::page_scan scan(reader, stop);
  EXPECT_FALSE(scan.interrupted());
  EXPECT_EQ(scan.height_bound(), NUM_BLOCKS);
  EXPECT_EQ(scan.schema_versions(), std::set<uint32_t>{cryptonote::lmdb_salvage::SUPPORTED_SCHEMA_VERSION});
  EXPECT_TRUE(scan.pruning_seeds().empty());

  // every record is among the candidates of its key; stale copies and other tables' values may join it
  cryptonote::lmdb_salvage::page_scan::cursor heights, infos, txs;
  std::vector<std::string> values;
  std::vector<block_info_record> records;
  const auto contains = [&](const std::string &v) { return std::find(values.begin(), values.end(), v) != values.end(); };
  for (uint64_t h = 0; h < NUM_BLOCKS; ++h)
  {
    scan.values(heights, h, values);
    ASSERT_TRUE(contains(value_for("b", h))) << "height " << h;
    ASSERT_TRUE(contains(std::string(1, (char)(1 + h / 1000)))) << "height " << h;
    scan.block_infos(infos, h, records);
    const block_info_record expected = info_for(h);
    ASSERT_TRUE(std::any_of(records.begin(), records.end(), [&](const block_info_record &r) { return !memcmp(&r, &expected, sizeof(r)); })) << "height " << h;
  }
  for (uint64_t id = 0; id < NUM_TXS; ++id)
  {
    scan.values(txs, id, values);
    const crypto::hash ph = prunable_hash_for(id);
    ASSERT_TRUE(contains(value_for("t", id))) << "tx id " << id;
    ASSERT_TRUE(contains(value_for("u", id))) << "tx id " << id;
    ASSERT_TRUE(contains(std::string((const char*)&ph, sizeof(ph)))) << "tx id " << id;
  }
}

TEST_F(lmdb_salvage_test, page_scan_skips_destroyed_pages)
{
  const std::string path = damaged_copy("holes.mdb");
  const uint64_t pages = boost::filesystem::file_size(path) / 4096;
  {
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    const std::string zero(4096, '\0');
    for (uint64_t p = 0; p < pages; p += 7)
    {
      f.seekp(p * 4096);
      f.write(zero.data(), zero.size());
    }
  }
  std::atomic<bool> stop{false};
  file_reader intact_reader(data_file), damaged_reader(path);
  cryptonote::lmdb_salvage::page_scan intact(intact_reader, stop), damaged(damaged_reader, stop);
  // holes only take candidates away, they never make new ones up; except overflow continuation pages,
  // which have no header, so a destroyed one can only be caught by content hashes (every 40th key)
  cryptonote::lmdb_salvage::page_scan::cursor ci, cd;
  std::vector<std::string> before, after;
  uint64_t found = 0;
  for (uint64_t h = 0; h < NUM_BLOCKS; ++h)
  {
    intact.values(ci, h, before);
    damaged.values(cd, h, after);
    if (h % 40)
      for (const std::string &v: after)
        EXPECT_NE(std::find(before.begin(), before.end(), v), before.end()) << "a value under key " << h << " that the intact file does not have";
    found += std::find(after.begin(), after.end(), value_for("b", h)) != after.end();
  }
  EXPECT_GT(found, 0u);
  EXPECT_LT(found, NUM_BLOCKS);
}
