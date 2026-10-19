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
#include <functional>
#include <boost/filesystem/path.hpp>

#include "cryptonote_config.h"
#include "span.h"

namespace cryptonote
{
  //! the compiled-in fast sync block hashes of a network (same type as GetCheckpointsCallback)
  typedef std::function<const epee::span<const unsigned char>(network_type)> block_hashes_callback;

  /**
   * @brief rebuild a crash-damaged blockchain database
   *
   * Reads <data_dir>/lmdb without mmap and without ever writing to it, then
   * walks the chain from genesis. A block is accepted only if it links to its
   * parent, its stored metadata matches what consensus rules derive from it,
   * and every one of its transactions (read by sequential id) hashes to the
   * value the block commits to. Accepted blocks are replayed into a new
   * database through the regular BlockchainDB write path, which regenerates
   * every derived index; the first block that fails ends the replay.
   *
   * The network is identified from the genesis block, and the pruning seed,
   * hard fork history, txpool and alternative blocks are carried over. The
   * weight of a block with pruned transactions that cannot be recomputed is
   * checked against the compiled-in hashes of its 512-block chunk.
   *
   * Nothing is created unless the volume has room for a second copy of the
   * database. On success the damaged database is kept as
   * <data_dir>/lmdb.damaged-<time> and the new one takes its place.
   *
   * @param data_dir the directory holding the lmdb folder
   * @param stop polled between blocks; set it to abort, leaving the old database in place
   * @param get_block_hashes the compiled-in block hashes and weights (blocks::GetCheckpointsData), may be empty
   *
   * @return true if a new database was installed
   */
  bool reconstruct_blockchain_db(const boost::filesystem::path &data_dir, const std::atomic<bool> &stop, const block_hashes_callback &get_block_hashes);
}
