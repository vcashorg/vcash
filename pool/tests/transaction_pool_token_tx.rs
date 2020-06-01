// Copyright 2019 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod common;

use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::{transaction, Block, BlockHeader, TokenKey, Transaction, Weighting};
use self::core::global;
use self::core::libtx;
use self::core::pow::Difficulty;
use self::keychain::{ExtKeychain, Keychain};
use self::pool::TxSource;
use self::util::RwLock;
use crate::common::*;
use grin_core as core;
use grin_keychain as keychain;
use grin_pool as pool;
use grin_util as util;
use std::sync::Arc;

#[test]
fn test_transaction_pool_token_tx() {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = ".test_transaction_pool_token_tx".to_string();
	clean_output_dir(db_root.clone());

	{
		let mut chain = ChainAdapter::init(db_root.clone()).unwrap();

		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

		// Initialize the chain/txhashset with an initial block
		// so we have a non-empty UTXO set.
		let add_block =
			|prev_header: BlockHeader, txs: Vec<Transaction>, chain: &mut ChainAdapter| {
				let height = prev_header.height + 1;
				let key_id = ExtKeychain::derive_key_id(1, height as u32, 0, 0, 0);
				let fee = txs.iter().map(|x| x.fee()).sum();
				let reward = libtx::reward::output(
					&keychain,
					&libtx::ProofBuilder::new(&keychain),
					&key_id,
					height,
					fee,
					false,
				)
				.unwrap();
				let mut block = Block::new(&prev_header, txs, Difficulty::min(), reward).unwrap();

				// Set the prev_root to the prev hash for testing purposes (no MMR to obtain a root from).
				block.header.prev_root = prev_header.hash();

				chain.update_db_for_block(&block);
				block
			};

		let mut start_header = BlockHeader::default();
		//support token
		start_header.height = 60000;
		let block = add_block(start_header, vec![], &mut chain);
		let header = block.header;

		// Now create tx to spend that first coinbase (now matured).
		// Provides us with some useful outputs to test with.
		let initial_tx = test_transaction_spending_coinbase(&keychain, &header, vec![500]);

		// Mine that initial tx so we can spend it with multiple txs
		let block = add_block(header, vec![initial_tx], &mut chain);
		let header = block.header;

		// Initialize a new pool with our chain adapter.
		let pool = RwLock::new(test_setup(Arc::new(chain.clone()), verifier_cache.clone()));

		// start test issue token test
		let token_type = TokenKey::new_token_key();
		let issue_token_tx =
			test_issue_token_transaction(&keychain, 500, 499, token_type.clone(), 3500);
		let invalid_issue_token_tx =
			test_issue_token_transaction(&keychain, 499, 498, token_type.clone(), 10001);
		{
			let mut write_pool = pool.write();

			write_pool
				.add_to_pool(test_source(), issue_token_tx, false, &header)
				.unwrap();

			assert!(write_pool
				.add_to_pool(test_source(), invalid_issue_token_tx, false, &header)
				.is_err());

			assert_eq!(write_pool.total_size(), 1);
		}

		let txs = pool.read().prepare_mineable_transactions().unwrap();

		let block = add_block(header, txs, &mut chain);

		// Check the block contains what we expect.
		assert_eq!(block.inputs().len(), 1);
		assert_eq!(block.outputs().len(), 2);
		assert_eq!(block.kernels().len(), 2);
		assert_eq!(block.token_inputs().len(), 0);
		assert_eq!(block.token_outputs().len(), 1);
		assert_eq!(block.token_kernels().len(), 1);

		// Now reconcile the transaction pool with the new block
		// and check the resulting contents of the pool are what we expect.
		{
			let mut write_pool = pool.write();
			write_pool.reconcile_block(&block).unwrap();

			assert_eq!(write_pool.total_size(), 0);
		}

		let header = block.header;
		// start test send token tx test
		let initial_token_tx = test_token_transaction(
			&keychain,
			499,
			498,
			token_type.clone(),
			vec![3500],
			vec![500, 600, 700, 800, 900],
		);

		// Add this tx to the pool (stem=false, direct to txpool).
		{
			let mut write_pool = pool.write();

			write_pool
				.add_to_pool(test_source(), initial_token_tx, false, &header)
				.unwrap();

			assert_eq!(write_pool.total_size(), 1);
		}

		let token_tx1 = test_token_transaction(
			&keychain,
			498,
			497,
			token_type.clone(),
			vec![500, 600],
			vec![499, 601],
		);
		let token_tx2 = test_token_transaction(
			&keychain,
			497,
			496,
			token_type.clone(),
			vec![499, 700],
			vec![498, 701],
		);

		// Take a write lock and add a couple of tx entries to the pool.
		{
			let mut write_pool = pool.write();

			// Check we have a single initial tx in the pool.
			assert_eq!(write_pool.total_size(), 1);

			write_pool
				.add_to_pool(test_source(), token_tx1.clone(), false, &header)
				.unwrap();

			write_pool
				.add_to_pool(test_source(), token_tx2.clone(), false, &header)
				.unwrap();

			assert_eq!(write_pool.total_size(), 3);
		}

		// Test adding the exact same tx multiple times (same kernel signature).
		// This will fail for stem=false during tx aggregation due to duplicate
		// outputs and duplicate kernels.
		{
			let mut write_pool = pool.write();
			assert!(write_pool
				.add_to_pool(test_source(), token_tx1.clone(), false, &header)
				.is_err());
		}

		// Test token kernel sum mismatch
		{
			let tx = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![500, 600],
				vec![1010],
			);
			let mut write_pool = pool.write();
			assert!(write_pool
				.add_to_pool(test_source(), tx, false, &header)
				.is_err());
		}

		// Test adding a duplicate tx with the same input and outputs.
		// Note: not the *same* tx, just same underlying inputs/outputs.
		{
			let tx1a = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![500, 600],
				vec![499, 601],
			);
			let mut write_pool = pool.write();
			assert!(write_pool
				.add_to_pool(test_source(), tx1a, false, &header)
				.is_err());
		}

		// Test adding a tx attempting to spend a non-existent output.
		{
			let bad_tx = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![10000],
				vec![4000, 6000],
			);
			let mut write_pool = pool.write();
			assert!(write_pool
				.add_to_pool(test_source(), bad_tx, false, &header)
				.is_err());
		}

		// Test adding a tx that would result in a duplicate output (conflicts with
		// output from token_tx2). For reasons of security all outputs in the UTXO set must
		// be unique. Otherwise spending one will almost certainly cause the other
		// to be immediately stolen via a "replay" tx.
		{
			let tx = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![900],
				vec![498, 402],
			);
			let mut write_pool = pool.write();
			assert!(write_pool
				.add_to_pool(test_source(), tx, false, &header)
				.is_err());
		}

		// Confirm the tx pool correctly identifies an invalid tx (already spent).
		{
			let mut write_pool = pool.write();
			let tx3 = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![500],
				vec![497, 3],
			);
			assert!(write_pool
				.add_to_pool(test_source(), tx3, false, &header)
				.is_err());
			assert_eq!(write_pool.total_size(), 3);
		}

		// Now add a couple of txs to the stempool (stem = true).
		{
			let mut write_pool = pool.write();
			let tx = test_token_transaction(
				&keychain,
				496,
				495,
				token_type.clone(),
				vec![601],
				vec![301, 300],
			);
			write_pool
				.add_to_pool(test_source(), tx, true, &header)
				.unwrap();
			let tx2 = test_token_transaction(
				&keychain,
				495,
				494,
				token_type.clone(),
				vec![301],
				vec![151, 150],
			);
			write_pool
				.add_to_pool(test_source(), tx2, true, &header)
				.unwrap();
			assert_eq!(write_pool.total_size(), 3);
			assert_eq!(write_pool.stempool.size(), 2);
		}

		// Check we can take some entries from the stempool and "fluff" them into the
		// txpool. This also exercises multi-kernel txs.
		{
			let mut write_pool = pool.write();
			let agg_tx = write_pool
				.stempool
				.all_transactions_aggregate()
				.unwrap()
				.unwrap();
			assert_eq!(agg_tx.kernels().len(), 2);
			write_pool
				.add_to_pool(test_source(), agg_tx, false, &header)
				.unwrap();
			assert_eq!(write_pool.total_size(), 4);
			assert!(write_pool.stempool.is_empty());
		}

		// Adding a duplicate tx to the stempool will result in it being fluffed.
		// This handles the case of the stem path having a cycle in it.
		{
			let mut write_pool = pool.write();
			let tx = test_token_transaction(
				&keychain,
				494,
				493,
				token_type.clone(),
				vec![151],
				vec![76, 75],
			);
			write_pool
				.add_to_pool(test_source(), tx.clone(), true, &header)
				.unwrap();
			assert_eq!(write_pool.total_size(), 4);
			assert_eq!(write_pool.stempool.size(), 1);

			// Duplicate stem tx so fluff, adding it to txpool and removing it from stempool.
			write_pool
				.add_to_pool(test_source(), tx.clone(), true, &header)
				.unwrap();
			assert_eq!(write_pool.total_size(), 5);
			assert!(write_pool.stempool.is_empty());
		}

		// Now check we can correctly deaggregate a multi-kernel tx based on current
		// contents of the txpool.
		// We will do this be adding a new tx to the pool
		// that is a superset of a tx already in the pool.
		{
			let mut write_pool = pool.write();

			let token_tx4 = test_token_transaction(
				&keychain,
				493,
				492,
				token_type.clone(),
				vec![800],
				vec![431, 369],
			);
			// tx1 and tx2 are already in the txpool (in aggregated form)
			// tx4 is the "new" part of this aggregated tx that we care about
			let agg_tx =
				transaction::aggregate(vec![token_tx1.clone(), token_tx2.clone(), token_tx4])
					.unwrap();

			agg_tx
				.validate(Weighting::AsTransaction, verifier_cache.clone())
				.unwrap();

			write_pool
				.add_to_pool(test_source(), agg_tx, false, &header)
				.unwrap();
			assert_eq!(write_pool.total_size(), 6);
			let entry = write_pool.txpool.entries.last().unwrap();
			assert_eq!(entry.tx.kernels().len(), 1);
			assert_eq!(entry.src, TxSource::Deaggregate);
		}
	}
	// Cleanup db directory
	clean_output_dir(db_root.clone());
}
