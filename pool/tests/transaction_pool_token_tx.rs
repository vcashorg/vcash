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
use self::core::core::{transaction, TokenKey, Weighting};
use self::core::global;
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
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.trasaction_pool_token_tx";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(db_root, genesis));
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		verifier_cache.clone(),
	);

	add_some_blocks(&chain, 3, &keychain);

	let header_1 = chain.get_header_by_height(1).unwrap();

	// Now create tx to spend an early coinbase (now matured).
	// Provides us with some useful outputs to test with.
	let initial_tx = test_transaction_spending_coinbase(&keychain, &header_1, vec![500]);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&chain, &[initial_tx], &keychain);

	let header = chain.head_header().unwrap();

	// start test issue token test
	let token_type = TokenKey::new_token_key();
	let issue_token_tx =
		test_issue_token_transaction(&keychain, 500, 499, token_type.clone(), 3500);
	let invalid_issue_token_tx =
		test_issue_token_transaction(&keychain, 499, 498, token_type.clone(), 10001);

	pool.add_to_pool(test_source(), issue_token_tx.clone(), false, &header)
		.unwrap();
	assert!(pool
		.add_to_pool(test_source(), invalid_issue_token_tx, false, &header)
		.is_err());
	assert_eq!(pool.total_size(), 1);

	let txs = pool.prepare_mineable_transactions().unwrap();

	add_block(&chain, &txs, &keychain);

	// Get full block from head of the chain (block we just processed).
	let block = chain.get_block(&chain.head().unwrap().hash()).unwrap();

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
		pool.reconcile_block(&block).unwrap();
		assert_eq!(pool.total_size(), 0);
	}

	let header = block.header;
	// start test send token tx test
	let initial_token_tx = test_token_transaction(
		&keychain,
		499,
		498,
		token_type.clone(),
		vec![(true, 3500)],
		vec![500, 600, 700, 800, 900],
	);

	// Add this tx to the pool (stem=false, direct to txpool).
	{
		pool.add_to_pool(test_source(), initial_token_tx.clone(), false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 1);
	}

	let token_tx1 = test_token_transaction(
		&keychain,
		498,
		497,
		token_type.clone(),
		vec![(false, 500), (false, 600)],
		vec![499, 601],
	);
	let token_tx2 = test_token_transaction(
		&keychain,
		497,
		496,
		token_type.clone(),
		vec![(false, 499), (false, 700)],
		vec![498, 701],
	);

	// Take a write lock and add a couple of tx entries to the pool.
	{
		assert_eq!(pool.total_size(), 1);

		pool.add_to_pool(test_source(), token_tx1.clone(), false, &header)
			.unwrap();
		pool.add_to_pool(test_source(), token_tx2.clone(), false, &header)
			.unwrap();

		assert_eq!(pool.total_size(), 3);
	}

	// Test adding the exact same tx multiple times (same kernel signature).
	// This will fail for stem=false during tx aggregation due to duplicate
	// outputs and duplicate kernels.
	{
		assert!(pool
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
			vec![(false, 500), (false, 600)],
			vec![1010],
		);
		assert!(pool.add_to_pool(test_source(), tx, false, &header).is_err());
	}

	// Test adding a duplicate tx with the same input and outputs.
	// Note: not the *same* tx, just same underlying inputs/outputs.
	{
		let tx1a = test_token_transaction(
			&keychain,
			496,
			495,
			token_type.clone(),
			vec![(false, 500), (false, 600)],
			vec![499, 601],
		);
		assert!(pool
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
			vec![(false, 10000)],
			vec![4000, 6000],
		);
		assert!(pool
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
			vec![(false, 900)],
			vec![498, 402],
		);
		assert!(pool.add_to_pool(test_source(), tx, false, &header).is_err());
	}

	// Confirm the tx pool correctly identifies an invalid tx (already spent).
	{
		let tx3 = test_token_transaction(
			&keychain,
			496,
			495,
			token_type.clone(),
			vec![(false, 500)],
			vec![497, 3],
		);
		assert!(pool
			.add_to_pool(test_source(), tx3, false, &header)
			.is_err());
		assert_eq!(pool.total_size(), 3);
	}

	// Now add a couple of txs to the stempool (stem = true).
	{
		let tx = test_token_transaction(
			&keychain,
			496,
			495,
			token_type.clone(),
			vec![(false, 601)],
			vec![301, 300],
		);
		pool.add_to_pool(test_source(), tx, true, &header).unwrap();
		let tx2 = test_token_transaction(
			&keychain,
			495,
			494,
			token_type.clone(),
			vec![(false, 301)],
			vec![151, 150],
		);
		pool.add_to_pool(test_source(), tx2, true, &header).unwrap();

		assert_eq!(pool.total_size(), 3);
		assert_eq!(pool.stempool.size(), 2);
	}

	// Check we can take some entries from the stempool and "fluff" them into the
	// txpool. This also exercises multi-kernel txs.
	{
		let agg_tx = pool
			.stempool
			.all_transactions_aggregate(None)
			.unwrap()
			.unwrap();
		assert_eq!(agg_tx.kernels().len(), 2);
		pool.add_to_pool(test_source(), agg_tx, false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 4);
		assert!(pool.stempool.is_empty());
	}

	// Adding a duplicate tx to the stempool will result in it being fluffed.
	// This handles the case of the stem path having a cycle in it.
	{
		let tx = test_token_transaction(
			&keychain,
			494,
			493,
			token_type.clone(),
			vec![(false, 151)],
			vec![76, 75],
		);
		pool.add_to_pool(test_source(), tx.clone(), true, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 4);
		assert_eq!(pool.stempool.size(), 1);

		// Duplicate stem tx so fluff, adding it to txpool and removing it from stempool.
		pool.add_to_pool(test_source(), tx.clone(), true, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 5);
		assert!(pool.stempool.is_empty());
	}

	// Now check we can correctly deaggregate a multi-kernel tx based on current
	// contents of the txpool.
	// We will do this be adding a new tx to the pool
	// that is a superset of a tx already in the pool.
	{
		let token_tx4 = test_token_transaction(
			&keychain,
			493,
			492,
			token_type.clone(),
			vec![(false, 800)],
			vec![431, 369],
		);
		// tx1 and tx2 are already in the txpool (in aggregated form)
		// tx4 is the "new" part of this aggregated tx that we care about
		let agg_tx =
			transaction::aggregate(&[token_tx1.clone(), token_tx2.clone(), token_tx4]).unwrap();

		agg_tx
			.validate(Weighting::AsTransaction, verifier_cache.clone())
			.unwrap();

		pool.add_to_pool(test_source(), agg_tx, false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 6);
		let entry = pool.txpool.entries.last().unwrap();
		assert_eq!(entry.tx.kernels().len(), 1);
		assert_eq!(entry.src, TxSource::Deaggregate);
	}

	// Cleanup db directory
	clean_output_dir(db_root.into());
}
