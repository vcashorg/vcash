// Copyright 2021 The Grin Developers
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

//! Utility functions to build Grin transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Each building function is a combinator that produces a function taking
//! a transaction a sum of blinding factors, to return another transaction
//! and sum. Combinators can then be chained and executed using the
//! _transaction_ function.
//!
//! Example:
//! build::transaction(
//!   KernelFeatures::Plain{ fee: 2.try_into().unwrap() },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ]
//! )

use crate::core::{Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use crate::libtx::proof::{self, ProofBuild};
use crate::libtx::{aggsig, Error};
use keychain::{BlindSum, BlindingFactor, Identifier, Keychain, SwitchCommitmentType};

use crate::core::{TokenInput, TokenKernelFeatures, TokenKey, TokenOutput, TokenTxKernel};

/// Context information available to transaction combinators.
pub struct Context<'a, K, B>
where
	K: Keychain,
	B: ProofBuild,
{
	/// The keychain used for key derivation
	pub keychain: &'a K,
	/// The bulletproof builder
	pub builder: &'a B,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) tuple into another, given the provided context.
/// Will return an Err if seomthing went wrong at any point during transaction building.
pub type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(Transaction, BlindSum, BlindSum), Error>,
) -> Result<(Transaction, BlindSum, BlindSum), Error>;

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
fn build_input<K, B>(value: u64, features: OutputFeatures, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			if let Ok((tx, sum, token_sum)) = acc {
				let commit =
					build
						.keychain
						.commit(value, &key_id, SwitchCommitmentType::Regular)?;
				// TODO: proper support for different switch commitment schemes
				let input = Input::new(features, commit);
				Ok((
					tx.with_input(input),
					sum.sub_key_id(key_id.to_value_path(value)),
					token_sum,
				))
			} else {
				acc
			}
		},
	)
}

/// Adds an token input with the provided value and blinding key to the transaction
/// being built.
pub fn build_token_input<K, B>(
	value: u64,
	token_type: TokenKey,
	is_issue_token: bool,
	key_id: Identifier,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			if let Ok((tx, sum, token_sum)) = acc {
				let commit =
					build
						.keychain
						.commit(value, &key_id, SwitchCommitmentType::Regular)?;
				let features = if is_issue_token {
					OutputFeatures::TokenIssue
				} else {
					OutputFeatures::Token
				};
				let input = TokenInput::new(features, token_type, commit);
				Ok((
					tx.with_token_input(input),
					sum,
					token_sum.sub_key_id(key_id.to_value_path(value)),
				))
			} else {
				acc
			}
		},
	)
}

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
pub fn input<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!(
		"Building input (spending regular output): {}, {}",
		value, key_id
	);
	build_input(value, OutputFeatures::Plain, key_id)
}

/// Adds an token input with the provided value and blinding key to the transaction
/// being built.
pub fn token_input<K, B>(
	value: u64,
	token_type: TokenKey,
	is_issue_token: bool,
	key_id: Identifier,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!(
		"Building token input (spending regular output): {}, {}, {}",
		value, token_type, key_id
	);
	build_token_input(value, token_type, is_issue_token, key_id)
}

/// Adds a coinbase input spending a coinbase output.
pub fn coinbase_input<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!("Building input (spending coinbase): {}, {}", value, key_id);
	build_input(value, OutputFeatures::Coinbase, key_id)
}

/// Adds an output with the provided value and key identifier from the
/// keychain.
pub fn output<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			let (tx, sum, token_sum) = acc?;

			// TODO: proper support for different switch commitment schemes
			let switch = SwitchCommitmentType::Regular;

			let commit = build.keychain.commit(value, &key_id, switch)?;

			debug!("Building output: {}, {:?}", value, commit);

			let proof = proof::create(
				build.keychain,
				build.builder,
				value,
				&key_id,
				switch,
				commit,
				None,
			)?;

			Ok((
				tx.with_output(Output::new(OutputFeatures::Plain, commit, proof)),
				sum.add_key_id(key_id.to_value_path(value)),
				token_sum,
			))
		},
	)
}

/// Adds an output with the provided value and key identifier from the
/// keychain.
pub fn token_output<K, B>(
	value: u64,
	token_type: TokenKey,
	is_token_issue: bool,
	key_id: Identifier,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			let (tx, sum, token_sum) = acc?;

			// TODO: proper support for different switch commitment schemes
			let switch = SwitchCommitmentType::Regular;

			let commit = build.keychain.commit(value, &key_id, switch)?;

			debug!(
				"Building token output: {}, {}, {:?}",
				token_type.clone(),
				value,
				commit
			);

			let proof = proof::create(
				build.keychain,
				build.builder,
				value,
				&key_id,
				switch,
				commit.clone(),
				None,
			)?;

			let features = match is_token_issue {
				true => OutputFeatures::TokenIssue,
				false => OutputFeatures::Token,
			};

			Ok((
				tx.with_token_output(TokenOutput::new(features, token_type, commit, proof)),
				sum,
				token_sum.add_key_id(key_id.to_value_path(value)),
			))
		},
	)
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			acc.map(|(tx, sum, token_sum)| (tx, sum.add_blinding_factor(excess.clone()), token_sum))
		},
	)
}

/// Sets an initial transaction to add to when building a new transaction.
pub fn initial_tx<K, B>(tx: Transaction) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			acc.map(|(_, sum, token_sum)| (tx.clone(), sum, token_sum))
		},
	)
}

/// Takes an existing transaction and partially builds on it.
///
/// Example:
/// let (tx, sum) = build::transaction(tx, vec![input_rand(4), output_rand(1))], keychain)?;
///
pub fn partial_transaction<K, B>(
	tx: Transaction,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<(Transaction, BlindingFactor, BlindingFactor), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum, token_sum) = elems
		.iter()
		.fold(Ok((tx, BlindSum::new(), BlindSum::new())), |acc, elem| {
			elem(&mut ctx, acc)
		})?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;
	let token_blind_sum = ctx.keychain.blind_sum(&token_sum)?;
	Ok((tx, blind_sum, token_blind_sum))
}

/// Builds a complete transaction.
/// NOTE: We only use this in tests (for convenience).
/// In the real world we use signature aggregation across multiple participants.
pub fn transaction<K, B>(
	features: KernelFeatures,
	token_featrues: Option<TokenKernelFeatures>,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut kernel = TxKernel::with_features(features);

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign()?;

	// Generate kernel public excess and associated signature.
	let excess = BlindingFactor::rand(&keychain.secp());
	let skey = excess.secret_key(&keychain.secp())?;
	kernel.excess = keychain.secp().commit(0, skey)?;
	let pubkey = &kernel.excess.to_pubkey(&keychain.secp())?;
	kernel.excess_sig = aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey))?;
	kernel.verify()?;
	transaction_with_kernel(elems, kernel, token_featrues, excess, keychain, builder)
}

/// Build a complete transaction with the provided kernel and corresponding private excess.
/// NOTE: Only used in tests (for convenience).
/// Cannot recommend passing private excess around like this in the real world.
pub fn transaction_with_kernel<K, B>(
	elems: &[Box<Append<K, B>>],
	kernel: TxKernel,
	token_featrues: Option<TokenKernelFeatures>,
	excess: BlindingFactor,
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum, token_sum) = elems.iter().fold(
		Ok((Transaction::empty(), BlindSum::new(), BlindSum::new())),
		|acc, elem| elem(&mut ctx, acc),
	)?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;

	// Update tx with new kernel and offset.
	let mut tx = tx.replace_kernel(kernel);
	tx.offset = blind_sum.split(&excess, &keychain.secp())?;

	if token_featrues.is_some() {
		let mut token_kern = TokenTxKernel::with_features(token_featrues.unwrap());
		token_kern.token_type = tx.token_outputs()[0].token_type();
		let token_blind_sum = ctx.keychain.blind_sum(&token_sum)?;
		let token_msg = token_kern.msg_to_sign()?;
		let token_key = token_blind_sum.secret_key(&keychain.secp())?;
		token_kern.excess = ctx.keychain.secp().commit(0, token_key)?;
		let pubkey = &token_kern.excess.to_pubkey(&keychain.secp())?;
		token_kern.excess_sig = aggsig::sign_with_blinding(
			&keychain.secp(),
			&token_msg,
			&token_blind_sum,
			Some(&pubkey),
		)
		.unwrap();

		let tx = tx.replace_token_kernel(token_kern);

		return Ok(tx);
	}

	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use super::*;
	use crate::core::transaction::Weighting;
	use crate::global;
	use crate::libtx::ProofBuilder;
	use keychain::{ExtKeychain, ExtKeychainPath};

	#[test]
	fn blind_simple_tx() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			None,
			&[input(10, key_id1), input(12, key_id2), output(20, key_id3)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		tx.validate(Weighting::AsTransaction, height).unwrap();
	}

	#[test]
	fn blind_simple_tx_with_offset() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			None,
			&[input(10, key_id1), input(12, key_id2), output(20, key_id3)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		tx.validate(Weighting::AsTransaction, height).unwrap();
	}

	#[test]
	fn blind_simpler_tx() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

		let tx = transaction(
			KernelFeatures::Plain { fee: 4.into() },
			None,
			&[input(6, key_id1), output(2, key_id2)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		tx.validate(Weighting::AsTransaction, height).unwrap();
	}
}
