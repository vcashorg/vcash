// Copyright 2020 The Grin Developers
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

//! Lightweight readonly view into output MMR for convenience.

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr::{self, ReadonlyPMMR};
use crate::core::core::{
	Block, BlockHeader, Input, Output, TokenInput, TokenIssueProof, TokenOutput, Transaction,
};
use crate::core::global;
use crate::core::ser::PMMRIndexHashable;
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::util::secp::pedersen::RangeProof;
use grin_store::pmmr::PMMRBackend;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	output_pmmr: ReadonlyPMMR<'a, Output, PMMRBackend<Output>>,
	token_output_pmmr: ReadonlyPMMR<'a, TokenOutput, PMMRBackend<TokenOutput>>,
	issue_token_pmmr: ReadonlyPMMR<'a, TokenIssueProof, PMMRBackend<TokenIssueProof>>,
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	token_rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		output_pmmr: ReadonlyPMMR<'a, Output, PMMRBackend<Output>>,
		token_output_pmmr: ReadonlyPMMR<'a, TokenOutput, PMMRBackend<TokenOutput>>,
		issue_token_pmmr: ReadonlyPMMR<'a, TokenIssueProof, PMMRBackend<TokenIssueProof>>,
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
		token_rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	) -> UTXOView<'a> {
		UTXOView {
			output_pmmr,
			token_output_pmmr,
			issue_token_pmmr,
			header_pmmr,
			rproof_pmmr,
			token_rproof_pmmr,
		}
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(&self, block: &Block, batch: &Batch<'_>) -> Result<(), Error> {
		for output in block.outputs() {
			self.validate_output(output, batch)?;
		}

		for input in block.inputs() {
			self.validate_input(input, batch)?;
		}

		for output in block.token_outputs() {
			self.validate_token_output(output, batch)?;
		}

		for input in block.token_inputs() {
			self.validate_token_input(input, batch)?;
		}

		Ok(())
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(&self, tx: &Transaction, batch: &Batch<'_>) -> Result<(), Error> {
		for output in tx.outputs() {
			self.validate_output(output, batch)?;
		}

		for input in tx.inputs() {
			self.validate_input(input, batch)?;
		}

		for output in tx.token_outputs() {
			self.validate_token_output(output, batch)?;
		}

		for input in tx.token_inputs() {
			self.validate_token_input(input, batch)?;
		}

		Ok(())
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Compare the hash in the output MMR at the expected pos.
	fn validate_input(&self, input: &Input, batch: &Batch<'_>) -> Result<(), Error> {
		if let Ok(pos) = batch.get_output_pos(&input.commitment()) {
			if let Some(hash) = self.output_pmmr.get_hash(pos) {
				if hash == input.hash_with_index(pos - 1) {
					return Ok(());
				}
			}
		}
		Err(ErrorKind::AlreadySpent(input.commitment()).into())
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &Output, batch: &Batch<'_>) -> Result<(), Error> {
		if let Ok(pos) = batch.get_output_pos(&output.commitment()) {
			if let Some(out_mmr) = self.output_pmmr.get_data(pos) {
				if out_mmr.commitment() == output.commitment() {
					return Err(ErrorKind::DuplicateCommitment(output.commitment()).into());
				}
			}
		}
		Ok(())
	}

	// TokenInput is valid if it is spending an (unspent) output
	// that currently exists in the token_output MMR.
	// Compare the hash in the token_output MMR at the expected pos.
	fn validate_token_input(
		&self,
		token_input: &TokenInput,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		if let Ok((pos, _)) = batch.get_token_output_pos_height(&token_input.commitment()) {
			if let Some(hash) = self.token_output_pmmr.get_hash(pos) {
				if hash == token_input.hash_with_index(pos - 1) {
					return Ok(());
				}
			}
		}
		Err(ErrorKind::AlreadySpent(token_input.commitment()).into())
	}

	// Token_Output is valid if it would not result in a duplicate commitment in the token_output MMR.
	fn validate_token_output(
		&self,
		token_output: &TokenOutput,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		if let Ok((pos, _)) = batch.get_token_output_pos_height(&token_output.commitment()) {
			if let Some(out_mmr) = self.token_output_pmmr.get_data(pos) {
				if out_mmr.commitment() == token_output.commitment() {
					return Err(ErrorKind::DuplicateCommitment(token_output.commitment()).into());
				}
			}
		}

		if token_output.is_tokenissue() {
			if let Ok(pos) = batch.get_token_issue_proof_pos(&token_output.token_type()) {
				if let Some(out_mmr) = self.issue_token_pmmr.get_data(pos) {
					if out_mmr.token_type() == token_output.token_type() {
						return Err(ErrorKind::DuplicateTokenKey(token_output.token_type()).into());
					}
				}
			}
		}

		Ok(())
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos: u64) -> Result<Output, Error> {
		match self.output_pmmr.get_data(pos) {
			Some(output_id) => match self.rproof_pmmr.get_data(pos) {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound.into()),
			},
			None => Err(ErrorKind::OutputNotFound.into()),
		}
	}

	/// Retrieves an unspent token output using its PMMR position
	pub fn get_unspent_token_output_at(&self, pos: u64) -> Result<TokenOutput, Error> {
		match self.token_output_pmmr.get_data(pos) {
			Some(output_id) => match self.token_rproof_pmmr.get_data(pos) {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound.into()),
			},
			None => Err(ErrorKind::OutputNotFound.into()),
		}
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(
		&self,
		inputs: &Vec<Input>,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		// Find the greatest output pos of any coinbase
		// outputs we are attempting to spend.
		let pos = inputs
			.iter()
			.filter(|x| x.is_coinbase())
			.filter_map(|x| batch.get_output_pos(&x.commitment()).ok())
			.max()
			.unwrap_or(0);

		if pos > 0 {
			// If we have not yet reached 1440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity() {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}

			// Find the "cutoff" pos in the output MMR based on the
			// header from 1,000 blocks ago.
			let cutoff_height = height.saturating_sub(global::coinbase_maturity());
			let cutoff_header = self.get_header_by_height(cutoff_height, batch)?;
			let cutoff_pos = cutoff_header.output_mmr_size;

			// If any output pos exceed the cutoff_pos
			// we know they have not yet sufficiently matured.
			if pos > cutoff_pos {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}
		}

		Ok(())
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos: u64) -> Option<Hash> {
		self.header_pmmr.get_data(pos).map(|x| x.hash())
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(
		&self,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<BlockHeader, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height + 1);
		if let Some(hash) = self.get_header_hash(pos) {
			let header = batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(ErrorKind::Other("get header by height".to_string()).into())
		}
	}
}
