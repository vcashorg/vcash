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

//! BlockSums per-block running totals for utxo_sum and kernel_sum.
//! Allows fast "full" verification of kernel sums at a given block height.

use crate::core::committed::Committed;
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use util::secp::pedersen::Commitment;
use util::secp_static;

use crate::core::transaction::TokenKey;
use std::collections::HashMap;

/// The output_sum and kernel_sum for a given block.
/// This is used to validate the next block being processed by applying
/// the inputs, outputs, kernels and kernel_offset from the new block
/// and checking everything sums correctly.
#[derive(Debug, Clone)]
pub struct BlockSums {
	/// The sum of the unspent outputs.
	pub utxo_sum: Commitment,
	/// The sum of all kernels.
	pub kernel_sum: Commitment,
}

impl Writeable for BlockSums {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(&self.utxo_sum)?;
		writer.write_fixed_bytes(&self.kernel_sum)?;
		Ok(())
	}
}

impl Readable for BlockSums {
	fn read<R: Reader>(reader: &mut R) -> Result<BlockSums, ser::Error> {
		Ok(BlockSums {
			utxo_sum: Commitment::read(reader)?,
			kernel_sum: Commitment::read(reader)?,
		})
	}
}

impl Default for BlockSums {
	fn default() -> BlockSums {
		let zero_commit = secp_static::commit_to_zero_value();
		BlockSums {
			utxo_sum: zero_commit,
			kernel_sum: zero_commit,
		}
	}
}

/// It's a tuple but we can verify the "full" kernel sums on it.
/// This means we can take a previous block_sums, apply a new block to it
/// and verify the full kernel sums (full UTXO and kernel sets).
impl<'a> Committed for (BlockSums, &'a dyn Committed) {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.1.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		let mut outputs = vec![self.0.utxo_sum];
		outputs.extend(&self.1.outputs_committed());
		outputs
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		let mut kernels = vec![self.0.kernel_sum];
		kernels.extend(&self.1.kernels_committed());
		kernels
	}

	fn token_inputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		HashMap::new()
	}

	fn token_outputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		HashMap::new()
	}

	fn token_kernels_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		HashMap::new()
	}
}

/// The token_utxo_sum and token_kernel_sum for a given block.
/// This is used to validate the next block being processed by applying
/// the token_inputs, token_outputs and token_kernels from the new block
/// and checking everything sums correctly.
#[derive(Debug, Clone)]
pub struct BlockTokenSums {
	/// The token issue commit map
	pub token_issue_commit_map: HashMap<TokenKey, Commitment>,
	/// The sum of the unspent token outputs map
	pub token_utxo_sum_map: HashMap<TokenKey, Commitment>,
	/// The sum of all token kernels map
	pub token_kernel_sum_map: HashMap<TokenKey, Commitment>,
}

impl Writeable for BlockTokenSums {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u16(self.token_issue_commit_map.len() as u16)?;
		for (token_type, commit) in &self.token_issue_commit_map {
			token_type.write(writer)?;
			writer.write_fixed_bytes(commit)?;
		}

		writer.write_u16(self.token_utxo_sum_map.len() as u16)?;
		for (token_type, commit) in &self.token_utxo_sum_map {
			token_type.write(writer)?;
			writer.write_fixed_bytes(commit)?;
		}

		writer.write_u16(self.token_kernel_sum_map.len() as u16)?;
		for (token_type, excess) in &self.token_kernel_sum_map {
			token_type.write(writer)?;
			writer.write_fixed_bytes(excess)?;
		}

		Ok(())
	}
}

impl Readable for BlockTokenSums {
	fn read<R: Reader>(reader: &mut R) -> Result<BlockTokenSums, ser::Error> {
		let mut token_issue_commit_map: HashMap<TokenKey, Commitment> = HashMap::new();
		let length = reader.read_u16()?;
		for _ in 0..length {
			let tokey_type = TokenKey::read(reader)?;
			let commit = Commitment::read(reader)?;
			token_issue_commit_map.insert(tokey_type, commit);
		}

		let mut token_utxo_sum_map: HashMap<TokenKey, Commitment> = HashMap::new();
		let length = reader.read_u16()?;
		for _ in 0..length {
			let tokey_type = TokenKey::read(reader)?;
			let commit = Commitment::read(reader)?;
			token_utxo_sum_map.insert(tokey_type, commit);
		}

		let mut token_kernel_sum_map: HashMap<TokenKey, Commitment> = HashMap::new();
		let length = reader.read_u16()?;
		for _ in 0..length {
			let tokey_type = TokenKey::read(reader)?;
			let commit = Commitment::read(reader)?;
			token_kernel_sum_map.insert(tokey_type, commit);
		}

		Ok(BlockTokenSums {
			token_issue_commit_map,
			token_utxo_sum_map,
			token_kernel_sum_map,
		})
	}
}

impl Default for BlockTokenSums {
	fn default() -> BlockTokenSums {
		BlockTokenSums {
			token_issue_commit_map: HashMap::new(),
			token_utxo_sum_map: HashMap::new(),
			token_kernel_sum_map: HashMap::new(),
		}
	}
}

impl<'a> Committed for (BlockTokenSums, &'a dyn Committed) {
	fn inputs_committed(&self) -> Vec<Commitment> {
		vec![]
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		vec![]
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		vec![]
	}

	fn token_inputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_inputs_commit = self.1.token_inputs_committed();
		for (token_key, commit) in self.0.token_issue_commit_map.iter() {
			token_inputs_commit.insert(token_key.clone(), vec![commit.clone()]);
		}

		token_inputs_commit
	}

	fn token_outputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_outputs_commit = self.1.token_outputs_committed();
		for (token_key, commit) in self.0.token_utxo_sum_map.iter() {
			token_outputs_commit.insert(token_key.clone(), vec![commit.clone()]);
		}

		token_outputs_commit
	}

	fn token_kernels_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_kernel_commit = self.1.token_kernels_committed();
		for (token_key, commit) in self.0.token_kernel_sum_map.iter() {
			token_kernel_commit.insert(token_key.clone(), vec![commit.clone()]);
		}

		token_kernel_commit
	}
}
