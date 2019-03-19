// Copyright 2018 The Grin Developers
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

//! Hash Function
//!
//! Primary hash function used in the protocol
//!

use byteorder::{BigEndian, ByteOrder};
use std::cmp::min;
use std::convert::AsRef;
use std::ops::Add;
use std::{fmt, ops};

use crate::blake2::blake2b::Blake2b;

use crate::ser::{self, AsFixedBytes, Error, FixedLength, Readable, Reader, Writeable, Writer};
use crate::util;
use digest::Digest;
use sha2::Sha256;

/// A hash consisting of all zeroes, used as a sentinel. No known preimage.
pub const ZERO_HASH: Hash = Hash([0; 32]);

/// A hash to uniquely (or close enough) identify one of the main blockchain
/// constructs. Used pervasively for blocks, transactions and outputs.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl DefaultHashable for Hash {}

impl Hash {
	fn hash_with<T: Writeable>(&self, other: T) -> Hash {
		let mut hasher = HashWriter::default();
		ser::Writeable::write(self, &mut hasher).unwrap();
		ser::Writeable::write(&other, &mut hasher).unwrap();
		let mut ret = [0; 32];
		hasher.finalize(&mut ret);
		Hash(ret)
	}

	/// compute double sha256 hash of Hash with other one
	pub fn dhash_with<T: Writeable>(&self, other: T) -> Hash {
		let mut hasher = DHashWriter::default();
		ser::Writeable::write(self, &mut hasher).unwrap();
		ser::Writeable::write(&other, &mut hasher).unwrap();
		let mut ret = [0; 32];
		hasher.finalize(&mut ret);
		Hash(ret)
	}
}

impl fmt::Debug for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let hash_hex = self.to_hex();
		const NUM_SHOW: usize = 12;

		write!(f, "{}", &hash_hex[..NUM_SHOW])
	}
}

impl fmt::Display for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl FixedLength for Hash {
	/// Size of a hash in bytes.
	const LEN: usize = 32;
}

impl Hash {
	/// Builds a Hash from a byte vector. If the vector is too short, it will be
	/// completed by zeroes. If it's too long, it will be truncated.
	pub fn from_vec(v: &[u8]) -> Hash {
		let mut h = [0; Hash::LEN];
		let copy_size = min(v.len(), Hash::LEN);
		h[..copy_size].copy_from_slice(&v[..copy_size]);
		Hash(h)
	}

	/// Converts the hash to a byte vector
	pub fn to_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	/// Returns a byte slice of the hash contents.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Convert a hash to hex string format.
	pub fn to_hex(&self) -> String {
		util::to_hex(self.to_vec())
	}

	/// Convert hex string back to hash.
	pub fn from_hex(hex: &str) -> Result<Hash, Error> {
		let bytes = util::from_hex(hex.to_string())
			.map_err(|_| Error::HexError(format!("failed to decode {}", hex)))?;
		Ok(Hash::from_vec(&bytes))
	}

	/// Most significant 64 bits
	pub fn to_u64(&self) -> u64 {
		BigEndian::read_u64(&self.0)
	}
}

impl ops::Index<usize> for Hash {
	type Output = u8;

	fn index(&self, idx: usize) -> &u8 {
		&self.0[idx]
	}
}

impl ops::Index<ops::Range<usize>> for Hash {
	type Output = [u8];

	fn index(&self, idx: ops::Range<usize>) -> &[u8] {
		&self.0[idx]
	}
}

impl ops::Index<ops::RangeTo<usize>> for Hash {
	type Output = [u8];

	fn index(&self, idx: ops::RangeTo<usize>) -> &[u8] {
		&self.0[idx]
	}
}

impl ops::Index<ops::RangeFrom<usize>> for Hash {
	type Output = [u8];

	fn index(&self, idx: ops::RangeFrom<usize>) -> &[u8] {
		&self.0[idx]
	}
}

impl ops::Index<ops::RangeFull> for Hash {
	type Output = [u8];

	fn index(&self, idx: ops::RangeFull) -> &[u8] {
		&self.0[idx]
	}
}

impl AsRef<[u8]> for Hash {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Readable for Hash {
	fn read(reader: &mut dyn Reader) -> Result<Hash, ser::Error> {
		let v = reader.read_fixed_bytes(32)?;
		let mut a = [0; 32];
		a.copy_from_slice(&v[..]);
		Ok(Hash(a))
	}
}

impl Writeable for Hash {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_fixed_bytes(&self.0)
	}
}

impl Add for Hash {
	type Output = Hash;
	fn add(self, other: Hash) -> Hash {
		self.hash_with(other)
	}
}

impl Default for Hash {
	fn default() -> Hash {
		ZERO_HASH
	}
}

/// Serializer that outputs a double sha256 hash of the serialized object
pub struct DHashWriter {
	state: Vec<u8>,
}

impl DHashWriter {
	/// Consume the `BitHashWriter`, outputting its current hash into a 32-byte
	/// array
	pub fn finalize(self, output: &mut [u8]) {
		let mut sha2 = Sha256::new();
		sha2.input(self.state.as_slice());
		output.copy_from_slice(sha2.result().as_slice());
		sha2 = Sha256::new();
		sha2.input(&output);
		output.copy_from_slice(sha2.result().as_slice());
	}
}

impl Default for DHashWriter {
	fn default() -> DHashWriter {
		DHashWriter { state: Vec::new() }
	}
}

impl ser::Writer for DHashWriter {
	fn serialization_mode(&self) -> ser::SerializationMode {
		ser::SerializationMode::Hash
	}

	fn write_fixed_bytes<T: AsFixedBytes>(&mut self, b32: &T) -> Result<(), ser::Error> {
		self.state.extend_from_slice(b32.as_ref());
		Ok(())
	}
}

/// Serializer that outputs a hash of the serialized object
pub struct HashWriter {
	state: Blake2b,
}

impl HashWriter {
	/// Consume the `HashWriter`, outputting its current hash into a 32-byte
	/// array
	pub fn finalize(self, output: &mut [u8]) {
		output.copy_from_slice(self.state.finalize().as_bytes());
	}

	/// Consume the `HashWriter`, outputting a `Hash` corresponding to its
	/// current state
	pub fn into_hash(self) -> Hash {
		let mut res = [0; 32];
		res.copy_from_slice(self.state.finalize().as_bytes());
		Hash(res)
	}
}

impl Default for HashWriter {
	fn default() -> HashWriter {
		HashWriter {
			state: Blake2b::new(32),
		}
	}
}

impl ser::Writer for HashWriter {
	fn serialization_mode(&self) -> ser::SerializationMode {
		ser::SerializationMode::Hash
	}

	fn write_fixed_bytes<T: AsFixedBytes>(&mut self, b32: &T) -> Result<(), ser::Error> {
		self.state.update(b32.as_ref());
		Ok(())
	}
}

/// A trait for types that have a canonical hash
pub trait Hashed {
	/// Obtain the hash of the object
	fn hash(&self) -> Hash;

	/// Obtain the double sha256 hash of the object
	fn dhash(&self) -> Hash;
}

/// Implementing this trait enables the default
/// hash implementation
pub trait DefaultHashable: Writeable {}
impl<D: DefaultHashable> Hashed for D {
	fn hash(&self) -> Hash {
		let mut hasher = HashWriter::default();
		Writeable::write(self, &mut hasher).unwrap();
		let mut ret = [0; 32];
		hasher.finalize(&mut ret);
		Hash(ret)
	}

	fn dhash(&self) -> Hash {
		let mut hasher = DHashWriter::default();
		ser::Writeable::write(self, &mut hasher).unwrap();
		let mut ret = [0; 32];
		hasher.finalize(&mut ret);
		Hash(ret)
	}
}

impl<D: DefaultHashable> DefaultHashable for &D {}
impl<D: DefaultHashable, E: DefaultHashable> DefaultHashable for (D, E) {}
impl<D: DefaultHashable, E: DefaultHashable, F: DefaultHashable> DefaultHashable for (D, E, F) {}

/// Implement Hashed trait for external types here
impl DefaultHashable for crate::util::secp::pedersen::RangeProof {}
impl DefaultHashable for Vec<u8> {}
impl DefaultHashable for u64 {}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn dsha256_test() {
		let hex0 =
			Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
				.unwrap();
		let result0 = hex0.dhash();
		assert_eq!(
			result0.to_hex(),
			"2b32db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667151e"
		);

		let hex1 =
			Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
				.unwrap();
		let result1 = hex1.dhash();
		assert_eq!(
			result1.to_hex(),
			"59420d36b80353ed5a5822ca464cc9bffb8abe9cd63959651d3cd85a8252d83f"
		);

		let hex3 =
			Hash::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
				.unwrap();
		let result3 = hex3.dhash();
		assert_eq!(
			result3.to_hex(),
			"71ca5049661b67d2babaf306cd9bc8090a93324c2d4ff1bb12a371a02cc23eb8"
		);
	}
}
