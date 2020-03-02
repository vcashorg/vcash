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

//! Common types and traits for cuckoo family of solvers

use crate::pow::error::{Error, ErrorKind};
use crate::pow::num::{PrimInt, ToPrimitive};
use crate::pow::siphash::siphash24;
use blake2::blake2b::blake2b;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::hash::Hash;
use std::io::Cursor;
use std::ops::{BitOrAssign, Mul};

use crate::core::hash::Hash as BitHash;
use crate::num_bigint::BigUint;
use crate::pow::num::FromPrimitive;
use rand::{thread_rng, Rng};

/// Operations needed for edge type (going to be u32 or u64)
pub trait EdgeType: PrimInt + ToPrimitive + Mul + BitOrAssign + Hash {}
impl EdgeType for u32 {}
impl EdgeType for u64 {}

/// An edge in the Cuckoo graph, simply references two u64 nodes.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Edge<T>
where
	T: EdgeType,
{
	pub u: T,
	pub v: T,
}

impl<T> fmt::Display for Edge<T>
where
	T: EdgeType,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"(u: {}, v: {})",
			self.u.to_u64().unwrap_or(0),
			self.v.to_u64().unwrap_or(0)
		)
	}
}

/// An element of an adjencency list
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Link<T>
where
	T: EdgeType,
{
	pub next: T,
	pub to: T,
}

impl<T> fmt::Display for Link<T>
where
	T: EdgeType,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"(next: {}, to: {})",
			self.next.to_u64().unwrap_or(0),
			self.to.to_u64().unwrap_or(0)
		)
	}
}

pub fn set_header_nonce(header: &[u8], nonce: Option<u32>) -> Result<[u64; 4], Error> {
	if let Some(n) = nonce {
		let len = header.len();
		let mut header = header.to_owned();
		header.truncate(len - 4); // drop last 4 bytes (u32) off the end
		header.write_u32::<LittleEndian>(n)?;
		create_siphash_keys(&header)
	} else {
		create_siphash_keys(&header)
	}
}

pub fn create_siphash_keys(header: &[u8]) -> Result<[u64; 4], Error> {
	let h = blake2b(32, &[], &header);
	let hb = h.as_bytes();
	let mut rdr = Cursor::new(hb);
	Ok([
		rdr.read_u64::<LittleEndian>()?,
		rdr.read_u64::<LittleEndian>()?,
		rdr.read_u64::<LittleEndian>()?,
		rdr.read_u64::<LittleEndian>()?,
	])
}

/// Macro to clean up u64 unwrapping
#[macro_export]
macro_rules! to_u64 {
	($n:expr) => {
		$n.to_u64().ok_or(ErrorKind::IntegerCast)?
	};
}

/// Macro to clean up u64 unwrapping as u32
#[macro_export]
macro_rules! to_u32 {
	($n:expr) => {
		$n.to_u64().ok_or(ErrorKind::IntegerCast)? as u32
	};
}

/// Macro to clean up u64 unwrapping as usize
#[macro_export]
macro_rules! to_usize {
	($n:expr) => {
		$n.to_u64().ok_or(ErrorKind::IntegerCast)? as usize
	};
}

/// Macro to clean up casting to edge type
#[macro_export]
macro_rules! to_edge {
	($edge_type:ident, $n:expr) => {
		$edge_type::from($n).ok_or(ErrorKind::IntegerCast)?
	};
}

/// Utility struct to calculate commonly used Cuckoo parameters calculated
/// from header, nonce, edge_bits, etc.
pub struct CuckooParams<T>
where
	T: EdgeType,
{
	pub edge_bits: u8,
	pub proof_size: usize,
	pub num_edges: u64,
	pub siphash_keys: [u64; 4],
	pub edge_mask: T,
}

impl<T> CuckooParams<T>
where
	T: EdgeType,
{
	/// Instantiates new params and calculate edge mask, etc
	pub fn new(edge_bits: u8, proof_size: usize) -> Result<CuckooParams<T>, Error> {
		let num_edges = (1 as u64) << edge_bits;
		let edge_mask = to_edge!(T, num_edges - 1);
		Ok(CuckooParams {
			edge_bits,
			proof_size,
			num_edges,
			siphash_keys: [0; 4],
			edge_mask,
		})
	}

	/// Reset the main keys used for siphash from the header and nonce
	pub fn reset_header_nonce(&mut self, header: Vec<u8>, nonce: Option<u32>) -> Result<(), Error> {
		self.siphash_keys = set_header_nonce(&header, nonce)?;
		Ok(())
	}

	/// Return siphash masked for type
	pub fn sipnode(&self, edge: T, uorv: u64, shift: bool) -> Result<T, Error> {
		let hash_u64 = siphash24(
			&self.siphash_keys,
			2 * edge.to_u64().ok_or(ErrorKind::IntegerCast)? + uorv,
		);
		let mut masked = hash_u64 & self.edge_mask.to_u64().ok_or(ErrorKind::IntegerCast)?;
		if shift {
			masked <<= 1;
			masked |= uorv;
		}
		Ok(T::from(masked).ok_or(ErrorKind::IntegerCast)?)
	}
}

/// compact convert to diff
pub fn compact_to_diff(nbits: u32) -> u64 {
	let mut shift: u32 = (nbits >> 24) & 0xff;
	let mut diff: f64 = (0x0000ffff as f64) / ((nbits & 0x00ffffff) as f64);
	while shift < 29 {
		diff = diff * 256.0;
		shift = shift + 1;
	}
	while shift > 29 {
		diff = diff / 256.0;
		shift = shift - 1;
	}

	return diff as u64;
}

/// hash convert to biguint
pub fn hash_to_biguint(hash: BitHash) -> BigUint {
	let data = hash.to_vec();
	BigUint::from_bytes_le(&data)
}

/// biguint convert to hash
pub fn biguint_to_hash(bignum: BigUint) -> BitHash {
	let data = bignum.to_bytes_le();
	BitHash::from_vec(&data)
}

/// compact convert to biguint
pub fn compact_to_biguint(nbits: u32) -> Option<BigUint> {
	let bignum: Option<BigUint>;
	let size = nbits >> 24;
	let mut word = nbits & 0x007fffff;
	if size <= 3 {
		word >>= 8 * (3 - size);
		bignum = BigUint::from_u32(word);
	} else {
		let mut temp = BigUint::from_u32(word).unwrap();
		temp <<= 8 * (size - 3) as usize;
		bignum = Some(temp);
	}

	//is negative
	if word != 0 && (nbits & 0x00800000) != 0 {
		return None;
	}
	//is overflow
	if word != 0 && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32)) {
		return None;
	}
	return bignum;
}

/// biguint convert to compact
pub fn biguint_to_compact(bignum: BigUint, negative: bool) -> u32 {
	let mut size: i32 = (bignum.bits() as i32 + 7) / 8;
	let mut compact: u32;
	if size <= 3 {
		let bignum_low64 = get_biguint_low64(&bignum);
		compact = (bignum_low64 << 8 * (3 - size)) as u32;
	} else {
		let new_bignum = bignum >> (8 * (size - 3) as usize);
		compact = get_biguint_low64(&new_bignum) as u32;
	}

	// The 0x00800000 bit denotes the sign.
	// Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
	if compact & 0x00800000 != 0 {
		compact >>= 8;
		size += 1;
	}

	assert_eq!((compact & !0x007fffff), 0);
	assert_eq!(size < 256, true);

	compact |= (size << 24) as u32;
	compact |= if negative && (compact & 0x007fffff != 0) {
		0x00800000
	} else {
		0
	};

	compact
}

fn get_biguint_low64(bignum: &BigUint) -> u64 {
	let mut data = bignum.to_bytes_le();
	data.truncate(64);
	let new_num = BigUint::from_bytes_le(&data);
	new_num.to_u64().unwrap()
}

/// create random mask by miner_bits
pub fn random_mask(nbits: u32) -> Result<BitHash, String> {
	let mut mask = [0u8; 32];
	let mut rng = thread_rng();
	rng.fill(&mut mask);

	let biguint = compact_to_biguint(nbits);
	if biguint.is_some() {
		let biguint = biguint.unwrap();
		let hash = biguint_to_hash(biguint);
		let bytes = hash.as_bytes();
		let mut iter = bytes.len() - 1;
		loop {
			mask[iter] = 0;
			if bytes[iter] != 0 || iter == 0 {
				break;
			}
			iter = iter - 1;
		}

		return Ok(BitHash::from_vec(&mask));
	}

	return Err("Bad bits".to_string());
}

/// use mask to header hash
pub fn pow_hash_after_mask(hash: BitHash, mask: BitHash) -> BitHash {
	let hash_bytes = hash.as_bytes();
	let mask_bytes = mask.as_bytes();
	let mut new_bytes = [0 as u8; 32];
	for i in 0..hash_bytes.len() {
		new_bytes[i] = hash_bytes[i] ^ mask_bytes[i];
	}

	return BitHash::from_vec(new_bytes.as_ref());
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::ZERO_HASH;

	#[test]
	fn pow_hash_after_mask_test() {
		let origin_hash_0 =
			BitHash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();
		let mask_hash_0 =
			BitHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
				.unwrap();
		let pow_hash_0 = pow_hash_after_mask(origin_hash_0, mask_hash_0);
		let target_hash_0 = origin_hash_0;
		assert_eq!(pow_hash_0, target_hash_0);

		let origin_hash_1 =
			BitHash::from_hex("0101010101010101010101010101010101010101010101010101010101010101")
				.unwrap();
		let mask_hash_1 =
			BitHash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
				.unwrap();
		let pow_hash_1 = pow_hash_after_mask(origin_hash_1, mask_hash_1);
		let target_hash_1 =
			BitHash::from_hex("1010101010101010101010101010101010101010101010101010101010101010")
				.unwrap();
		assert_eq!(pow_hash_1, target_hash_1);

		let origin_hash_2 =
			BitHash::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
				.unwrap();
		let mask_hash_2 =
			BitHash::from_hex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
				.unwrap();
		let pow_hash_2 = pow_hash_after_mask(origin_hash_2, mask_hash_2);
		let target_hash_2 =
			BitHash::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
				.unwrap();
		assert_eq!(pow_hash_2, target_hash_2);
	}

	#[test]
	fn random_mask_test() {
		// diff 2^0, hash = "00000000ffff0000000000000000000000000000000000000000000000000000"
		let bits_0 = 486604799;
		let random_0 = random_mask(bits_0).unwrap().to_hex();
		let random_str_0 = random_0.as_str();
		assert!(random_str_0.ends_with("0000000000"));

		// diff 2^10, hash = "00000000003fffc0000000000000000000000000000000000000000000000000"
		let bits_1 = 457179072;
		let random_1 = random_mask(bits_1).unwrap().to_hex();
		let random_str_1 = random_1.as_str();
		assert!(random_str_1.ends_with("000000000000"));

		// diff 2^20, hash = "0000000000000ffff00000000000000000000000000000000000000000000000"
		let bits_2 = 437256176;
		let random_2 = random_mask(bits_2).unwrap().to_hex();
		let random_str_2 = random_2.as_str();
		assert!(random_str_2.ends_with("00000000000000"));

		// diff 2^30, hash = "0000000000000003fffc00000000000000000000000000000000000000000000"
		let bits_3 = 419692540;
		let random_3 = random_mask(bits_3).unwrap().to_hex();
		let random_str_3 = random_3.as_str();
		assert!(random_str_3.ends_with("0000000000000000"));

		// diff 2^40, hash = "000000000000000000ffff000000000000000000000000000000000000000000"
		let bits_4 = 402718719;
		let random_4 = random_mask(bits_4).unwrap().to_hex();
		let random_str_4 = random_4.as_str();
		assert!(random_str_4.ends_with("00000000000000000000"));

		// diff 2^50, hash = "000000000000000000003fffc000000000000000000000000000000000000000"
		let bits_5 = 373292992;
		let random_5 = random_mask(bits_5).unwrap().to_hex();
		let random_str_5 = random_5.as_str();
		assert!(random_str_5.ends_with("0000000000000000000000"));

		// diff 2^60, hash = "00000000000000000000000ffff0000000000000000000000000000000000000"
		let bits_6 = 353370096;
		let random_6 = random_mask(bits_6).unwrap().to_hex();
		let random_str_6 = random_6.as_str();
		assert!(random_str_6.ends_with("000000000000000000000000"));

		// hash = "00000000000005db8b0000000000000000000000000000000000000000000000"
		let bits_7 = 436591499;
		let random_7 = random_mask(bits_7).unwrap().to_hex();
		let random_str_7 = random_7.as_str();
		assert!(random_str_7.ends_with("00000000000000"));

		// hash = "0000000000000000896c00000000000000000000000000000000000000000000"
		let bits_8 = 419465580;
		let random_8 = random_mask(bits_8).unwrap().to_hex();
		let random_str_8 = random_8.as_str();
		assert!(random_str_8.ends_with("000000000000000000"));
	}

	#[test]
	fn biguint_hash_test() {
		let test_hash0 = ZERO_HASH;
		let ret_hash0 = biguint_to_hash(hash_to_biguint(test_hash0));
		assert_eq!(test_hash0, ret_hash0);

		let test_hash1 =
			BitHash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();
		let ret_hash1 = biguint_to_hash(hash_to_biguint(test_hash1));
		assert_eq!(test_hash1, ret_hash1);

		let test_hash2 =
			BitHash::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
				.unwrap();
		let ret_hash2 = biguint_to_hash(hash_to_biguint(test_hash2));
		assert_eq!(test_hash2, ret_hash2);
	}

	#[test]
	fn biguint_compact_test() {
		let biguint0 = compact_to_biguint(0).unwrap();
		let compact0 = biguint_to_compact(biguint0, false);
		assert_eq!(0_u32, compact0);

		let biguint1 = compact_to_biguint(0x00123456).unwrap();
		let compact1 = biguint_to_compact(biguint1, false);
		assert_eq!(0_u32, compact1);

		let biguint2 = compact_to_biguint(0x01003456).unwrap();
		let compact2 = biguint_to_compact(biguint2, false);
		assert_eq!(0_u32, compact2);

		let biguint3 = compact_to_biguint(0x04000000).unwrap();
		let compact3 = biguint_to_compact(biguint3, false);
		assert_eq!(0_u32, compact3);

		let biguint4 = compact_to_biguint(0x00923456).unwrap();
		let compact4 = biguint_to_compact(biguint4, false);
		assert_eq!(0_u32, compact4);

		let biguint5 = compact_to_biguint(0x01123456).unwrap();
		let compact5 = biguint_to_compact(biguint5, false);
		assert_eq!(0x01120000_u32, compact5);

		let biguint6 = compact_to_biguint(0x01fedcba);
		assert_eq!(biguint6, None);

		let biguint7 = compact_to_biguint(0x02123456).unwrap();
		let compact7 = biguint_to_compact(biguint7, false);
		assert_eq!(0x02123400_u32, compact7);

		let biguint8 = compact_to_biguint(0x04123456).unwrap();
		let compact8 = biguint_to_compact(biguint8, false);
		assert_eq!(0x04123456_u32, compact8);

		let biguint9 = compact_to_biguint(0x20123456).unwrap();
		let compact9 = biguint_to_compact(biguint9, false);
		assert_eq!(0x20123456_u32, compact9);

		let biguint10 = compact_to_biguint(0xff123456);
		assert_eq!(biguint10, None);

		let biguint11 = compact_to_biguint(0x05009234).unwrap();
		let compact11 = biguint_to_compact(biguint11, false);
		assert_eq!(0x05009234_u32, compact11);

		let biguint12 = compact_to_biguint(0x04923456);
		assert_eq!(biguint12, None);

		let biguint13 = compact_to_biguint(0x03123456).unwrap();
		let compact13 = biguint_to_compact(biguint13, false);
		assert_eq!(0x03123456_u32, compact13);
	}
}
