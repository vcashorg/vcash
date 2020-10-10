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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]

use crate::core;
use crate::core::hash::Hash;
use crate::pow::ProofOfWork;
use chrono::prelude::{TimeZone, Utc};
use keychain::BlindingFactor;
use util;
use util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use util::secp::pedersen::{Commitment, RangeProof};
use util::secp::Signature;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	let genesis_dev_header_version = core::HeaderVersion(2);
	core::Block::with_header(core::BlockHeader {
		version: genesis_dev_header_version,
		height: 0,
		// previous: core::hash::Hash([0xff; 32]),
		timestamp: Utc.ymd(1997, 8, 4).and_hms(0, 0, 0),
		bits: 0x2100ffff,
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	})
}

/// Floonet genesis block
pub fn genesis_floo() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2019, 3, 27).and_hms(0, 0, 0),
		prev_root: Hash::from_hex(
			"00000000000000000017ff4903ef366c8f62e3151ba74e41b8332a126542f538",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"73b5e0a05ea9e1e4e33b8f1c723bc5c10d17f07042c2af7644f4dbb61f4bc556",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"667a3ba22f237a875f67c9933037c8564097fa57a3e75be507916de28fc0da26",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"cfdddfe2d938d0026f8b1304442655bbdddde175ff45ddf44cb03bcb0071a72d",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		bits: 0x1b01cc26,
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("09b1242944552f51ba4ae26699f5583fe6d57fa0dd9987ceabd9600f625341c39f")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			70, 132, 229, 74, 16, 200, 129, 132, 19, 82, 50, 68, 9, 191, 37, 18, 252, 75, 217, 99,
			34, 104, 114, 114, 193, 158, 59, 254, 154, 3, 40, 15, 134, 86, 6, 232, 35, 63, 110,
			213, 248, 99, 203, 37, 129, 117, 250, 201, 213, 193, 231, 115, 242, 56, 10, 197, 251,
			206, 20, 94, 98, 39, 233, 115,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("095142abcf5062e5f53ffd3101ed404ba22eadf3f12dd950281e6c74212f90f196")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				252, 128, 125, 252, 137, 194, 212, 142, 251, 117, 46, 226, 157, 49, 93, 109, 35,
				60, 67, 255, 250, 148, 26, 155, 13, 121, 208, 174, 176, 56, 132, 211, 226, 94, 131,
				173, 144, 90, 100, 219, 93, 103, 103, 48, 59, 163, 53, 150, 187, 187, 35, 6, 101,
				160, 153, 235, 145, 56, 122, 31, 141, 161, 177, 193, 15, 8, 16, 115, 35, 170, 75,
				202, 205, 234, 86, 244, 47, 244, 61, 214, 106, 105, 42, 242, 194, 153, 78, 31, 113,
				114, 149, 12, 70, 158, 128, 89, 159, 137, 6, 146, 245, 77, 9, 76, 26, 229, 71, 50,
				241, 26, 76, 135, 241, 172, 72, 212, 204, 21, 184, 129, 191, 2, 49, 142, 106, 81,
				215, 0, 59, 248, 226, 147, 173, 188, 0, 17, 82, 181, 142, 36, 50, 185, 3, 88, 212,
				203, 167, 167, 25, 60, 2, 209, 103, 99, 104, 218, 83, 46, 112, 31, 191, 133, 103,
				231, 196, 102, 156, 37, 98, 177, 160, 99, 176, 203, 233, 163, 221, 32, 5, 65, 77,
				2, 251, 11, 121, 62, 49, 88, 24, 84, 33, 125, 96, 30, 9, 44, 44, 218, 53, 58, 204,
				138, 236, 189, 79, 78, 174, 109, 31, 103, 220, 149, 111, 97, 96, 233, 53, 252, 183,
				146, 198, 130, 10, 52, 126, 253, 104, 217, 151, 246, 215, 208, 124, 132, 49, 83,
				69, 245, 47, 187, 109, 38, 198, 204, 165, 206, 19, 46, 28, 128, 211, 131, 177, 104,
				237, 97, 80, 200, 189, 222, 62, 238, 102, 216, 77, 53, 162, 40, 78, 203, 116, 121,
				4, 103, 199, 105, 163, 29, 16, 198, 113, 14, 19, 79, 124, 245, 23, 233, 41, 118,
				143, 168, 133, 39, 58, 5, 12, 158, 210, 232, 137, 57, 34, 228, 222, 67, 69, 18,
				232, 248, 191, 94, 126, 191, 235, 57, 106, 192, 203, 245, 13, 242, 227, 238, 7, 33,
				90, 79, 184, 196, 109, 10, 100, 151, 0, 36, 225, 158, 187, 12, 191, 105, 220, 94,
				25, 89, 166, 223, 202, 185, 184, 79, 198, 12, 0, 240, 188, 245, 90, 53, 219, 223,
				248, 56, 110, 37, 163, 135, 16, 120, 110, 110, 166, 185, 210, 51, 246, 221, 151,
				173, 180, 221, 181, 0, 145, 6, 177, 15, 253, 172, 31, 157, 212, 26, 185, 120, 184,
				41, 101, 23, 45, 58, 248, 255, 200, 156, 81, 241, 107, 198, 101, 191, 210, 172,
				234, 179, 81, 82, 198, 167, 70, 171, 240, 209, 51, 158, 217, 29, 146, 247, 58, 44,
				88, 164, 139, 233, 95, 179, 94, 163, 172, 149, 127, 254, 1, 175, 194, 255, 85, 120,
				141, 112, 146, 248, 142, 25, 200, 157, 4, 75, 145, 31, 175, 253, 95, 45, 178, 92,
				219, 20, 12, 119, 50, 217, 84, 156, 83, 87, 226, 94, 122, 246, 58, 109, 54, 237,
				40, 92, 29, 16, 77, 196, 173, 150, 80, 132, 71, 137, 190, 208, 186, 253, 56, 115,
				112, 70, 29, 159, 106, 40, 81, 252, 144, 248, 224, 131, 88, 70, 215, 73, 190, 200,
				149, 143, 172, 117, 240, 196, 212, 140, 151, 230, 228, 193, 139, 153, 223, 97, 4,
				235, 66, 4, 84, 113, 246, 225, 185, 159, 61, 80, 240, 54, 106, 18, 233, 57, 54,
				180, 224, 160, 147, 176, 71, 130, 235, 69, 108, 98, 160, 83, 53, 90, 212, 108, 152,
				74, 195, 58, 84, 49, 215, 151, 207, 135, 255, 159, 198, 193, 156, 146, 231, 5, 111,
				127, 163, 47, 250, 62, 7, 204, 229, 117, 231, 85, 104, 70, 228, 25, 198, 163, 100,
				65, 12, 166, 139, 0, 123, 139, 195, 105, 51, 83, 93, 54, 126, 196, 80, 189, 92,
				189, 210, 4, 92, 66, 10, 117, 141, 237, 58, 255, 1, 185, 117, 108, 178, 101, 208,
				9, 246, 173, 176, 31, 138, 240, 22, 7, 219, 147, 143, 195, 156, 84, 234, 121, 64,
				59, 246, 141, 25, 228, 210, 170, 163, 138, 84,
			],
		},
	);
	gen.with_reward(output, kernel)
}

/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2019, 3, 28).and_hms(0, 0, 0),
		prev_root: Hash::from_hex(
			"0000000000000000002a8bc32f43277fe9c063b9c99ea252b483941dcd06e217",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"fa7566d275006c6c467876758f2bc87e4cebd2020ae9cf9f294c6217828d6872",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"1b7fff259aee3edfb5867c4775e4e1717826b843cda6685e5140442ece7bfc2e",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"e8bb096a73cbe6e099968965f5342fc1702ee2802802902286dcf0f279e326bf",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		bits: 0x18120f14,
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("0860eaaa24a954b7c269109d0d84deca638b93d0481b6ba3e74365a71145c6d6a2")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			93, 198, 127, 118, 148, 6, 204, 6, 172, 90, 74, 74, 226, 122, 185, 138, 82, 249, 250,
			73, 15, 192, 106, 224, 165, 107, 31, 225, 180, 217, 137, 28, 185, 140, 251, 21, 231,
			64, 111, 208, 214, 121, 183, 132, 67, 55, 184, 84, 63, 95, 198, 0, 58, 196, 200, 97,
			15, 115, 211, 185, 225, 52, 92, 135,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("09e1875e6209265959df8e4053f641cb73db743f338e7ee08adb616042e9304aa5")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				141, 236, 79, 167, 69, 191, 67, 74, 182, 230, 73, 160, 7, 196, 45, 173, 62, 4, 67,
				35, 204, 174, 226, 169, 189, 119, 129, 235, 47, 185, 113, 103, 240, 37, 130, 45,
				96, 145, 41, 202, 57, 184, 14, 253, 251, 43, 58, 44, 250, 5, 25, 129, 146, 50, 0,
				13, 93, 120, 42, 35, 203, 63, 174, 237, 15, 15, 70, 120, 22, 194, 159, 135, 12, 3,
				137, 161, 209, 163, 25, 243, 73, 242, 97, 208, 251, 28, 10, 142, 107, 189, 31, 142,
				178, 220, 180, 62, 184, 85, 192, 224, 45, 133, 216, 10, 90, 237, 80, 26, 232, 118,
				188, 98, 129, 215, 14, 37, 40, 213, 123, 164, 190, 78, 212, 210, 171, 179, 14, 16,
				240, 125, 2, 11, 4, 11, 13, 141, 135, 5, 19, 173, 107, 39, 182, 35, 25, 132, 30,
				16, 162, 227, 74, 168, 225, 226, 12, 200, 80, 242, 211, 219, 42, 180, 226, 99, 173,
				203, 13, 3, 235, 211, 234, 129, 146, 156, 54, 208, 3, 235, 101, 117, 119, 187, 33,
				85, 161, 179, 73, 65, 187, 32, 156, 162, 224, 246, 114, 22, 220, 125, 69, 57, 171,
				82, 252, 70, 196, 192, 75, 183, 189, 132, 4, 212, 235, 117, 66, 196, 127, 182, 118,
				144, 229, 80, 35, 57, 224, 11, 167, 35, 220, 119, 226, 35, 13, 119, 175, 125, 188,
				44, 76, 36, 237, 76, 39, 238, 194, 252, 210, 48, 144, 115, 138, 127, 98, 27, 159,
				200, 196, 35, 77, 71, 168, 112, 77, 68, 116, 145, 96, 150, 44, 203, 139, 119, 73,
				41, 22, 85, 201, 245, 27, 123, 215, 41, 131, 80, 145, 114, 132, 11, 78, 20, 44,
				136, 49, 230, 229, 134, 48, 212, 43, 217, 244, 31, 28, 217, 224, 205, 60, 163, 0,
				77, 187, 53, 216, 36, 11, 152, 2, 135, 51, 168, 51, 52, 89, 6, 149, 22, 126, 163,
				207, 215, 82, 202, 3, 228, 185, 4, 194, 7, 14, 222, 80, 36, 22, 215, 149, 32, 237,
				237, 64, 64, 213, 6, 21, 54, 0, 127, 16, 236, 254, 28, 7, 45, 197, 154, 49, 86,
				155, 104, 180, 93, 111, 204, 184, 6, 63, 46, 69, 201, 54, 7, 120, 0, 209, 134, 238,
				253, 247, 160, 220, 40, 4, 137, 156, 121, 202, 251, 168, 18, 130, 55, 255, 232,
				157, 224, 205, 146, 37, 15, 151, 255, 18, 253, 195, 152, 20, 219, 8, 2, 162, 180,
				65, 149, 185, 149, 0, 141, 242, 45, 231, 146, 212, 65, 181, 255, 0, 101, 107, 106,
				248, 141, 87, 18, 216, 147, 140, 75, 81, 152, 10, 81, 240, 54, 40, 182, 78, 155,
				48, 36, 235, 23, 226, 86, 71, 29, 164, 96, 206, 229, 190, 137, 40, 219, 182, 127,
				146, 32, 113, 133, 40, 220, 210, 189, 107, 14, 49, 170, 27, 220, 190, 62, 244, 21,
				119, 153, 246, 228, 154, 58, 125, 11, 153, 69, 43, 12, 70, 106, 187, 235, 216, 20,
				44, 196, 114, 249, 59, 248, 199, 214, 2, 74, 62, 176, 227, 198, 91, 78, 128, 194,
				33, 245, 141, 248, 208, 66, 107, 233, 143, 243, 140, 24, 140, 164, 234, 190, 115,
				183, 233, 118, 226, 41, 35, 136, 96, 214, 171, 250, 88, 17, 202, 121, 150, 49, 68,
				103, 75, 47, 225, 177, 126, 116, 65, 69, 65, 232, 55, 98, 40, 117, 251, 61, 21,
				207, 162, 24, 10, 53, 170, 159, 254, 111, 253, 39, 153, 76, 64, 255, 150, 99, 36,
				146, 83, 198, 132, 236, 206, 1, 234, 135, 232, 15, 207, 196, 146, 194, 216, 208,
				199, 20, 163, 201, 112, 115, 114, 251, 13, 190, 244, 149, 147, 98, 9, 130, 128,
				238, 67, 55, 230, 174, 98, 52, 42, 13, 198, 143, 8, 59, 55, 139, 216, 27, 137, 242,
				201, 240, 4, 82, 178, 110, 167, 23, 201, 112, 74, 26, 109, 9, 65, 213, 243, 64,
				176, 52, 76, 96, 183,
			],
		},
	);
	gen.with_reward(output, kernel)
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::global;
	use crate::ser::{self, ProtocolVersion};
	use util::ToHex;

	#[test]
	fn floonet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let gen_hash = genesis_floo().hash();
		println!("floonet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_floo(), ProtocolVersion(1)).unwrap();
		println!("floonet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"569ed9e4a5463896190447e6ffe37c394c4d77ce470aa29ad762e0286b896832"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"d76bd125d72d9c37b4a549f1840ccef79f461f59ff170f8e9fab93b36422658f"
		);
	}

	#[test]
	fn mainnet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let gen_hash = genesis_main().hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_main(), ProtocolVersion(1)).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"569ed9e4a5463896190447e6ffe37c394c4d77ce470aa29ad762e0286b896832"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"7c4e3988a5df6a4d76cd6a65306bbc4989a76b4b9ab1767796e03d305fe90030"
		);
	}
}
