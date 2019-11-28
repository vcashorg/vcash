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

//! Transactions

use crate::core::hash::{self, DefaultHashable, Hashed};
use crate::core::verifier_cache::VerifierCache;
use crate::core::{committed, Committed};
use crate::libtx::secp_ser;
use crate::ser::{
	self, read_multi, FixedLength, PMMRable, ProtocolVersion, Readable, Reader,
	VerifySortedAndUnique, Writeable, Writer,
};
use crate::{consensus, global};
use enum_primitive::FromPrimitive;
use keychain::{self, BlindingFactor};
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::sync::Arc;
use std::{error, fmt};
use util;
use util::secp;
use util::secp::pedersen::{Commitment, RangeProof};
use util::static_secp_instance;
use util::RwLock;

use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};
use util::secp::constants::MAX_PROOF_SIZE;

/// TokenKey can uniquely identify a token
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct TokenKey(hash::Hash);

impl TokenKey {
	/// create a new token key
	pub fn new_token_key() -> TokenKey {
		let mut ret = [0u8; 32];
		let mut rng = thread_rng();
		rng.fill(&mut ret);
		TokenKey(hash::Hash::from_vec(&ret))
	}

	/// create a token key with ZERO_HASH
	pub fn new_zero_key() -> TokenKey {
		TokenKey(hash::ZERO_HASH)
	}

	/// Convert hex string back to TokenKey.
	pub fn from_hex(hex: &str) -> Result<TokenKey, Error> {
		let data = hash::Hash::from_hex(hex)?;
		Ok(TokenKey(data))
	}

	/// Convert a TokenKey to hex string format.
	pub fn to_hex(&self) -> String {
		self.0.to_hex()
	}
}

impl DefaultHashable for TokenKey {}

impl Writeable for TokenKey {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.0.write(writer)?;
		Ok(())
	}
}

impl Readable for TokenKey {
	fn read(reader: &mut dyn Reader) -> Result<TokenKey, ser::Error> {
		let data = hash::Hash::read(reader)?;
		Ok(TokenKey(data))
	}
}

impl AsRef<[u8]> for TokenKey {
	fn as_ref(&self) -> &[u8] {
		&self.0.as_ref()
	}
}

impl fmt::Display for TokenKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl serde::ser::Serialize for TokenKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> serde::de::Deserialize<'de> for TokenKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		deserializer.deserialize_str(TokenKeyVisitor)
	}
}

struct TokenKeyVisitor;

impl<'de> serde::de::Visitor<'de> for TokenKeyVisitor {
	type Value = TokenKey;

	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("a token type")
	}

	fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
	where
		E: serde::de::Error,
	{
		Ok(TokenKey::from_hex(v).map_err(serde::de::Error::custom)?)
	}
}

/// Various tx kernel variants.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KernelFeatures {
	/// Plain kernel (the default for Grin txs).
	Plain {
		/// Plain kernels have fees.
		fee: u64,
	},
	/// A coinbase kernel.
	Coinbase,
	/// A kernel with an explicit lock height (and fee).
	HeightLocked {
		/// Height locked kernels have fees.
		fee: u64,
		/// Height locked kernels have lock heights.
		lock_height: u64,
	},
}

impl KernelFeatures {
	const PLAIN_U8: u8 = 0;
	const COINBASE_U8: u8 = 1;
	const HEIGHT_LOCKED_U8: u8 = 2;

	/// Underlying (u8) value representing this kernel variant.
	/// This is the first byte when we serialize/deserialize the kernel features.
	pub fn as_u8(&self) -> u8 {
		match self {
			KernelFeatures::Plain { .. } => KernelFeatures::PLAIN_U8,
			KernelFeatures::Coinbase => KernelFeatures::COINBASE_U8,
			KernelFeatures::HeightLocked { .. } => KernelFeatures::HEIGHT_LOCKED_U8,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			KernelFeatures::Plain { .. } => String::from("Plain"),
			KernelFeatures::Coinbase => String::from("Coinbase"),
			KernelFeatures::HeightLocked { .. } => String::from("HeightLocked"),
		}
	}

	/// msg = hash(features)                       for coinbase kernels
	///       hash(features || fee)                for plain kernels
	///       hash(features || fee || lock_height) for height locked kernels
	pub fn kernel_sig_msg(&self) -> Result<secp::Message, Error> {
		let x = self.as_u8();
		let hash = match self {
			KernelFeatures::Plain { fee } => (x, fee).hash(),
			KernelFeatures::Coinbase => (x).hash(),
			KernelFeatures::HeightLocked { fee, lock_height } => (x, fee, lock_height).hash(),
		};

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}

	/// Write tx kernel features out in v1 protocol format.
	/// Always include the fee and lock_height, writing 0 value if unused.
	fn write_v1<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let (fee, lock_height) = match self {
			KernelFeatures::Plain { fee } => (*fee, 0),
			KernelFeatures::Coinbase => (0, 0),
			KernelFeatures::HeightLocked { fee, lock_height } => (*fee, *lock_height),
		};
		writer.write_u8(self.as_u8())?;
		writer.write_u64(fee)?;
		writer.write_u64(lock_height)?;
		Ok(())
	}

	/// Write tx kernel features out in v2 protocol format.
	/// These are variable sized based on feature variant.
	/// Only write fee out for feature variants that support it.
	/// Only write lock_height out for feature variants that support it.
	fn write_v2<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			KernelFeatures::Plain { fee } => {
				writer.write_u8(self.as_u8())?;
				writer.write_u64(*fee)?;
			}
			KernelFeatures::Coinbase => {
				writer.write_u8(self.as_u8())?;
			}
			KernelFeatures::HeightLocked { fee, lock_height } => {
				writer.write_u8(self.as_u8())?;
				writer.write_u64(*fee)?;
				writer.write_u64(*lock_height)?;
			}
		}
		Ok(())
	}

	// Always read feature byte, 8 bytes for fee and 8 bytes for lock height.
	// Fee and lock height may be unused for some kernel variants but we need
	// to read these bytes and verify they are 0 if unused.
	fn read_v1(reader: &mut dyn Reader) -> Result<KernelFeatures, ser::Error> {
		let feature_byte = reader.read_u8()?;
		let fee = reader.read_u64()?;
		let lock_height = reader.read_u64()?;

		let features = match feature_byte {
			KernelFeatures::PLAIN_U8 => {
				if lock_height != 0 {
					return Err(ser::Error::CorruptedData);
				}
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => {
				if fee != 0 {
					return Err(ser::Error::CorruptedData);
				}
				if lock_height != 0 {
					return Err(ser::Error::CorruptedData);
				}
				KernelFeatures::Coinbase
			}
			KernelFeatures::HEIGHT_LOCKED_U8 => KernelFeatures::HeightLocked { fee, lock_height },
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(features)
	}

	// V2 kernels only expect bytes specific to each variant.
	// Coinbase kernels have no associated fee and we do not serialize a fee for these.
	fn read_v2(reader: &mut dyn Reader) -> Result<KernelFeatures, ser::Error> {
		let features = match reader.read_u8()? {
			KernelFeatures::PLAIN_U8 => {
				let fee = reader.read_u64()?;
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => KernelFeatures::Coinbase,
			KernelFeatures::HEIGHT_LOCKED_U8 => {
				let fee = reader.read_u64()?;
				let lock_height = reader.read_u64()?;
				KernelFeatures::HeightLocked { fee, lock_height }
			}
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(features)
	}
}

impl Writeable for KernelFeatures {
	/// Protocol version may increment rapidly for other unrelated changes.
	/// So we match on ranges here and not specific version values.
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// Care must be exercised when writing for hashing purposes.
		// All kernels are hashed using original v1 serialization strategy.
		if writer.serialization_mode() == ser::SerializationMode::Hash {
			return self.write_v1(writer);
		}

		match writer.protocol_version().value() {
			0..=1 => self.write_v1(writer),
			2..=ProtocolVersion::MAX => self.write_v2(writer),
		}
	}
}

impl Readable for KernelFeatures {
	fn read(reader: &mut dyn Reader) -> Result<KernelFeatures, ser::Error> {
		match reader.protocol_version().value() {
			0..=1 => KernelFeatures::read_v1(reader),
			2..=ProtocolVersion::MAX => KernelFeatures::read_v2(reader),
		}
	}
}

/// Various tx token kernel variants.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TokenKernelFeatures {
	/// token Plain kernel (the default for Grin txs).
	PlainToken,
	/// A issue token kernel.
	IssueToken,
	/// A token kernel with an explicit lock height.
	HeightLockedToken {
		/// Height locked kernels have lock heights.
		lock_height: u64,
	},
}

impl TokenKernelFeatures {
	const PLAIN_TOKEN_U8: u8 = 0;
	const ISSUE_TOKEN_U8: u8 = 1;
	const HEIGHT_LOCKED_U8: u8 = 2;

	/// Underlying (u8) value representing this kernel variant.
	/// This is the first byte when we serialize/deserialize the kernel features.
	pub fn as_u8(&self) -> u8 {
		match self {
			TokenKernelFeatures::PlainToken { .. } => TokenKernelFeatures::PLAIN_TOKEN_U8,
			TokenKernelFeatures::IssueToken => TokenKernelFeatures::ISSUE_TOKEN_U8,
			TokenKernelFeatures::HeightLockedToken { .. } => TokenKernelFeatures::HEIGHT_LOCKED_U8,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			TokenKernelFeatures::PlainToken { .. } => String::from("PlainToken"),
			TokenKernelFeatures::IssueToken => String::from("IssueToken"),
			TokenKernelFeatures::HeightLockedToken { .. } => String::from("HeightLockedToken"),
		}
	}

	/// Construct token msg from token_type and token kernel features.
	pub fn token_kernel_sig_msg(&self, token_type: TokenKey) -> Result<secp::Message, Error> {
		let x = self.as_u8();
		let hash = match self {
			TokenKernelFeatures::HeightLockedToken { lock_height } => {
				(x, token_type, lock_height).hash()
			}
			_ => (x, token_type).hash(),
		};

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}
}

impl Writeable for TokenKernelFeatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			TokenKernelFeatures::HeightLockedToken { lock_height } => {
				writer.write_u8(self.as_u8())?;
				writer.write_u64(*lock_height)?;
			}
			_ => {
				writer.write_u8(self.as_u8())?;
			}
		}
		Ok(())
	}
}

impl Readable for TokenKernelFeatures {
	fn read(reader: &mut dyn Reader) -> Result<TokenKernelFeatures, ser::Error> {
		let features = match reader.read_u8()? {
			TokenKernelFeatures::PLAIN_TOKEN_U8 => TokenKernelFeatures::PlainToken,
			TokenKernelFeatures::ISSUE_TOKEN_U8 => TokenKernelFeatures::IssueToken,
			TokenKernelFeatures::HEIGHT_LOCKED_U8 => {
				let lock_height = reader.read_u64()?;
				TokenKernelFeatures::HeightLockedToken { lock_height }
			}
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(features)
	}
}

/// Errors thrown by Transaction validation
#[derive(Clone, Eq, Debug, PartialEq, Serialize, Deserialize)]
pub enum Error {
	/// Underlying Secp256k1 error (signature validation or invalid public key
	/// typically)
	Secp(secp::Error),
	/// Underlying keychain related error
	Keychain(keychain::Error),
	/// The sum of output minus input commitments does not
	/// match the sum of kernel commitments
	KernelSumMismatch,
	/// Restrict tx total weight.
	TooHeavy,
	/// Error originating from an invalid lock-height
	LockHeight(u64),
	/// Range proof validation error
	RangeProof,
	/// Error originating from an invalid Merkle proof
	MerkleProof,
	/// Returns if the value hidden within the a RangeProof message isn't
	/// repeated 3 times, indicating it's incorrect
	InvalidProofMessage,
	/// Error when verifying kernel sums via committed trait.
	Committed(committed::Error),
	/// Error when sums do not verify correctly during tx aggregation.
	/// Likely a "double spend" across two unconfirmed txs.
	AggregationError,
	/// Validation error relating to cut-through (tx is spending its own
	/// output).
	CutThrough,
	/// Validation error relating to output features.
	/// It is invalid for a transaction to contain a coinbase output, for example.
	InvalidOutputFeatures,
	/// Validation error relating to kernel features.
	/// It is invalid for a transaction to contain a coinbase kernel, for example.
	InvalidKernelFeatures,
	/// Validation error relating to token kernel features.
	/// It is invalid for a token transaction to contain a coinbase kernel, for example.
	InvalidTokenKernelFeatures,
	/// Signature verification error.
	IncorrectSignature,
	/// Underlying serialization error.
	Serialization(ser::Error),
	/// TokenInput's token_type does not equal TokenOutput's token_type
	TokenTypeMismatch,
	/// Issue Token Key Repeated
	IssueTokenKeyRepeated,
	/// Issue Token tx outputs and kernel mismatch
	IssueTokenSumMismatch,
	/// Unreach Token Support Height
	UnreachTokenSupportHeight,
}

impl error::Error for Error {
	fn description(&self) -> &str {
		match *self {
			_ => "some kind of keychain error",
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			_ => write!(f, "some kind of keychain error"),
		}
	}
}

impl From<ser::Error> for Error {
	fn from(e: ser::Error) -> Error {
		Error::Serialization(e)
	}
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error::Keychain(e)
	}
}

impl From<committed::Error> for Error {
	fn from(e: committed::Error) -> Error {
		Error::Committed(e)
	}
}

/// A proof that a transaction sums to zero. Includes both the transaction's
/// Pedersen commitment and the signature, that guarantees that the commitments
/// amount to zero.
/// The signature signs the fee and the lock_height, which are retained for
/// signature validation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernel {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key (sum of the commitment public keys).
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::Signature,
}

impl DefaultHashable for TxKernel {}
hashable_ord!(TxKernel);

impl ::std::hash::Hash for TxKernel {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

impl Writeable for TxKernel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.excess.write(writer)?;
		self.excess_sig.write(writer)?;
		Ok(())
	}
}

impl Readable for TxKernel {
	fn read(reader: &mut dyn Reader) -> Result<TxKernel, ser::Error> {
		Ok(TxKernel {
			features: KernelFeatures::read(reader)?,
			excess: Commitment::read(reader)?,
			excess_sig: secp::Signature::read(reader)?,
		})
	}
}

/// We store kernels in the kernel MMR.
/// Note: These are "variable size" to support different kernel featuere variants.
impl PMMRable for TxKernel {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

/// Kernels are "variable size" but we need to implement FixedLength for legacy reasons.
/// At some point we will refactor the MMR backend so this is no longer required.
impl FixedLength for TxKernel {
	const LEN: usize = 0;
}

impl KernelFeatures {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		match self {
			KernelFeatures::Coinbase => true,
			_ => false,
		}
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		match self {
			KernelFeatures::Plain { .. } => true,
			_ => false,
		}
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		match self {
			KernelFeatures::HeightLocked { .. } => true,
			_ => false,
		}
	}
}

impl TxKernel {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		self.features.is_height_locked()
	}

	/// Return the excess commitment for this tx_kernel.
	pub fn excess(&self) -> Commitment {
		self.excess
	}

	/// The msg signed as part of the tx kernel.
	/// Based on kernel features and associated fields (fee and lock_height).
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.features.kernel_sig_msg()?;
		Ok(msg)
	}

	/// Verify the transaction proof validity. Entails handling the commitment
	/// as a public key and checking the signature verifies with the fee as
	/// message.
	pub fn verify(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let sig = &self.excess_sig;
		// Verify aggsig directly in libsecp
		let pubkey = &self.excess.to_pubkey(&secp)?;
		if !secp::aggsig::verify_single(
			&secp,
			&sig,
			&self.msg_to_sign()?,
			None,
			&pubkey,
			Some(&pubkey),
			None,
			false,
		) {
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(tx_kernels: &Vec<TxKernel>) -> Result<(), Error> {
		let len = tx_kernels.len();
		let mut sigs: Vec<secp::Signature> = Vec::with_capacity(len);
		let mut pubkeys: Vec<secp::key::PublicKey> = Vec::with_capacity(len);
		let mut msgs: Vec<secp::Message> = Vec::with_capacity(len);

		let secp = static_secp_instance();
		let secp = secp.lock();

		for tx_kernel in tx_kernels {
			sigs.push(tx_kernel.excess_sig);
			pubkeys.push(tx_kernel.excess.to_pubkey(&secp)?);
			msgs.push(tx_kernel.msg_to_sign()?);
		}

		if !secp::aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}

	/// Build an empty tx kernel with zero values.
	pub fn empty() -> TxKernel {
		TxKernel::with_features(KernelFeatures::Plain { fee: 0 })
	}

	/// Build an empty tx kernel with the provided kernel features.
	pub fn with_features(features: KernelFeatures) -> TxKernel {
		TxKernel {
			features,
			excess: Commitment::from_vec(vec![0; 33]),
			excess_sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		}
	}
}

/// A proof that a transaction sums to zero. Includes both the transaction's
/// Pedersen commitment and the signature, that guarantees that the commitments
/// amount to zero.
/// The signature signs the fee and the lock_height, which are retained for
/// signature validation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenTxKernel {
	/// Options for a kernel's structure or use
	pub features: TokenKernelFeatures,
	/// Token type
	pub token_type: TokenKey,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::Signature,
}

impl DefaultHashable for TokenTxKernel {}
hashable_ord!(TokenTxKernel);

impl ::std::hash::Hash for TokenTxKernel {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

impl Writeable for TokenTxKernel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.token_type.write(writer)?;
		self.excess.write(writer)?;
		self.excess_sig.write(writer)?;
		Ok(())
	}
}

impl Readable for TokenTxKernel {
	fn read(reader: &mut dyn Reader) -> Result<TokenTxKernel, ser::Error> {
		Ok(TokenTxKernel {
			features: TokenKernelFeatures::read(reader)?,
			token_type: TokenKey::read(reader)?,
			excess: Commitment::read(reader)?,
			excess_sig: secp::Signature::read(reader)?,
		})
	}
}

/// We store TokenTxKernel in the token kernel MMR.
impl PMMRable for TokenTxKernel {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

/// Kernels are "variable size" but we need to implement FixedLength for legacy reasons.
/// At some point we will refactor the MMR backend so this is no longer required.
impl FixedLength for TokenTxKernel {
	const LEN: usize = 0;
}

impl TokenKernelFeatures {
	/// Is this a issue token kernel?
	pub fn is_issue_token(&self) -> bool {
		match self {
			TokenKernelFeatures::IssueToken => true,
			_ => false,
		}
	}

	/// Is this a plain token kernel?
	pub fn is_plain_token(&self) -> bool {
		match self {
			TokenKernelFeatures::PlainToken { .. } => true,
			_ => false,
		}
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		match self {
			TokenKernelFeatures::HeightLockedToken { .. } => true,
			_ => false,
		}
	}
}

impl TokenTxKernel {
	/// Is this a coinbase kernel?
	pub fn is_issue_token(&self) -> bool {
		self.features.is_issue_token()
	}

	/// Is this a plain kernel?
	pub fn is_plain_token(&self) -> bool {
		self.features.is_plain_token()
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		self.features.is_height_locked()
	}

	/// Return the excess commitment for this tx_kernel.
	pub fn excess(&self) -> Commitment {
		self.excess
	}

	/// The msg signed as part of the tx kernel.
	/// Consists of the fee and the lock_height.
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self
			.features
			.token_kernel_sig_msg(self.token_type.clone())?;
		Ok(msg)
	}

	/// Verify the transaction proof validity. Entails handling the commitment
	/// as a public key and checking the signature verifies with the fee as
	/// message.
	pub fn verify(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let sig = &self.excess_sig;
		// Verify aggsig directly in libsecp
		let pubkey = &self.excess.to_pubkey(&secp)?;
		if !secp::aggsig::verify_single(
			&secp,
			&sig,
			&self.msg_to_sign()?,
			None,
			&pubkey,
			Some(&pubkey),
			None,
			false,
		) {
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(tx_kernels: &Vec<TokenTxKernel>) -> Result<(), Error> {
		let len = tx_kernels.len();
		let mut sigs: Vec<secp::Signature> = Vec::with_capacity(len);
		let mut pubkeys: Vec<secp::key::PublicKey> = Vec::with_capacity(len);
		let mut msgs: Vec<secp::Message> = Vec::with_capacity(len);

		let secp = static_secp_instance();
		let secp = secp.lock();

		for tx_kernel in tx_kernels {
			sigs.push(tx_kernel.excess_sig);
			pubkeys.push(tx_kernel.excess.to_pubkey(&secp)?);
			msgs.push(tx_kernel.msg_to_sign()?);
		}

		if !secp::aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}

	/// Build an empty tx kernel with zero values.
	pub fn empty() -> TokenTxKernel {
		TokenTxKernel {
			features: TokenKernelFeatures::IssueToken,
			token_type: TokenKey::new_zero_key(),
			excess: Commitment::from_vec(vec![0; 33]),
			excess_sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		}
	}

	/// Build an empty tx kernel with the provided kernel features.
	pub fn with_features(features: TokenKernelFeatures) -> TokenTxKernel {
		TokenTxKernel {
			features,
			token_type: TokenKey::new_zero_key(),
			excess: Commitment::from_vec(vec![0; 33]),
			excess_sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		}
	}

	/// is a TokenTxKernel for zero key
	pub fn is_empty(&self) -> bool {
		self.token_type == TokenKey::new_zero_key()
	}

	/// Builds a new tx kernel with the provided fee.
	pub fn with_token_type(self, token_type: TokenKey) -> TokenTxKernel {
		TokenTxKernel { token_type, ..self }
	}
}

/// Enum of possible tx weight verification options -
///
/// * As "transaction" checks tx (as block) weight does not exceed max_block_weight.
/// * As "block" same as above but allow for additional coinbase reward (1 output, 1 kernel).
/// * With "no limit" to skip the weight check.
///
#[derive(Clone, Copy)]
pub enum Weighting {
	/// Tx represents a tx (max block weight, accounting for additional coinbase reward).
	AsTransaction,
	/// Tx representing a tx with artificially limited max_weight.
	/// This is used when selecting mineable txs from the pool.
	AsLimitedTransaction(usize),
	/// Tx represents a block (max block weight).
	AsBlock,
	/// No max weight limit (skip the weight check).
	NoLimit,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBody {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<Input>,
	/// List of token inputs spent by the transaction.
	pub token_inputs: Vec<TokenInput>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<Output>,
	/// List of token outputs the transaction produces.
	pub token_outputs: Vec<TokenOutput>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernel>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub token_kernels: Vec<TokenTxKernel>,
}

/// PartialEq
impl PartialEq for TransactionBody {
	fn eq(&self, l: &TransactionBody) -> bool {
		self.inputs == l.inputs
			&& self.token_inputs == l.token_inputs
			&& self.outputs == l.outputs
			&& self.token_outputs == l.token_outputs
			&& self.kernels == l.kernels
			&& self.token_kernels == l.token_kernels
	}
}

/// Implementation of Writeable for a body, defines how to
/// write the body as binary.
impl Writeable for TransactionBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match writer.protocol_version().value() {
			0..=1 => self.write_v1(writer),
			2..=ProtocolVersion::MAX => self.write_v2(writer),
		}
	}
}

/// Implementation of Readable for a body, defines how to read a
/// body from a binary stream.
impl Readable for TransactionBody {
	fn read(reader: &mut dyn Reader) -> Result<TransactionBody, ser::Error> {
		match reader.protocol_version().value() {
			0..=1 => TransactionBody::read_v1(reader),
			2..=ProtocolVersion::MAX => TransactionBody::read_v2(reader),
		}
	}
}

impl Committed for TransactionBody {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.inputs.iter().map(|x| x.commitment()).collect()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.outputs.iter().map(|x| x.commitment()).collect()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.kernels.iter().map(|x| x.excess()).collect()
	}

	fn token_inputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_inputs_map: HashMap<TokenKey, Vec<Commitment>> = HashMap::new();
		for token_input in self.token_inputs.iter() {
			let commit_vec = token_inputs_map
				.entry(token_input.token_type)
				.or_insert(vec![]);
			commit_vec.push(token_input.commit);
		}

		token_inputs_map
	}

	fn token_outputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_outputs_map: HashMap<TokenKey, Vec<Commitment>> = HashMap::new();
		for token_output in self.token_outputs.iter() {
			if token_output.is_token() {
				let commit_vec = token_outputs_map
					.entry(token_output.token_type)
					.or_insert(vec![]);
				commit_vec.push(token_output.commit);
			}
		}

		token_outputs_map
	}

	fn token_kernels_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		let mut token_kernels_map: HashMap<TokenKey, Vec<Commitment>> = HashMap::new();
		for token_kernel in self.token_kernels.iter() {
			if token_kernel.is_plain_token() {
				let commit_vec = token_kernels_map
					.entry(token_kernel.token_type)
					.or_insert(vec![]);
				commit_vec.push(token_kernel.excess());
			}
		}

		token_kernels_map
	}
}

impl Default for TransactionBody {
	fn default() -> TransactionBody {
		TransactionBody::empty()
	}
}

impl TransactionBody {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionBody {
		TransactionBody {
			inputs: vec![],
			token_inputs: vec![],
			outputs: vec![],
			token_outputs: vec![],
			kernels: vec![],
			token_kernels: vec![],
		}
	}

	fn write_v1<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(
			writer,
			[write_u64, self.inputs.len() as u64],
			[write_u64, self.outputs.len() as u64],
			[write_u64, self.kernels.len() as u64]
		);

		self.inputs.write(writer)?;
		self.outputs.write(writer)?;
		self.kernels.write(writer)?;

		Ok(())
	}

	fn write_v2<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(
			writer,
			[write_u64, self.inputs.len() as u64],
			[write_u64, self.token_inputs.len() as u64],
			[write_u64, self.outputs.len() as u64],
			[write_u64, self.token_outputs.len() as u64],
			[write_u64, self.kernels.len() as u64],
			[write_u64, self.token_kernels.len() as u64]
		);

		self.inputs.write(writer)?;
		self.token_inputs.write(writer)?;
		self.outputs.write(writer)?;
		self.token_outputs.write(writer)?;
		self.kernels.write(writer)?;
		self.token_kernels.write(writer)?;

		Ok(())
	}

	fn read_v1(reader: &mut dyn Reader) -> Result<TransactionBody, ser::Error> {
		let (input_len, output_len, kernel_len) =
			ser_multiread!(reader, read_u64, read_u64, read_u64);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBody::weight_as_block(
			input_len as usize,
			output_len as usize,
			kernel_len as usize,
			0,
			0,
			0,
		);

		if tx_block_weight > global::max_block_weight() {
			return Err(ser::Error::TooLargeReadErr);
		}

		let inputs = read_multi(reader, input_len)?;
		let outputs = read_multi(reader, output_len)?;
		let kernels = read_multi(reader, kernel_len)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBody::init(inputs, outputs, kernels, vec![], vec![], vec![], true)
			.map_err(|_| ser::Error::CorruptedData)?;

		Ok(body)
	}

	fn read_v2(reader: &mut dyn Reader) -> Result<TransactionBody, ser::Error> {
		let (
			input_len,
			token_input_len,
			output_len,
			token_output_len,
			kernel_len,
			token_kernel_len,
		) = ser_multiread!(reader, read_u64, read_u64, read_u64, read_u64, read_u64, read_u64);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBody::weight_as_block(
			input_len as usize,
			output_len as usize,
			kernel_len as usize,
			token_input_len as usize,
			token_output_len as usize,
			token_kernel_len as usize,
		);

		if tx_block_weight > global::max_block_weight() {
			return Err(ser::Error::TooLargeReadErr);
		}

		let inputs = read_multi(reader, input_len)?;
		let token_inputs = read_multi(reader, token_input_len)?;
		let outputs = read_multi(reader, output_len)?;
		let token_outputs = read_multi(reader, token_output_len)?;
		let kernels = read_multi(reader, kernel_len)?;
		let token_kernels = read_multi(reader, token_kernel_len)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBody::init(
			inputs,
			outputs,
			kernels,
			token_inputs,
			token_outputs,
			token_kernels,
			true,
		)
		.map_err(|_| ser::Error::CorruptedData)?;

		Ok(body)
	}

	/// Sort the inputs|outputs|kernels.
	pub fn sort(&mut self) {
		self.inputs.sort_unstable();
		self.token_inputs.sort_unstable();
		self.outputs.sort_unstable();
		self.token_outputs.sort_unstable();
		self.kernels.sort_unstable();
		self.token_kernels.sort_unstable();
	}

	/// Creates a new transaction body initialized with
	/// the provided inputs, outputs and kernels.
	/// Guarantees inputs, outputs, kernels are sorted lexicographically.
	pub fn init(
		inputs: Vec<Input>,
		outputs: Vec<Output>,
		kernels: Vec<TxKernel>,
		token_inputs: Vec<TokenInput>,
		token_outputs: Vec<TokenOutput>,
		token_kernels: Vec<TokenTxKernel>,
		verify_sorted: bool,
	) -> Result<TransactionBody, Error> {
		let mut body = TransactionBody {
			inputs,
			token_inputs,
			outputs,
			token_outputs,
			kernels,
			token_kernels,
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted()?;
		} else {
			// If we are not verifying sort order then sort in place and return.
			body.sort();
		}
		Ok(body)
	}

	/// Builds a new body with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(mut self, input: Input) -> TransactionBody {
		self.inputs
			.binary_search(&input)
			.err()
			.map(|e| self.inputs.insert(e, input));
		self
	}

	/// Builds a new TransactionBody with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(mut self, output: Output) -> TransactionBody {
		self.outputs
			.binary_search(&output)
			.err()
			.map(|e| self.outputs.insert(e, output));
		self
	}

	/// Builds a new body with the provided token inputs added. Existing
	/// token inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_input(mut self, input: TokenInput) -> TransactionBody {
		self.token_inputs
			.binary_search(&input)
			.err()
			.map(|e| self.token_inputs.insert(e, input));
		self
	}

	/// Builds a new TransactionBody with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_output(mut self, output: TokenOutput) -> TransactionBody {
		self.token_outputs
			.binary_search(&output)
			.err()
			.map(|e| self.token_outputs.insert(e, output));
		self
	}

	/// Builds a new TransactionBody with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		self.kernels
			.binary_search(&kernel)
			.err()
			.map(|e| self.kernels.insert(e, kernel));
		self
	}

	/// Builds a new TransactionBody replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		self.kernels.clear();
		self.kernels.push(kernel);
		self
	}

	/// Builds a new TransactionBody with the provided token kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_kernel(mut self, token_kernel: TokenTxKernel) -> TransactionBody {
		self.token_kernels
			.binary_search(&token_kernel)
			.err()
			.map(|e| self.token_kernels.insert(e, token_kernel));
		self
	}

	/// Builds a new TransactionBody replacing any existing token kernels with the provided token kernel.
	pub fn replace_token_kernel(mut self, kernel: TokenTxKernel) -> TransactionBody {
		self.token_kernels.clear();
		self.token_kernels.push(kernel);
		self
	}

	/// Total fee for a TransactionBody is the sum of fees of all fee carrying kernels.
	pub fn fee(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|k| match k.features {
				KernelFeatures::Coinbase => None,
				KernelFeatures::Plain { fee } | KernelFeatures::HeightLocked { fee, .. } => {
					Some(fee)
				}
			})
			.fold(0, |acc, fee| acc.saturating_add(fee))
	}

	fn overage(&self) -> i64 {
		self.fee() as i64
	}

	/// Calculate transaction weight
	pub fn body_weight(&self) -> usize {
		TransactionBody::weight(
			self.inputs.len(),
			self.outputs.len(),
			self.kernels.len(),
			self.token_inputs.len(),
			self.token_outputs.len(),
			self.token_kernels.len(),
		)
	}

	/// Calculate weight of transaction using block weighing
	pub fn body_weight_as_block(&self) -> usize {
		TransactionBody::weight_as_block(
			self.inputs.len(),
			self.outputs.len(),
			self.kernels.len(),
			self.token_inputs.len(),
			self.token_outputs.len(),
			self.token_kernels.len(),
		)
	}

	/// Calculate transaction weight from transaction details. This is non
	/// consensus critical and compared to block weight, incentivizes spending
	/// more outputs (to lower the fee).
	pub fn weight(
		input_len: usize,
		output_len: usize,
		kernel_len: usize,
		token_input_len: usize,
		token_output_len: usize,
		token_kernel_len: usize,
	) -> usize {
		let body_weight = output_len
			.saturating_mul(4)
			.saturating_add(kernel_len)
			.saturating_sub(input_len);
		let body_token_weight = token_output_len
			.saturating_mul(4)
			.saturating_add(token_kernel_len)
			.saturating_sub(token_input_len);
		max(body_weight + body_token_weight, 1)
	}

	/// Calculate transaction weight using block weighing from transaction
	/// details. Consensus critical and uses consensus weight values.
	pub fn weight_as_block(
		input_len: usize,
		output_len: usize,
		kernel_len: usize,
		token_input_len: usize,
		token_output_len: usize,
		token_kernel_len: usize,
	) -> usize {
		let weight = input_len
			.saturating_mul(consensus::BLOCK_INPUT_WEIGHT)
			.saturating_add(output_len.saturating_mul(consensus::BLOCK_OUTPUT_WEIGHT))
			.saturating_add(kernel_len.saturating_mul(consensus::BLOCK_KERNEL_WEIGHT));

		let token_weight = token_input_len
			.saturating_mul(consensus::BLOCK_INPUT_WEIGHT)
			.saturating_add(token_output_len.saturating_mul(consensus::BLOCK_OUTPUT_WEIGHT))
			.saturating_add(token_kernel_len.saturating_mul(consensus::BLOCK_KERNEL_WEIGHT));

		weight + token_weight
	}

	/// Lock height of a body is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		let kernel_height = self
			.kernels
			.iter()
			.filter_map(|x| match x.features {
				KernelFeatures::HeightLocked { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0);

		let token_kernel_height = self
			.token_kernels
			.iter()
			.filter_map(|x| match x.features {
				TokenKernelFeatures::HeightLockedToken { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0);

		if kernel_height > token_kernel_height {
			kernel_height
		} else {
			token_kernel_height
		}
	}

	/// Verify the body is not too big in terms of number of inputs|outputs|kernels.
	/// Weight rules vary depending on the "weight type" (block or tx or pool).
	fn verify_weight(&self, weighting: Weighting) -> Result<(), Error> {
		// A coinbase reward is a single output and a single kernel (for now).
		// We need to account for this when verifying max tx weights.
		let coinbase_weight = consensus::BLOCK_OUTPUT_WEIGHT + consensus::BLOCK_KERNEL_WEIGHT;

		// If "tx" body then remember to reduce the max_block_weight by the weight of a kernel.
		// If "limited tx" then compare against the provided max_weight.
		// If "block" body then verify weight based on full set of inputs|outputs|kernels.
		// If "pool" body then skip weight verification (pool can be larger than single block).
		//
		// Note: Taking a max tx and building a block from it we need to allow room
		// for the additional coinbase reward (1 output + 1 kernel).
		//
		let max_weight = match weighting {
			Weighting::AsTransaction => global::max_block_weight().saturating_sub(coinbase_weight),
			Weighting::AsLimitedTransaction(max_weight) => {
				min(global::max_block_weight(), max_weight).saturating_sub(coinbase_weight)
			}
			Weighting::AsBlock => global::max_block_weight(),
			Weighting::NoLimit => {
				// We do not verify "tx as pool" weight so we are done here.
				return Ok(());
			}
		};

		if self.body_weight_as_block() > max_weight {
			return Err(Error::TooHeavy);
		}
		Ok(())
	}

	// Verify that inputs|outputs|kernels are sorted in lexicographical order
	// and that there are no duplicates (they are all unique within this transaction).
	fn verify_sorted(&self) -> Result<(), Error> {
		self.inputs.verify_sorted_and_unique()?;
		self.token_inputs.verify_sorted_and_unique()?;
		self.outputs.verify_sorted_and_unique()?;
		self.token_outputs.verify_sorted_and_unique()?;
		self.kernels.verify_sorted_and_unique()?;
		self.token_kernels.verify_sorted_and_unique()?;
		Ok(())
	}

	// Verify that no input is spending an output from the same block.
	// Assumes inputs and outputs are sorted
	fn verify_cut_through(&self) -> Result<(), Error> {
		let mut inputs = self.inputs.iter().map(|x| x.hash()).peekable();
		let mut outputs = self.outputs.iter().map(|x| x.hash()).peekable();
		while let (Some(ih), Some(oh)) = (inputs.peek(), outputs.peek()) {
			match ih.cmp(oh) {
				Ordering::Less => {
					inputs.next();
				}
				Ordering::Greater => {
					outputs.next();
				}
				Ordering::Equal => {
					return Err(Error::CutThrough);
				}
			}
		}
		Ok(())
	}

	/// Verify we have no invalid outputs or kernels in the transaction
	/// due to invalid features.
	/// Specifically, a transaction cannot contain a coinbase output or a coinbase kernel.
	pub fn verify_features(&self) -> Result<(), Error> {
		self.verify_output_features()?;
		self.verify_token_input_features()?;
		self.verify_token_output_features()?;
		self.verify_kernel_features()?;
		Ok(())
	}

	// Verify we have no outputs tagged as COINBASE.
	fn verify_output_features(&self) -> Result<(), Error> {
		if self.outputs.iter().any(|x| !x.is_plain()) {
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify token_inputs tagged as Token.
	fn verify_token_input_features(&self) -> Result<(), Error> {
		if self
			.token_inputs
			.iter()
			.any(|x| !x.is_token() && !x.is_tokenissue())
		{
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify we have no token_outputs tagged as Plain or COINBASE.
	fn verify_token_output_features(&self) -> Result<(), Error> {
		if self
			.token_outputs
			.iter()
			.any(|x| !x.is_token() && !x.is_tokenissue())
		{
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify we have no kernels tagged as COINBASE.
	fn verify_kernel_features(&self) -> Result<(), Error> {
		if self.kernels.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidKernelFeatures);
		}
		Ok(())
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		self.verify_weight(weighting)?;
		self.verify_sorted()?;
		self.verify_cut_through()?;
		Ok(())
	}

	/// Validate the issue token outputs and kernel
	pub fn validate_issue_token_output(&self) -> Result<(), Error> {
		let mut output_token_key_set: HashSet<TokenKey> = HashSet::new();
		if !self
			.token_outputs
			.iter()
			.filter(|x| x.is_tokenissue())
			.all(|x| output_token_key_set.insert(x.token_type))
		{
			return Err(Error::IssueTokenKeyRepeated);
		}

		let mut kernel_token_key_set: HashSet<TokenKey> = HashSet::new();
		if !self
			.token_kernels
			.iter()
			.filter(|x| x.is_issue_token())
			.all(|x| kernel_token_key_set.insert(x.token_type))
		{
			return Err(Error::IssueTokenKeyRepeated);
		}

		if output_token_key_set.len() != kernel_token_key_set.len() {
			return Err(Error::IssueTokenSumMismatch);
		}

		for token_type in output_token_key_set.iter() {
			if !kernel_token_key_set.contains(token_type) {
				return Err(Error::IssueTokenSumMismatch);
			}
		}

		Ok(())
	}

	/// Validate chain height reaches support_token_height
	pub fn validate_token_height(&self, height: u64) -> Result<(), Error> {
		if height < global::support_token_height() && self.token_kernels.len() > 0 {
			return Err(Error::UnreachTokenSupportHeight);
		}

		Ok(())
	}

	/// Validates all relevant parts of a transaction body. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		self.validate_read(weighting)?;

		self.validate_issue_token_output()?;

		// Find all the outputs that have not had their rangeproofs verified.
		let outputs = {
			let mut verifier = verifier.write();
			verifier.filter_rangeproof_unverified(&self.outputs)
		};

		// Now batch verify all those unverified rangeproofs
		if !outputs.is_empty() {
			let mut commits = vec![];
			let mut proofs = vec![];
			for x in &outputs {
				commits.push(x.commit);
				proofs.push(x.proof);
			}
			Output::batch_verify_proofs(&commits, &proofs)?;
		}

		// Find all the token_outputs that have not had their rangeproofs verified.
		let token_outputs = {
			let mut verifier = verifier.write();
			verifier.filter_token_rangeproof_unverified(&self.token_outputs)
		};

		// Now batch verify all those unverified rangeproofs
		if !token_outputs.is_empty() {
			let mut commits = vec![];
			let mut proofs = vec![];
			for x in &token_outputs {
				commits.push(x.commit);
				proofs.push(x.proof);
			}
			Output::batch_verify_proofs(&commits, &proofs)?;
		}

		// Find all the kernels that have not yet been verified.
		let kernels = {
			let mut verifier = verifier.write();
			verifier.filter_kernel_sig_unverified(&self.kernels)
		};

		// Verify the unverified tx kernels.
		TxKernel::batch_sig_verify(&kernels)?;

		// Find all the token kernels that have not yet been verified.
		let token_kernels = {
			let mut verifier = verifier.write();
			verifier.filter_token_kernel_sig_unverified(&self.token_kernels)
		};

		// Verify the unverified tx token kernels.
		TokenTxKernel::batch_sig_verify(&token_kernels)?;

		// Cache the successful verification results for the new outputs and kernels.
		{
			let mut verifier = verifier.write();
			verifier.add_rangeproof_verified(outputs);
			verifier.add_token_rangeproof_verified(token_outputs);
			verifier.add_kernel_sig_verified(kernels);
			verifier.add_token_kernel_sig_verified(token_kernels);
		}
		Ok(())
	}
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBody,
}

impl DefaultHashable for Transaction {}

/// PartialEq
impl PartialEq for Transaction {
	fn eq(&self, tx: &Transaction) -> bool {
		self.body == tx.body && self.offset == tx.offset
	}
}

impl Into<TransactionBody> for Transaction {
	fn into(self) -> TransactionBody {
		self.body
	}
}

/// Implementation of Writeable for a fully blinded transaction, defines how to
/// write the transaction as binary.
impl Writeable for Transaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.offset.write(writer)?;
		self.body.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction, defines how to read a full
/// transaction from a binary stream.
impl Readable for Transaction {
	fn read(reader: &mut dyn Reader) -> Result<Transaction, ser::Error> {
		let offset = BlindingFactor::read(reader)?;
		let body = TransactionBody::read(reader)?;
		let tx = Transaction { offset, body };

		// Now "lightweight" validation of the tx.
		// Treat any validation issues as data corruption.
		// An example of this would be reading a tx
		// that exceeded the allowed number of inputs.
		tx.validate_read().map_err(|_| ser::Error::CorruptedData)?;

		Ok(tx)
	}
}

impl Committed for Transaction {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.body.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.body.outputs_committed()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.body.kernels_committed()
	}

	fn token_inputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		self.body.token_inputs_committed()
	}

	fn token_outputs_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		self.body.token_outputs_committed()
	}

	fn token_kernels_committed(&self) -> HashMap<TokenKey, Vec<Commitment>> {
		self.body.token_kernels_committed()
	}
}

impl Default for Transaction {
	fn default() -> Transaction {
		Transaction::empty()
	}
}

impl Transaction {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> Transaction {
		Transaction {
			offset: BlindingFactor::zero(),
			body: Default::default(),
		}
	}

	/// Creates a new transaction initialized with
	/// the provided inputs, outputs, kernels
	pub fn new(
		inputs: Vec<Input>,
		outputs: Vec<Output>,
		token_inputs: Vec<TokenInput>,
		token_outputs: Vec<TokenOutput>,
		kernels: Vec<TxKernel>,
		token_kernels: Vec<TokenTxKernel>,
	) -> Transaction {
		let offset = BlindingFactor::zero();

		// Initialize a new tx body and sort everything.
		let body = TransactionBody::init(
			inputs,
			outputs,
			kernels,
			token_inputs,
			token_outputs,
			token_kernels,
			false,
		)
		.expect("sorting, not verifying");

		Transaction { offset, body }
	}

	/// Creates a new transaction using this transaction as a template
	/// and with the specified offset.
	pub fn with_offset(self, offset: BlindingFactor) -> Transaction {
		Transaction { offset, ..self }
	}

	/// Builds a new transaction with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(self, input: Input) -> Transaction {
		Transaction {
			body: self.body.with_input(input),
			..self
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> Transaction {
		Transaction {
			body: self.body.with_output(output),
			..self
		}
	}

	/// Builds a new transaction with the provided token inputs added. Existing
	/// token inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_input(self, input: TokenInput) -> Transaction {
		Transaction {
			body: self.body.with_token_input(input),
			..self
		}
	}

	/// Builds a new transaction with the provided token output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_output(self, output: TokenOutput) -> Transaction {
		Transaction {
			body: self.body.with_token_output(output),
			..self
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.with_kernel(kernel),
			..self
		}
	}

	/// Builds a new transaction replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.replace_kernel(kernel),
			..self
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_token_kernel(self, token_kernel: TokenTxKernel) -> Transaction {
		Transaction {
			body: self.body.with_token_kernel(token_kernel),
			..self
		}
	}

	/// Builds a new transaction replacing any existing kernels with the provided kernel.
	pub fn replace_token_kernel(self, token_kernel: TokenTxKernel) -> Transaction {
		Transaction {
			body: self.body.replace_token_kernel(token_kernel),
			..self
		}
	}

	/// Get inputs
	pub fn inputs(&self) -> &Vec<Input> {
		&self.body.inputs
	}

	/// Get inputs mutable
	pub fn inputs_mut(&mut self) -> &mut Vec<Input> {
		&mut self.body.inputs
	}

	/// Get outputs
	pub fn outputs(&self) -> &Vec<Output> {
		&self.body.outputs
	}

	/// Get outputs mutable
	pub fn outputs_mut(&mut self) -> &mut Vec<Output> {
		&mut self.body.outputs
	}

	/// Get inputs
	pub fn token_inputs(&self) -> &Vec<TokenInput> {
		&self.body.token_inputs
	}

	/// Get inputs mutable
	pub fn token_inputs_mut(&mut self) -> &mut Vec<TokenInput> {
		&mut self.body.token_inputs
	}

	/// Get outputs
	pub fn token_outputs(&self) -> &Vec<TokenOutput> {
		&self.body.token_outputs
	}

	/// Get outputs mutable
	pub fn token_outputs_mut(&mut self) -> &mut Vec<TokenOutput> {
		&mut self.body.token_outputs
	}

	/// Get kernels
	pub fn kernels(&self) -> &Vec<TxKernel> {
		&self.body.kernels
	}

	/// Get kernels mut
	pub fn kernels_mut(&mut self) -> &mut Vec<TxKernel> {
		&mut self.body.kernels
	}

	/// Get token kernels
	pub fn token_kernels(&self) -> &Vec<TokenTxKernel> {
		&self.body.token_kernels
	}

	/// Get token kernels mut
	pub fn token_kernels_mut(&mut self) -> &mut Vec<TokenTxKernel> {
		&mut self.body.token_kernels
	}

	/// Total fee for a transaction is the sum of fees of all kernels.
	pub fn fee(&self) -> u64 {
		self.body.fee()
	}

	/// Total overage across all kernels.
	pub fn overage(&self) -> i64 {
		self.body.overage()
	}

	/// Lock height of a transaction is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.body.lock_height()
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification (on the body)
	/// * kernel signature verification (on the body)
	/// * kernel sum verification
	pub fn validate_read(&self) -> Result<(), Error> {
		self.body.validate_read(Weighting::AsTransaction)?;
		self.body.verify_features()?;
		Ok(())
	}

	/// Validate chain height reaches support_token_height
	pub fn validate_token_height(&self, height: u64) -> Result<(), Error> {
		self.body.validate_token_height(height)
	}

	/// Validates all relevant parts of a fully built transaction. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		self.body.validate(weighting, verifier)?;
		self.body.verify_features()?;
		self.verify_kernel_sums(self.overage(), self.offset.clone())?;
		self.verify_token_kernel_sum()?;
		Ok(())
	}

	/// Can be used to compare txs by their fee/weight ratio.
	/// Don't use these values for anything else though due to precision multiplier.
	pub fn fee_to_weight(&self) -> u64 {
		self.fee() * 1_000 / self.tx_weight() as u64
	}

	/// Calculate transaction weight
	pub fn tx_weight(&self) -> usize {
		self.body.body_weight()
	}

	/// Calculate transaction weight as a block
	pub fn tx_weight_as_block(&self) -> usize {
		self.body.body_weight_as_block()
	}

	/// Calculate transaction weight from transaction details
	pub fn weight(
		input_len: usize,
		output_len: usize,
		kernel_len: usize,
		token_input_len: usize,
		token_output_len: usize,
		token_kernel_len: usize,
	) -> usize {
		TransactionBody::weight(
			input_len,
			output_len,
			kernel_len,
			token_input_len,
			token_output_len,
			token_kernel_len,
		)
	}
}

/// Matches any output with a potential spending input, eliminating them
/// from the Vec. Provides a simple way to cut-through a block or aggregated
/// transaction. The elimination is stable with respect to the order of inputs
/// and outputs.
pub fn cut_through(
	inputs: &mut Vec<Input>,
	outputs: &mut Vec<Output>,
	token_inputs: &mut Vec<TokenInput>,
	token_outputs: &mut Vec<TokenOutput>,
) -> Result<(), Error> {
	// assemble output commitments set, checking they're all unique
	outputs.sort_unstable();
	if outputs.windows(2).any(|pair| pair[0] == pair[1]) {
		return Err(Error::AggregationError);
	}
	inputs.sort_unstable();
	let mut inputs_idx = 0;
	let mut outputs_idx = 0;
	let mut ncut = 0;
	while inputs_idx < inputs.len() && outputs_idx < outputs.len() {
		match inputs[inputs_idx].hash().cmp(&outputs[outputs_idx].hash()) {
			Ordering::Less => {
				inputs[inputs_idx - ncut] = inputs[inputs_idx];
				inputs_idx += 1;
			}
			Ordering::Greater => {
				outputs[outputs_idx - ncut] = outputs[outputs_idx];
				outputs_idx += 1;
			}
			Ordering::Equal => {
				inputs_idx += 1;
				outputs_idx += 1;
				ncut += 1;
			}
		}
	}
	// Cut elements that have already been copied
	outputs.drain(outputs_idx - ncut..outputs_idx);
	inputs.drain(inputs_idx - ncut..inputs_idx);

	token_outputs.sort_unstable();
	if token_outputs.windows(2).any(|pair| pair[0] == pair[1]) {
		return Err(Error::AggregationError);
	}
	token_inputs.sort_unstable();
	let mut inputs_idx = 0;
	let mut outputs_idx = 0;
	let mut ncut = 0;
	while inputs_idx < token_inputs.len() && outputs_idx < token_outputs.len() {
		let token_input = token_inputs[inputs_idx];
		let token_output = token_outputs[outputs_idx];
		match token_input.hash().cmp(&token_output.hash()) {
			Ordering::Less => {
				token_inputs[inputs_idx - ncut] = token_input;
				inputs_idx += 1;
			}
			Ordering::Greater => {
				token_outputs[outputs_idx - ncut] = token_output;
				outputs_idx += 1;
			}
			Ordering::Equal => {
				inputs_idx += 1;
				outputs_idx += 1;
				ncut += 1;
				if token_input.token_type != token_output.token_type {
					return Err(Error::TokenTypeMismatch);
				}
			}
		}
	}
	// Cut elements that have already been copied
	token_outputs.drain(outputs_idx - ncut..outputs_idx);
	token_inputs.drain(inputs_idx - ncut..inputs_idx);

	Ok(())
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(mut txs: Vec<Transaction>) -> Result<Transaction, Error> {
	// convenience short-circuiting
	if txs.is_empty() {
		return Ok(Transaction::empty());
	} else if txs.len() == 1 {
		return Ok(txs.pop().unwrap());
	}
	let mut n_inputs = 0;
	let mut n_outputs = 0;
	let mut n_kernels = 0;
	let mut n_token_inputs = 0;
	let mut n_token_outputs = 0;
	let mut n_token_kernels = 0;
	for tx in txs.iter() {
		n_inputs += tx.body.inputs.len();
		n_outputs += tx.body.outputs.len();
		n_kernels += tx.body.kernels.len();
		n_token_inputs += tx.body.token_inputs.len();
		n_token_outputs += tx.body.token_outputs.len();
		n_token_kernels += tx.body.token_kernels.len();
	}

	let mut inputs: Vec<Input> = Vec::with_capacity(n_inputs);
	let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
	let mut kernels: Vec<TxKernel> = Vec::with_capacity(n_kernels);
	let mut token_inputs: Vec<TokenInput> = Vec::with_capacity(n_token_inputs);
	let mut token_outputs: Vec<TokenOutput> = Vec::with_capacity(n_token_outputs);
	let mut token_kernels: Vec<TokenTxKernel> = Vec::with_capacity(n_token_kernels);

	// we will sum these together at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets: Vec<BlindingFactor> = Vec::with_capacity(txs.len());
	for mut tx in txs {
		// we will sum these later to give a single aggregate offset
		kernel_offsets.push(tx.offset);

		inputs.append(&mut tx.body.inputs);
		outputs.append(&mut tx.body.outputs);
		kernels.append(&mut tx.body.kernels);
		token_inputs.append(&mut tx.body.token_inputs);
		token_outputs.append(&mut tx.body.token_outputs);
		token_kernels.append(&mut tx.body.token_kernels);
	}

	// Sort inputs and outputs during cut_through.
	cut_through(
		&mut inputs,
		&mut outputs,
		&mut token_inputs,
		&mut token_outputs,
	)?;

	// Now sort kernels.
	kernels.sort_unstable();
	token_kernels.sort_unstable();

	// now sum the kernel_offsets up to give us an aggregate offset for the
	// transaction
	let total_kernel_offset = committed::sum_kernel_offsets(kernel_offsets, vec![])?;

	// build a new aggregate tx from the following -
	//   * cut-through inputs
	//   * cut-through outputs
	//   * full set of tx kernels
	//   * sum of all kernel offsets
	let tx = Transaction::new(
		inputs,
		outputs,
		token_inputs,
		token_outputs,
		kernels,
		token_kernels,
	)
	.with_offset(total_kernel_offset);

	Ok(tx)
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple
/// transactions
pub fn deaggregate(mk_tx: Transaction, txs: Vec<Transaction>) -> Result<Transaction, Error> {
	let mut inputs: Vec<Input> = vec![];
	let mut outputs: Vec<Output> = vec![];
	let mut kernels: Vec<TxKernel> = vec![];
	let mut token_inputs: Vec<TokenInput> = vec![];
	let mut token_outputs: Vec<TokenOutput> = vec![];
	let mut token_kernels: Vec<TokenTxKernel> = vec![];

	// we will subtract these at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets = vec![];

	let tx = aggregate(txs)?;

	for mk_input in mk_tx.body.inputs {
		if !tx.body.inputs.contains(&mk_input) && !inputs.contains(&mk_input) {
			inputs.push(mk_input);
		}
	}
	for mk_output in mk_tx.body.outputs {
		if !tx.body.outputs.contains(&mk_output) && !outputs.contains(&mk_output) {
			outputs.push(mk_output);
		}
	}
	for mk_kernel in mk_tx.body.kernels {
		if !tx.body.kernels.contains(&mk_kernel) && !kernels.contains(&mk_kernel) {
			kernels.push(mk_kernel);
		}
	}
	for mk_token_input in mk_tx.body.token_inputs {
		if !tx.body.token_inputs.contains(&mk_token_input)
			&& !token_inputs.contains(&mk_token_input)
		{
			token_inputs.push(mk_token_input);
		}
	}
	for mk_token_output in mk_tx.body.token_outputs {
		if !tx.body.token_outputs.contains(&mk_token_output)
			&& !token_outputs.contains(&mk_token_output)
		{
			token_outputs.push(mk_token_output);
		}
	}
	for mk_token_kernel in mk_tx.body.token_kernels {
		if !tx.body.token_kernels.contains(&mk_token_kernel)
			&& !token_kernels.contains(&mk_token_kernel)
		{
			token_kernels.push(mk_token_kernel);
		}
	}

	kernel_offsets.push(tx.offset);

	// now compute the total kernel offset
	let total_kernel_offset = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let positive_key = vec![mk_tx.offset]
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key(&secp).ok())
			.collect::<Vec<_>>();
		let negative_keys = kernel_offsets
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key(&secp).ok())
			.collect::<Vec<_>>();

		if positive_key.is_empty() && negative_keys.is_empty() {
			BlindingFactor::zero()
		} else {
			let sum = secp.blind_sum(positive_key, negative_keys)?;
			BlindingFactor::from_secret_key(sum)
		}
	};

	// Sorting them lexicographically
	inputs.sort_unstable();
	outputs.sort_unstable();
	kernels.sort_unstable();
	token_inputs.sort_unstable();
	token_outputs.sort_unstable();
	token_kernels.sort_unstable();

	// Build a new tx from the above data.
	let tx = Transaction::new(
		inputs,
		outputs,
		token_inputs,
		token_outputs,
		kernels,
		token_kernels,
	)
	.with_offset(total_kernel_offset);
	Ok(tx)
}

/// A transaction input.
///
/// Primarily a reference to an output being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Input {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

impl DefaultHashable for Input {}
hashable_ord!(Input);

impl ::std::hash::Hash for Input {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for Input {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for Input {
	fn read(reader: &mut dyn Reader) -> Result<Input, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let commit = Commitment::read(reader)?;
		Ok(Input::new(features, commit))
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features and the
/// hash of the block the output originated from.
impl Input {
	/// Build a new input from the data required to identify and verify an
	/// output being spent.
	pub fn new(features: OutputFeatures, commit: Commitment) -> Input {
		Input { features, commit }
	}

	/// The input commitment which _partially_ identifies the output being
	/// spent. In the presence of a fork we need additional info to uniquely
	/// identify the output. Specifically the block hash (to correctly
	/// calculate lock_height for coinbase outputs).
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase input?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain input?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}
}

/// A transaction tokeninput.
///
/// Primarily a reference to an output being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct TokenInput {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// Token type
	pub token_type: TokenKey,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

impl DefaultHashable for TokenInput {}
hashable_ord!(TokenInput);

impl ::std::hash::Hash for TokenInput {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for TokenInput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.token_type.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for TokenInput {
	fn read(reader: &mut dyn Reader) -> Result<TokenInput, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let token_type = TokenKey::read(reader)?;
		let commit = Commitment::read(reader)?;
		Ok(TokenInput::new(features, token_type, commit))
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features and the
/// hash of the block the output originated from.
impl TokenInput {
	/// Build a new input from the data required to identify and verify an
	/// output being spent.
	pub fn new(features: OutputFeatures, token_type: TokenKey, commit: Commitment) -> TokenInput {
		TokenInput {
			features,
			token_type,
			commit,
		}
	}

	/// The input commitment which _partially_ identifies the output being
	/// spent. In the presence of a fork we need additional info to uniquely
	/// identify the output. Specifically the block hash (to correctly
	/// calculate lock_height for coinbase outputs).
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// The input token key
	pub fn token_type(&self) -> TokenKey {
		self.token_type
	}

	/// Is this a token issue?
	pub fn is_tokenissue(&self) -> bool {
		self.features.is_tokenissue()
	}

	/// Is this a plain token tx?
	pub fn is_token(&self) -> bool {
		self.features.is_token()
	}
}

// Enum of various supported kernel "features".
enum_from_primitive! {
	/// Various flavors of tx kernel.
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[repr(u8)]
	pub enum OutputFeatures {
		/// Plain output (the default for Grin txs).
		Plain = 0,
		/// A coinbase output.
		Coinbase = 1,
		/// A Token issue output
		TokenIssue = 98,
		/// common token output
		Token = 99,
	}
}

impl Writeable for OutputFeatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)?;
		Ok(())
	}
}

impl Readable for OutputFeatures {
	fn read(reader: &mut dyn Reader) -> Result<OutputFeatures, ser::Error> {
		let features =
			OutputFeatures::from_u8(reader.read_u8()?).ok_or(ser::Error::CorruptedData)?;
		Ok(features)
	}
}

/// Output for a transaction, defining the new ownership of coins that are being
/// transferred. The commitment is a blinded value for the output while the
/// range proof guarantees the commitment includes a positive value without
/// overflow and the ownership of the private key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Output {
	/// Options for an output's structure or use
	pub features: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl DefaultHashable for Output {}
hashable_ord!(Output);

impl ::std::hash::Hash for Output {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for Output {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		// The hash of an output doesn't include the range proof, which
		// is committed to separately
		if writer.serialization_mode() != ser::SerializationMode::Hash {
			writer.write_bytes(&self.proof)?
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for Output {
	fn read(reader: &mut dyn Reader) -> Result<Output, ser::Error> {
		Ok(Output {
			features: OutputFeatures::read(reader)?,
			commit: Commitment::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

/// We can build an Output MMR but store instances of OutputIdentifier in the MMR data file.
impl PMMRable for Output {
	type E = OutputIdentifier;

	fn as_elmt(&self) -> OutputIdentifier {
		OutputIdentifier::from_output(self)
	}
}

/// Output for a token transaction
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TokenOutput {
	/// Options for an output's structure or use
	pub features: OutputFeatures,
	/// Token type
	pub token_type: TokenKey,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl DefaultHashable for TokenOutput {}
hashable_ord!(TokenOutput);

impl ::std::hash::Hash for TokenOutput {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction TokenOutput, defines how to write
/// an TokenOutput as binary.
impl Writeable for TokenOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.token_type.write(writer)?;
		self.commit.write(writer)?;
		// The hash of an output doesn't include the range proof, which
		// is committed to separately
		if writer.serialization_mode() != ser::SerializationMode::Hash {
			writer.write_bytes(&self.proof)?
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction TokenOutput, defines how to read
/// an TokenOutput from a binary stream.
impl Readable for TokenOutput {
	fn read(reader: &mut dyn Reader) -> Result<TokenOutput, ser::Error> {
		Ok(TokenOutput {
			features: OutputFeatures::read(reader)?,
			token_type: TokenKey::read(reader)?,
			commit: Commitment::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

/// We can build an TokenOutput MMR but store instances of TokenOutputIdentifier in the MMR data file.
impl PMMRable for TokenOutput {
	type E = TokenOutputIdentifier;

	fn as_elmt(&self) -> TokenOutputIdentifier {
		TokenOutputIdentifier::from_output(self)
	}
}

impl OutputFeatures {
	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		*self == OutputFeatures::Coinbase
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		*self == OutputFeatures::Plain
	}

	/// Is this a token issue output?
	pub fn is_tokenissue(&self) -> bool {
		*self == OutputFeatures::TokenIssue
	}

	/// Is this a token output?
	pub fn is_token(&self) -> bool {
		*self == OutputFeatures::Token
	}
}

impl Output {
	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Validates the range proof using the commitment
	pub fn verify_proof(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof(self.commit, self.proof, None)?;
		Ok(())
	}

	/// Batch validates the range proofs using the commitments
	pub fn batch_verify_proofs(
		commits: &Vec<Commitment>,
		proofs: &Vec<RangeProof>,
	) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None)?;
		Ok(())
	}
}

impl TokenOutput {
	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// the output token key
	pub fn token_type(&self) -> TokenKey {
		self.token_type
	}

	/// Is this a coinbase kernel?
	pub fn is_tokenissue(&self) -> bool {
		self.features.is_tokenissue()
	}

	/// Is this a plain kernel?
	pub fn is_token(&self) -> bool {
		self.features.is_token()
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Validates the range proof using the commitment
	pub fn verify_proof(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof(self.commit, self.proof, None)?;
		Ok(())
	}
}

/// An output_identifier can be build from either an input _or_ an output and
/// contains everything we need to uniquely identify an output being spent.
/// Needed because it is not sufficient to pass a commitment around.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OutputIdentifier {
	/// Output features (coinbase vs. regular transaction output)
	/// We need to include this when hashing to ensure coinbase maturity can be
	/// enforced.
	pub features: OutputFeatures,
	/// Output commitment
	pub commit: Commitment,
}

impl DefaultHashable for OutputIdentifier {}

impl OutputIdentifier {
	/// Build a new output_identifier.
	pub fn new(features: OutputFeatures, commit: &Commitment) -> OutputIdentifier {
		OutputIdentifier {
			features,
			commit: *commit,
		}
	}

	/// Our commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Build an output_identifier from an existing output.
	pub fn from_output(output: &Output) -> OutputIdentifier {
		OutputIdentifier {
			features: output.features,
			commit: output.commit,
		}
	}

	/// Converts this identifier to a full output, provided a RangeProof
	pub fn into_output(self, proof: RangeProof) -> Output {
		Output {
			proof,
			features: self.features,
			commit: self.commit,
		}
	}

	/// Build an output_identifier from an existing input.
	pub fn from_input(input: &Input) -> OutputIdentifier {
		OutputIdentifier {
			features: input.features,
			commit: input.commit,
		}
	}

	/// convert an output_identifier to hex string format.
	pub fn to_hex(&self) -> String {
		format!(
			"{:b}{}",
			self.features as u8,
			util::to_hex(self.commit.0.to_vec()),
		)
	}
}

impl FixedLength for OutputIdentifier {
	const LEN: usize = 1 + secp::constants::PEDERSEN_COMMITMENT_SIZE;
}

impl Writeable for OutputIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

impl Readable for OutputIdentifier {
	fn read(reader: &mut dyn Reader) -> Result<OutputIdentifier, ser::Error> {
		Ok(OutputIdentifier {
			features: OutputFeatures::read(reader)?,
			commit: Commitment::read(reader)?,
		})
	}
}

impl From<Output> for OutputIdentifier {
	fn from(out: Output) -> Self {
		OutputIdentifier {
			features: out.features,
			commit: out.commit,
		}
	}
}

/// An token_output_identifier can be build from either an token_input _or_ an token_output and
/// contains everything we need to uniquely identify an output being spent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TokenOutputIdentifier {
	/// TokenOutput features
	pub features: OutputFeatures,
	/// Token type
	pub token_type: TokenKey,
	/// Output commitment
	pub commit: Commitment,
}

impl DefaultHashable for TokenOutputIdentifier {}

impl TokenOutputIdentifier {
	/// Build a new output_identifier.
	pub fn new(
		features: OutputFeatures,
		token_type: TokenKey,
		commit: &Commitment,
	) -> TokenOutputIdentifier {
		TokenOutputIdentifier {
			features,
			token_type,
			commit: *commit,
		}
	}

	/// Our commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Build an output_identifier from an existing output.
	pub fn from_output(output: &TokenOutput) -> TokenOutputIdentifier {
		TokenOutputIdentifier {
			features: output.features,
			token_type: output.token_type,
			commit: output.commit,
		}
	}

	/// Converts this identifier to a full output, provided a RangeProof
	pub fn into_output(self, proof: RangeProof) -> TokenOutput {
		TokenOutput {
			proof,
			features: self.features,
			commit: self.commit,
			token_type: self.token_type,
		}
	}

	/// Build an output_identifier from an existing input.
	pub fn from_input(input: &TokenInput) -> TokenOutputIdentifier {
		TokenOutputIdentifier {
			features: input.features,
			commit: input.commit,
			token_type: input.token_type,
		}
	}

	/// convert an output_identifier to hex string format.
	pub fn to_hex(&self) -> String {
		format!(
			"{:b}{}",
			self.features as u8,
			util::to_hex(self.commit.0.to_vec()),
		)
	}
}

impl FixedLength for TokenOutputIdentifier {
	const LEN: usize = 1 + 32 + secp::constants::PEDERSEN_COMMITMENT_SIZE;
}

impl Writeable for TokenOutputIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.token_type.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

impl Readable for TokenOutputIdentifier {
	fn read(reader: &mut dyn Reader) -> Result<TokenOutputIdentifier, ser::Error> {
		Ok(TokenOutputIdentifier {
			features: OutputFeatures::read(reader)?,
			token_type: TokenKey::read(reader)?,
			commit: Commitment::read(reader)?,
		})
	}
}

impl From<TokenOutput> for TokenOutputIdentifier {
	fn from(out: TokenOutput) -> Self {
		TokenOutputIdentifier {
			features: out.features,
			commit: out.commit,
			token_type: out.token_type,
		}
	}
}

/// Proof for Token issue
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TokenIssueProof {
	/// Token type
	pub token_type: TokenKey,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl DefaultHashable for TokenIssueProof {}
hashable_ord!(TokenIssueProof);

/// Implementation of Writeable for a TokenIssueProof, defines how to write
/// an TokenIssueProof as binary.
impl Writeable for TokenIssueProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.token_type.write(writer)?;
		self.commit.write(writer)?;
		if writer.serialization_mode() != ser::SerializationMode::Hash {
			writer.write_bytes(&self.proof)?
		}
		Ok(())
	}
}

/// Implementation of Readable for a TokenIssueProof, defines how to read
/// an TokenIssueProof from a binary stream.
impl Readable for TokenIssueProof {
	fn read(reader: &mut dyn Reader) -> Result<TokenIssueProof, ser::Error> {
		Ok(TokenIssueProof {
			token_type: TokenKey::read(reader)?,
			commit: Commitment::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

/// We can build an TokenOutput MMR but store instances of TokenOutputIdentifier in the MMR data file.
impl PMMRable for TokenIssueProof {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

impl FixedLength for TokenIssueProof {
	const LEN: usize = 32 + secp::constants::PEDERSEN_COMMITMENT_SIZE + 8 + MAX_PROOF_SIZE;
}

impl From<TokenOutput> for TokenIssueProof {
	fn from(out: TokenOutput) -> Self {
		TokenIssueProof {
			token_type: out.token_type,
			commit: out.commit,
			proof: out.proof,
		}
	}
}

impl TokenIssueProof {
	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Token key for the output
	pub fn token_type(&self) -> TokenKey {
		self.token_type
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Validates the range proof using the commitment
	pub fn verify_proof(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof(self.commit, self.proof, None)?;
		Ok(())
	}

	/// Build an output_identifier from an existing output.
	pub fn from_token_output(output: &TokenOutput) -> TokenIssueProof {
		TokenIssueProof {
			token_type: output.token_type,
			commit: output.commit,
			proof: output.proof,
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hash;
	use crate::core::id::{ShortId, ShortIdentifiable};
	use keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	use util::secp;

	#[test]
	fn test_kernel_ser_deser() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, &SwitchCommitmentType::Regular)
			.unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		let kernel = TxKernel {
			features: KernelFeatures::Plain { fee: 10 },
			excess: commit,
			excess_sig: sig.clone(),
		};

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel2.features, KernelFeatures::Plain { fee: 10 });
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());

		// now check a kernel with lock_height serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100,
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(
			kernel2.features,
			KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100
			}
		);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn commit_consistency() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let commit = keychain
			.commit(1003, &key_id, &SwitchCommitmentType::Regular)
			.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let commit_2 = keychain
			.commit(1003, &key_id, &SwitchCommitmentType::Regular)
			.unwrap();

		assert!(commit == commit_2);
	}

	#[test]
	fn input_short_id() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, &SwitchCommitmentType::Regular)
			.unwrap();

		let input = Input {
			features: OutputFeatures::Plain,
			commit,
		};

		let block_hash =
			Hash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();

		let nonce = 0;

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("c4b05f2ba649").unwrap());

		// now generate the short_id for a *very* similar output (single feature flag
		// different) and check it generates a different short_id
		let input = Input {
			features: OutputFeatures::Coinbase,
			commit,
		};

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("3f0377c624e9").unwrap());
	}

	#[test]
	fn kernel_features_serialization() {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(0u8, 10u64, 0u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(features, KernelFeatures::Plain { fee: 10 });

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(1u8, 0u64, 0u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(features, KernelFeatures::Coinbase);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(2u8, 10u64, 100u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(
			features,
			KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100
			}
		);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(3u8, 0u64, 0u64)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));
	}
}
