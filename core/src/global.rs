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

//! Values that should be shared across all modules, without necessarily
//! having to pass them all over the place, but aren't consensus values.
//! should be used sparingly.

use crate::consensus::{
	HeaderInfo, BLOCK_TIME_SEC_ORIGIN, COINBASE_MATURITY, CUT_THROUGH_HORIZON, DAY_HEIGHT_ORIGIN,
	DIFFICULTY_ADJUST_WINDOW_ORIGIN, FOURTH_HARD_FORK_HEIGHT, GRIN_BASE, KERNEL_WEIGHT,
	MAX_BLOCK_WEIGHT, OUTPUT_WEIGHT, STATE_SYNC_THRESHOLD, TESTING_FOURTH_HARD_FORK,
	TESTING_THIRD_HARD_FORK, TESTNET_FOURTH_HARD_FORK_HEIGHT, YEAR_HEIGHT_ADJUSTED,
};
use crate::pow::{self, new_cuckatoo_ctx, PoWContext};
use crate::ser::ProtocolVersion;
use std::cell::Cell;
use util::OneTime;

use crate::consensus::{
	REFACTOR_HEADER_HEIGHT, SUPPORT_TOKEN_HEIGHT, TESTNET_REFACTOR_HEADER_HEIGHT,
	TESTNET_SUPPORT_TOKEN_HEIGHT, TESTNET_THIRD_HARD_FORK_HEIGHT, THIRD_HARD_FORK_HEIGHT,
};

/// An enum collecting sets of parameters used throughout the
/// code wherever mining is needed. This should allow for
/// different sets of parameters for different purposes,
/// e.g. CI, User testing, production values
/// Define these here, as they should be developer-set, not really tweakable
/// by users

/// The default "local" protocol version for this node.
/// We negotiate compatible versions with each peer via Hand/Shake.
/// Note: We also use a specific (possible different) protocol version
/// for both the backend database and MMR data files.
/// This defines the p2p layer protocol version for this node.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(4);

/// Automated testing edge_bits
pub const AUTOMATED_TESTING_MIN_EDGE_BITS: u8 = 9;

/// Automated testing proof size
pub const AUTOMATED_TESTING_PROOF_SIZE: usize = 4;

/// User testing edge_bits
pub const USER_TESTING_MIN_EDGE_BITS: u8 = 15;

/// User testing proof size
pub const USER_TESTING_PROOF_SIZE: usize = 42;

/// Automated testing coinbase maturity
pub const AUTOMATED_TESTING_COINBASE_MATURITY: u64 = 3;

/// User testing coinbase maturity
pub const USER_TESTING_COINBASE_MATURITY: u64 = 3;

/// Testing cut through horizon in blocks
pub const AUTOMATED_TESTING_CUT_THROUGH_HORIZON: u32 = 20;

/// Testing cut through horizon in blocks
pub const USER_TESTING_CUT_THROUGH_HORIZON: u32 = 70;

/// Testing state sync threshold in blocks
pub const TESTING_STATE_SYNC_THRESHOLD: u32 = 20;

/// Testing initial graph weight
pub const TESTING_INITIAL_GRAPH_WEIGHT: u32 = 1;

/// Testing initial block difficulty
pub const TESTING_INITIAL_DIFFICULTY: u64 = 1;

/// Testing max_block_weight (artifically low, just enough to support a few txs).
pub const TESTING_MAX_BLOCK_WEIGHT: u64 = 250;

/// Default unit of fee per tx weight, making each output cost about a Grincent
pub const DEFAULT_ACCEPT_FEE_BASE: u64 = GRIN_BASE / 100 / 20; // 500_000

/// default Future Time Limit (FTL) of 5 minutes
pub const DEFAULT_FUTURE_TIME_LIMIT: u64 = 5 * 60;

/// If a peer's last updated difficulty is 2 hours ago and its difficulty's lower than ours,
/// we're sure this peer is a stuck node, and we will kick out such kind of stuck peers.
pub const STUCK_PEER_KICK_TIME: i64 = 2 * 3600 * 1000;

/// If a peer's last seen time is 2 weeks ago we will forget such kind of defunct peers.
const PEER_EXPIRATION_DAYS: i64 = 7 * 2;

/// Constant that expresses defunct peer timeout in seconds to be used in checks.
pub const PEER_EXPIRATION_REMOVE_TIME: i64 = PEER_EXPIRATION_DAYS * 24 * 3600;

/// Trigger compaction check on average every day for all nodes.
/// Randomized per node - roll the dice on every block to decide.
/// Will compact the txhashset to remove pruned data.
/// Will also remove old blocks and associated data from the database.
/// For a node configured as "archival_mode = true" only the txhashset will be compacted.
pub const COMPACTION_CHECK: u64 = DAY_HEIGHT_ORIGIN;

/// Subsidy amount half height
const HALVINGINTERVAL: u64 = 1050000;

/// Floonet Subsidy amount half height
const TESTNET_HALVINGINTERVAL: u64 = YEAR_HEIGHT_ADJUSTED;

/// Testing Subsidy amount half height
const AUTOTEST_HALVINGINTERVAL: u64 = DAY_HEIGHT_ORIGIN;

/// Number of blocks to reuse a txhashset zip for (automated testing and user testing).
pub const TESTING_TXHASHSET_ARCHIVE_INTERVAL: u64 = 10;

/// Number of blocks to reuse a txhashset zip for.
pub const TXHASHSET_ARCHIVE_INTERVAL: u64 = 12 * 30;

/// Types of chain a server can run with, dictates the genesis block and
/// and mining parameters used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ChainTypes {
	/// For CI testing
	AutomatedTesting,
	/// For User testing
	UserTesting,
	/// Protocol testing network
	Testnet,
	/// Main production network
	Mainnet,
}

impl ChainTypes {
	/// Short name representing the chain type ("test", "main", etc.)
	pub fn shortname(&self) -> String {
		match *self {
			ChainTypes::AutomatedTesting => "auto".to_owned(),
			ChainTypes::UserTesting => "user".to_owned(),
			ChainTypes::Testnet => "test".to_owned(),
			ChainTypes::Mainnet => "main".to_owned(),
		}
	}
}

impl Default for ChainTypes {
	fn default() -> ChainTypes {
		ChainTypes::Mainnet
	}
}

lazy_static! {
	/// Global chain_type that must be initialized once on node startup.
	/// This is accessed via get_chain_type() which allows the global value
	/// to be overridden on a per-thread basis (for testing).
	pub static ref GLOBAL_CHAIN_TYPE: OneTime<ChainTypes> = OneTime::new();

	/// Global acccept fee base that must be initialized once on node startup.
	/// This is accessed via get_acccept_fee_base() which allows the global value
	/// to be overridden on a per-thread basis (for testing).
	pub static ref GLOBAL_ACCEPT_FEE_BASE: OneTime<u64> = OneTime::new();

	/// Global future time limit that must be initialized once on node startup.
	/// This is accessed via get_future_time_limit() which allows the global value
	/// to be overridden on a per-thread basis (for testing).
	pub static ref GLOBAL_FUTURE_TIME_LIMIT: OneTime<u64> = OneTime::new();

	/// Global feature flag for NRD kernel support.
	/// If enabled NRD kernels are treated as valid after HF3 (based on header version).
	/// If disabled NRD kernels are invalid regardless of header version or block height.
	pub static ref GLOBAL_NRD_FEATURE_ENABLED: OneTime<bool> = OneTime::new();
}

thread_local! {
	/// Mainnet|Testnet|UserTesting|AutomatedTesting
	pub static CHAIN_TYPE: Cell<Option<ChainTypes>> = Cell::new(None);

	/// minimum transaction fee per unit of transaction weight for mempool acceptance
	pub static ACCEPT_FEE_BASE: Cell<Option<u64>> = Cell::new(None);

	/// maximum number of seconds into future for timestamp of block to be acceptable
	pub static FUTURE_TIME_LIMIT: Cell<Option<u64>> = Cell::new(None);

	/// Local feature flag for NRD kernel support.
	pub static NRD_FEATURE_ENABLED: Cell<Option<bool>> = Cell::new(None);
}

/// One time initialization of the global chain_type.
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_chain_type(new_type: ChainTypes) {
	GLOBAL_CHAIN_TYPE.init(new_type)
}

/// Set the chain type on a per-thread basis via thread_local storage.
pub fn set_local_chain_type(new_type: ChainTypes) {
	CHAIN_TYPE.with(|chain_type| chain_type.set(Some(new_type)))
}

/// Get the chain type via thread_local, fallback to global chain_type.
pub fn get_chain_type() -> ChainTypes {
	CHAIN_TYPE.with(|chain_type| match chain_type.get() {
		None => {
			if !GLOBAL_CHAIN_TYPE.is_init() {
				panic!("GLOBAL_CHAIN_TYPE and CHAIN_TYPE unset. Consider set_local_chain_type() in tests.");
			}
			let chain_type = GLOBAL_CHAIN_TYPE.borrow();
			set_local_chain_type(chain_type);
			chain_type
		}
		Some(chain_type) => chain_type,
	})
}

/// One time initialization of the global future time limit
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_future_time_limit(new_ftl: u64) {
	GLOBAL_FUTURE_TIME_LIMIT.init(new_ftl)
}

/// One time initialization of the global accept fee base
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_accept_fee_base(new_base: u64) {
	GLOBAL_ACCEPT_FEE_BASE.init(new_base)
}

/// Set the accept fee base on a per-thread basis via thread_local storage.
pub fn set_local_accept_fee_base(new_base: u64) {
	ACCEPT_FEE_BASE.with(|base| base.set(Some(new_base)))
}

/// Accept Fee Base
/// Look at thread local config first. If not set fallback to global config.
/// Default to grin-cent/20 if global config unset.
pub fn get_accept_fee_base() -> u64 {
	ACCEPT_FEE_BASE.with(|base| match base.get() {
		None => {
			let base = if GLOBAL_ACCEPT_FEE_BASE.is_init() {
				GLOBAL_ACCEPT_FEE_BASE.borrow()
			} else {
				DEFAULT_ACCEPT_FEE_BASE
			};
			set_local_accept_fee_base(base);
			base
		}
		Some(base) => base,
	})
}

/// Set the future time limit on a per-thread basis via thread_local storage.
pub fn set_local_future_time_limit(new_ftl: u64) {
	FUTURE_TIME_LIMIT.with(|ftl| ftl.set(Some(new_ftl)))
}

/// Future Time Limit (FTL)
/// Look at thread local config first. If not set fallback to global config.
/// Default to false if global config unset.
pub fn get_future_time_limit() -> u64 {
	FUTURE_TIME_LIMIT.with(|ftl| match ftl.get() {
		None => {
			let ftl = if GLOBAL_FUTURE_TIME_LIMIT.is_init() {
				GLOBAL_FUTURE_TIME_LIMIT.borrow()
			} else {
				DEFAULT_FUTURE_TIME_LIMIT
			};
			set_local_future_time_limit(ftl);
			ftl
		}
		Some(ftl) => ftl,
	})
}

/// One time initialization of the global NRD feature flag.
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_nrd_enabled(enabled: bool) {
	GLOBAL_NRD_FEATURE_ENABLED.init(enabled)
}

/// Explicitly enable the local NRD feature flag.
pub fn set_local_nrd_enabled(enabled: bool) {
	NRD_FEATURE_ENABLED.with(|flag| flag.set(Some(enabled)))
}

/// Is the NRD feature flag enabled?
/// Look at thread local config first. If not set fallback to global config.
/// Default to false if global config unset.
pub fn is_nrd_enabled() -> bool {
	NRD_FEATURE_ENABLED.with(|flag| match flag.get() {
		None => {
			if GLOBAL_NRD_FEATURE_ENABLED.is_init() {
				let global_flag = GLOBAL_NRD_FEATURE_ENABLED.borrow();
				flag.set(Some(global_flag));
				global_flag
			} else {
				// Global config unset, default to false.
				false
			}
		}
		Some(flag) => flag,
	})
}

/// Return either a cuckaroo* context or a cuckatoo context
/// Single change point
pub fn create_pow_context<T>(
	_height: u64,
	edge_bits: u8,
	proof_size: usize,
	max_sols: u32,
) -> Result<Box<dyn PoWContext>, pow::Error> {
	new_cuckatoo_ctx(edge_bits, proof_size, max_sols)
}

/// The havling interval
pub fn halving_interval() -> u64 {
	match get_chain_type() {
		ChainTypes::Mainnet => HALVINGINTERVAL,
		ChainTypes::Testnet => TESTNET_HALVINGINTERVAL,
		_ => AUTOTEST_HALVINGINTERVAL,
	}
}

/// First Hard Fork:Support token height
pub fn support_token_height() -> u64 {
	match get_chain_type() {
		ChainTypes::Testnet => TESTNET_SUPPORT_TOKEN_HEIGHT,
		ChainTypes::Mainnet => SUPPORT_TOKEN_HEIGHT,
		_ => 0,
	}
}

/// Second Hard Fork:Refactor header height
pub fn refactor_header_height() -> u64 {
	match get_chain_type() {
		ChainTypes::Testnet => TESTNET_REFACTOR_HEADER_HEIGHT,
		ChainTypes::Mainnet => REFACTOR_HEADER_HEIGHT,
		_ => 0,
	}
}

/// Third Hard Fork:Block withholding attack and NRD Kernel
pub fn third_hard_fork_height() -> u64 {
	match get_chain_type() {
		ChainTypes::Testnet => TESTNET_THIRD_HARD_FORK_HEIGHT,
		ChainTypes::Mainnet => THIRD_HARD_FORK_HEIGHT,
		_ => TESTING_THIRD_HARD_FORK,
	}
}

/// Fourth Hard Fork:FeeFields
pub fn fourth_hard_fork_height() -> u64 {
	match get_chain_type() {
		ChainTypes::Testnet => TESTNET_FOURTH_HARD_FORK_HEIGHT,
		ChainTypes::Mainnet => FOURTH_HARD_FORK_HEIGHT,
		_ => TESTING_FOURTH_HARD_FORK,
	}
}

/// The minimum acceptable edge_bits
pub fn min_edge_bits() -> u8 {
	//    match get_chain_type() {
	//        ChainTypes::AutomatedTesting => AUTOMATED_TESTING_MIN_EDGE_BITS,
	//        ChainTypes::UserTesting => USER_TESTING_MIN_EDGE_BITS,
	//        _ => DEFAULT_MIN_EDGE_BITS,
	//    }
	AUTOMATED_TESTING_MIN_EDGE_BITS
}

/// Reference edge_bits used to compute factor on higher Cuck(at)oo graph sizes,
/// while the min_edge_bits can be changed on a soft fork, changing
/// base_edge_bits is a hard fork.
pub fn base_edge_bits() -> u8 {
	//    match get_chain_type() {
	//        ChainTypes::AutomatedTesting => AUTOMATED_TESTING_MIN_EDGE_BITS,
	//        ChainTypes::UserTesting => USER_TESTING_MIN_EDGE_BITS,
	//        _ => BASE_EDGE_BITS,
	//    }
	AUTOMATED_TESTING_MIN_EDGE_BITS
}

/// The proofsize
pub fn proofsize() -> usize {
	//    match get_chain_type() {
	//        ChainTypes::AutomatedTesting => AUTOMATED_TESTING_PROOF_SIZE,
	//        ChainTypes::UserTesting => USER_TESTING_PROOF_SIZE,
	//        _ => PROOFSIZE,
	//    }
	AUTOMATED_TESTING_PROOF_SIZE
}

/// Minimum bit difficulty
pub fn min_bit_diff() -> u32 {
	match get_chain_type() {
		ChainTypes::Testnet => 0x1b01cc26,
		ChainTypes::Mainnet => 0x18120f14,
		_ => 0x2100ffff,
	}
}

/// Coinbase maturity for coinbases to be spent
pub fn coinbase_maturity() -> u64 {
	match get_chain_type() {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_COINBASE_MATURITY,
		ChainTypes::UserTesting => USER_TESTING_COINBASE_MATURITY,
		_ => COINBASE_MATURITY,
	}
}

/// Initial mining difficulty
pub fn initial_block_difficulty() -> u64 {
	TESTING_INITIAL_DIFFICULTY
}

/// Initial mining secondary scale
pub fn initial_graph_weight() -> u32 {
	TESTING_INITIAL_GRAPH_WEIGHT
}

/// Maximum allowed block weight.
pub fn max_block_weight() -> u64 {
	match get_chain_type() {
		ChainTypes::AutomatedTesting => TESTING_MAX_BLOCK_WEIGHT,
		ChainTypes::UserTesting => TESTING_MAX_BLOCK_WEIGHT,
		ChainTypes::Testnet => MAX_BLOCK_WEIGHT,
		ChainTypes::Mainnet => MAX_BLOCK_WEIGHT,
	}
}

/// Maximum allowed transaction weight (1 weight unit ~= 32 bytes)
pub fn max_tx_weight() -> u64 {
	let coinbase_weight = OUTPUT_WEIGHT + KERNEL_WEIGHT;
	max_block_weight().saturating_sub(coinbase_weight) as u64
}

/// Horizon at which we can cut-through and do full local pruning
pub fn cut_through_horizon() -> u32 {
	match get_chain_type() {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_CUT_THROUGH_HORIZON,
		ChainTypes::UserTesting => USER_TESTING_CUT_THROUGH_HORIZON,
		ChainTypes::Testnet => USER_TESTING_CUT_THROUGH_HORIZON,
		_ => CUT_THROUGH_HORIZON,
	}
}

/// Threshold at which we can request a txhashset (and full blocks from)
pub fn state_sync_threshold() -> u32 {
	match get_chain_type() {
		ChainTypes::AutomatedTesting => TESTING_STATE_SYNC_THRESHOLD,
		ChainTypes::UserTesting => TESTING_STATE_SYNC_THRESHOLD,
		ChainTypes::Testnet => TESTING_STATE_SYNC_THRESHOLD,
		_ => STATE_SYNC_THRESHOLD,
	}
}

/// Number of blocks to reuse a txhashset zip for.
pub fn txhashset_archive_interval() -> u64 {
	match get_chain_type() {
		ChainTypes::AutomatedTesting => TESTING_TXHASHSET_ARCHIVE_INTERVAL,
		ChainTypes::UserTesting => TESTING_TXHASHSET_ARCHIVE_INTERVAL,
		ChainTypes::Testnet => TESTING_TXHASHSET_ARCHIVE_INTERVAL,
		_ => TXHASHSET_ARCHIVE_INTERVAL,
	}
}

/// Are we in production mode?
/// Production defined as a live public network, testnet[n] or mainnet.
pub fn is_production_mode() -> bool {
	match get_chain_type() {
		ChainTypes::Testnet => true,
		ChainTypes::Mainnet => true,
		_ => false,
	}
}

/// Are we in testnet?
/// Note: We do not have a corresponding is_mainnet() as we want any tests to be as close
/// as possible to "mainnet" configuration as possible.
/// We want to avoid missing any mainnet only code paths.
pub fn is_testnet() -> bool {
	match get_chain_type() {
		ChainTypes::Testnet => true,
		_ => false,
	}
}

/// Converts an iterator of block difficulty data to more a more manageable
/// vector and pads if needed (which will) only be needed for the first few
/// blocks after genesis

pub fn difficulty_data_to_vector<T>(cursor: T) -> Vec<HeaderInfo>
where
	T: IntoIterator<Item = HeaderInfo>,
{
	// Convert iterator to vector, so we can append to it if necessary
	let needed_block_count = DIFFICULTY_ADJUST_WINDOW_ORIGIN as usize + 1;
	let mut last_n: Vec<HeaderInfo> = cursor.into_iter().take(needed_block_count).collect();

	// Only needed just after blockchain launch... basically ensures there's
	// always enough data by simulating perfectly timed pre-genesis
	// blocks at the genesis difficulty as needed.
	let n = last_n.len();
	if needed_block_count > n {
		let last_ts_delta = if n > 1 {
			last_n[0].timestamp - last_n[1].timestamp
		} else {
			BLOCK_TIME_SEC_ORIGIN
		};
		let last_diff = last_n[0].difficulty;

		// fill in simulated blocks with values from the previous real block
		let mut last_ts = last_n.last().unwrap().timestamp;
		for _ in n..needed_block_count {
			last_ts = last_ts.saturating_sub(last_ts_delta);
			last_n.push(HeaderInfo::from_ts_diff(last_ts, last_diff));
		}
	}
	last_n.reverse();
	last_n
}

/// Calculates the size of a header (in bytes) given a number of edge bits in the PoW
#[inline]
pub fn max_header_size_bytes() -> usize {
	//414 for header body length.
	//1104 for BlockAuxData, based on max merkle branch length 13 and max coinbase tx length 600.
	//500 for extra redundancy.
	414 + 1104 + 500
}
