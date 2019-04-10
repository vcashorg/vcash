use crate::common::types::Error;
use crate::util::{Mutex, RwLock, StopState};
use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::api;
use crate::chain;
use crate::core::consensus::reward;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::{Block, BlockHeader};
use crate::core::{consensus, core, global, ser};
use crate::keychain::{ExtKeychain, Identifier, Keychain};
use crate::pool;
use crate::util;
use crate::wallet::{self, BlockFees};

#[derive(Clone)]
pub struct BlockHandler {
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool>>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	stop_state: Arc<Mutex<StopState>>,
	wallet_listener_url: Option<String>,
	key_id: Arc<RwLock<Option<Identifier>>>,
	waiting_bitming_block: Arc<RwLock<Option<(Block, u64)>>>,
	mining_blocks: Arc<RwLock<HashMap<Hash, Block>>>,
	notify_urls: Arc<Vec<String>>,
}

impl BlockHandler {
	pub fn new(
		chain: Arc<chain::Chain>,
		tx_pool: Arc<RwLock<pool::TransactionPool>>,
		verifier_cache: Arc<RwLock<dyn VerifierCache>>,
		stop_state: Arc<Mutex<StopState>>,
		wallet_listener_url: Option<String>,
		notify_urls: Vec<String>,
	) -> BlockHandler {
		BlockHandler {
			chain,
			tx_pool,
			verifier_cache,
			//sync_state,
			stop_state,
			wallet_listener_url,
			key_id: Arc::new(RwLock::new(None)),
			waiting_bitming_block: Arc::new(RwLock::new(None)),
			mining_blocks: Arc::new(RwLock::new(HashMap::new())),
			notify_urls: Arc::new(notify_urls),
		}
	}

	pub fn get_bitmining_block(&self) -> Result<(Block, u64), String> {
		let mining_block = { self.waiting_bitming_block.read().clone() };
		match mining_block {
			Some((block, fee)) => {
				self.mining_blocks
					.write()
					.insert(block.header.hash(), block.clone());
				Ok((block, fee))
			}
			None => Err("Waiting PoolCenter internal mining result, try again later!".to_string()),
		}
	}

	pub fn get_miningblock_by_hash(&self, hash: &Hash) -> Result<Block, String> {
		match self.mining_blocks.read().get(hash) {
			Some(block) => Ok(block.clone()),
			None => {
				let error_msg = format!(
					"Internal Errors happens, cannot find block by hash:{}",
					hash
				);
				error!("{}", error_msg);
				Err(error_msg)
			}
		}
	}

	pub fn submit_block(&self, block_data: Block) -> Result<(), String> {
		let res = self
			.chain
			.process_block(block_data.clone(), chain::Options::MINE);
		if let Err(e) = res {
			let err_reason = String::from(format!(
				"chain Failed to validate solution at height {}, grin header hash {} reason:{}",
				block_data.header.height,
				block_data.header.hash(),
				e
			));
			error!("{}", err_reason);
			return Err(err_reason);
		}
		{
			*self.key_id.write() = None;
		}

		Ok(())
	}

	pub fn mining_loop(&self) {
		info!("(PoolCenter Starting miner loop.",);
		let mut need_notify_pool = false;
		loop {
			if self.stop_state.lock().is_stopped() {
				break;
			}

			trace!("in miner loop. key_id: {:?}", self.key_id);

			// get the latest chain state and build a block on top of it
			let head = self.chain.head_header().unwrap();
			let mut latest_hash = self.chain.head().unwrap().last_block_h;
			let head_hash = head.hash();
			assert_eq!(head_hash, latest_hash);

			let (mut b, fee) = self.get_block();

			let sol = self.inner_mining_loop(&mut b, &head, &mut latest_hash);

			// we found a solution
			if sol {
				debug!(
					"PoolCenter Found valid proof of work, block {} (prev_root {}).",
					b.hash(),
					b.header.prev_root,
				);
				{
					*self.waiting_bitming_block.write() = Some((b, fee));
				}
				if need_notify_pool {
					self.notify_pool();
					need_notify_pool = false;
				}

				//sleep 10s, if chain head change break immediately
				let sleep_deadline = Utc::now().timestamp() + 10;
				while Utc::now().timestamp() < sleep_deadline {
					let new_header_hash = self.chain.head().unwrap().last_block_h;
					if head.hash() != new_header_hash {
						break;
					}
					thread::sleep(Duration::from_millis(1));
				}
			}

			let new_header_hash = self.chain.head().unwrap().last_block_h;
			if head.hash() != new_header_hash {
				self.mining_blocks.write().clear();
				need_notify_pool = true;
			}
		}

		warn!("PoolCenter miningloop exit.");
	}

	fn inner_mining_loop(&self, b: &mut Block, head: &BlockHeader, latest_hash: &mut Hash) -> bool {
		// look for a pow for at most 2 sec on the same block (to give a chance to new
		// transactions) and as long as the head hasn't changed
		let deadline = Utc::now().timestamp_millis() + 3_i64 * 1000;

		debug!(
			"PoolCenter Mining Cuckoo{} for max 3s on {} @ {} [{}].",
			global::min_edge_bits(),
			b.header.total_difficulty(),
			b.header.height,
			latest_hash
		);
		let mut iter_count = 0;

		while head.hash() == *latest_hash && Utc::now().timestamp() < deadline {
			let mut ctx = global::create_pow_context::<u32>(
				head.height,
				global::min_edge_bits(),
				global::proofsize(),
				10,
			)
			.unwrap();
			ctx.set_header_nonce(b.header.pre_pow(), None, true)
				.unwrap();
			if let Ok(proofs) = ctx.find_cycles() {
				b.header.pow.proof = proofs[0].clone();
				let proof_diff = b.header.pow.to_difficulty(b.header.height);
				if proof_diff >= (b.header.total_difficulty() - head.total_difficulty()) {
					debug!(
						"PoolServer found solution for height = {} before deadline in {}, iter_count = {}",b.header.height,
						deadline - Utc::now().timestamp_millis(), iter_count,
					);
					return true;
				}
			}

			b.header.pow.nonce += 1;
			*latest_hash = self.chain.head().unwrap().last_block_h;
			iter_count += 1;
		}

		debug!("PoolCenter No solution found in 3s",);
		false
	}

	fn notify_pool(&self) {
		if self.notify_urls.len() > 0 {
			let new_block = self.get_bitmining_block();
			match new_block {
				Ok((block, fee)) => {
					warn!("PoolCenter nofity pool at height {}", block.header.height);
					let info = JobInfo {
						height: block.header.height,
						cur_hash: block.header.hash().to_hex(),
						prev_hash: block.header.prev_hash.to_hex(),
						bits: block.header.bits,
						base_rewards: reward(block.header.height, 0),
						transactions_fee: fee,
					};
					let mut iter = self.notify_urls.iter();
					while let Some(item) = iter.next() {
						let res = api::client::post_no_ret(item.as_str(), None, &info);
						if res.is_err() {
							error!(
								"PoolCenter nofity pool failed at {}, reason {}",
								item,
								res.err().unwrap()
							);
						}
					}
				}
				Err(_) => {
					error!("PoolCenter nofity pool failed getting bitmining block");
				}
			}
		}
	}

	// Ensure a block suitable for mining is built and returned
	// If a wallet listener URL is not provided the reward will be "burnt"
	// Warning: This call does not return until/unless a new block can be built
	fn get_block(&self) -> (Block, u64) {
		let wallet_retry_interval = 5;
		// get the latest chain state and build a block on top of it
		let mut result = self.build_block();
		while let Err(e) = result {
			warn!("Error building new block: {:?}. Retrying.", e);
			match e {
				self::Error::Chain(c) => match c.kind() {
					chain::ErrorKind::DuplicateCommitment(_) => {
						debug!(
                            "Duplicate commit for potential coinbase detected. Trying next derivation."
                        );
					}
					_ => {
						error!("Chain Error: {}", c);
					}
				},
				self::Error::Wallet(_) => {
					error!(
                        "Error building new block: Can't connect to wallet listener at {:?}; will retry",
                        self.wallet_listener_url.clone().unwrap()
                    );
					thread::sleep(Duration::from_secs(wallet_retry_interval));
				}
				ae => {
					warn!("Error building new block: {:?}. Retrying.", ae);
				}
			}
			thread::sleep(Duration::from_millis(100));
			result = self.build_block();
		}
		return result.unwrap();
	}

	/// Builds a new block with the chain head as previous and eligible
	/// transactions from the pool.
	fn build_block(&self) -> Result<(Block, u64), Error> {
		let head = self.chain.head_header()?;

		// prepare the block header timestamp
		let mut now_sec = Utc::now().timestamp();
		let head_sec = head.timestamp.timestamp();
		if now_sec <= head_sec {
			now_sec = head_sec + 1;
		}

		// Determine the difficulty our block should be at.
		// Note: do not keep the difficulty_iter in scope (it has an active batch).
		let difficulty = consensus::next_difficulty(head.height + 1, self.chain.difficulty_iter()?);
		let nbits = if (head.height + 1) % consensus::DIFFICULTY_ADJUST_WINDOW != 0 {
			head.bits
		} else {
			let start_height = if head.height >= (consensus::DIFFICULTY_ADJUST_WINDOW - 1) {
				head.height - (consensus::DIFFICULTY_ADJUST_WINDOW - 1)
			} else {
				0
			};
			let first_head = self.chain.get_header_by_height(start_height)?;
			consensus::next_bit_difficulty(
				head.height,
				head.bits,
				head.timestamp.timestamp(),
				first_head.timestamp.timestamp(),
			)
		};

		// Extract current "mineable" transactions from the pool.
		// If this fails for *any* reason then fallback to an empty vec of txs.
		// This will allow us to mine an "empty" block if the txpool is in an
		// invalid (and unexpected) state.
		let txs = match self.tx_pool.read().prepare_mineable_transactions() {
			Ok(txs) => txs,
			Err(e) => {
				error!(
					"build_block: Failed to prepare mineable txs from txpool: {:?}",
					e
				);
				warn!("build_block: Falling back to mining empty block.");
				vec![]
			}
		};

		// build the coinbase and the block itself
		let fees = txs.iter().map(|tx| tx.fee()).sum();
		let height = head.height + 1;
		let block_fees = BlockFees {
			fees,
			height,
			key_id: self.key_id.read().clone(),
		};

		let (output, kernel) = {
			let mut write_lock = self.key_id.write();
			let (output, kernel, block_fees) =
				self.get_coinbase(self.wallet_listener_url.clone(), block_fees)?;
			*write_lock = block_fees.key_id.clone();
			(output, kernel)
		};

		let mut b = core::Block::from_reward(&head, txs, output, kernel, difficulty.difficulty)?;

		// making sure we're not spending time mining a useless block
		b.validate(&head.total_kernel_offset, self.verifier_cache.clone())?;

		b.header.bits = nbits;
		b.header.pow.nonce = thread_rng().gen();
		b.header.pow.secondary_scaling = difficulty.secondary_scaling;
		b.header.timestamp =
			DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(now_sec, 0), Utc);

		debug!(
            "Built new block with {} inputs and {} outputs, block difficulty: {}, cumulative difficulty {}",
            b.inputs().len(),
            b.outputs().len(),
            difficulty.difficulty,
            b.header.total_difficulty().to_num(),
        );

		// Now set txhashset roots and sizes on the header of the block being built.
		match self.chain.set_txhashset_roots(&mut b) {
			Ok(_) => Ok((b, fees)),
			Err(e) => {
				match e.kind() {
					// If this is a duplicate commitment then likely trying to use
					// a key that hass already been derived but not in the wallet
					// for some reason, allow caller to retry.
					chain::ErrorKind::DuplicateCommitment(e) => Err(Error::Chain(
						chain::ErrorKind::DuplicateCommitment(e).into(),
					)),

					// Some other issue, possibly duplicate kernel
					_ => {
						error!("Error setting txhashset root to build a block: {:?}", e);
						Err(Error::Chain(
							chain::ErrorKind::Other(format!("{:?}", e)).into(),
						))
					}
				}
			}
		}
	}

	///
	/// Probably only want to do this when testing.
	///
	fn burn_reward(
		&self,
		block_fees: BlockFees,
	) -> Result<(core::Output, core::TxKernel, BlockFees), Error> {
		warn!("Burning block fees: {:?}", block_fees);
		let keychain = ExtKeychain::from_random_seed(global::is_floonet()).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let (out, kernel) = crate::core::libtx::reward::output(
			&keychain,
			&key_id,
			block_fees.height,
			block_fees.fees,
		)
		.unwrap();
		Ok((out, kernel, block_fees))
	}

	// Connect to the wallet listener and get coinbase.
	// Warning: If a wallet listener URL is not provided the reward will be "burnt"
	fn get_coinbase(
		&self,
		wallet_listener_url: Option<String>,
		block_fees: BlockFees,
	) -> Result<(core::Output, core::TxKernel, BlockFees), Error> {
		match wallet_listener_url {
			None => {
				// Burn it
				return self.burn_reward(block_fees);
			}
			Some(wallet_listener_url) => {
				let res = wallet::create_coinbase(&wallet_listener_url, &block_fees)?;
				let out_bin = util::from_hex(res.output)
					.map_err(|_| Error::General("failed to parse hex output".to_owned()))?;
				let kern_bin = util::from_hex(res.kernel)
					.map_err(|_| Error::General("failed to parse hex kernel".to_owned()))?;

				let key_id_bin = util::from_hex(res.key_id)
					.map_err(|_| Error::General("failed to parse hex key id".to_owned()))?;
				let output = ser::deserialize(&mut &out_bin[..])
					.map_err(|_| Error::General("failed to deserialize output".to_owned()))?;

				let kernel = ser::deserialize(&mut &kern_bin[..])
					.map_err(|_| Error::General("failed to deserialize kernel".to_owned()))?;
				let key_id = ser::deserialize(&mut &key_id_bin[..])
					.map_err(|_| Error::General("failed to deserialize key id".to_owned()))?;
				let block_fees = BlockFees {
					key_id: Some(key_id),
					..block_fees
				};

				debug!("get_coinbase: {:?}", block_fees);
				return Ok((output, kernel, block_fees));
			}
		}
	}
}

/// pool mining job info
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JobInfo {
	/// vcash height
	pub height: u64,
	/// vcash current hash
	pub cur_hash: String,
	/// vcash prev hash
	pub prev_hash: String,
	/// vcash bits
	pub bits: u32,
	/// vcash reward
	pub base_rewards: u64,
	/// vcash fee
	pub transactions_fee: u64,
}
