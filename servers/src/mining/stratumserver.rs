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

//! Mining Stratum Server
use crate::util::{Mutex, RwLock};
use bufstream::BufStream;
use chrono::prelude::Utc;
use serde;
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use crate::chain::{self, SyncState};
use crate::common::stats::{StratumStats, WorkerStats};
use crate::common::types::StratumServerConfig;
use crate::core::core::hash::{Hash, Hashed, ZERO_HASH};
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::{get_grin_magic_data_str, Block};
use crate::core::pow::{compact_to_biguint, compact_to_diff, hash_to_biguint};
use crate::keychain;
use crate::mining::mine_block;
use crate::pool;
use crate::util;

// ----------------------------------------
// http://www.jsonrpc.org/specification
// RPC Methods

const COIN_BASE_PART1: &'static str = "00";
const COIN_BASE_EXTRA_NOUNCE1: &'static str = "00000000";

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
	id: Option<i32>,
	method: String,
	params: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
	id: Option<i32>,
	result: Option<Value>,
	error: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JobTemplate {
	job_id: String,
	pre_hash: String,
	coinbase1: String,
	coinbase2: String,
	merkle_branch: Vec<Hash>,
	version: String,
	bits: String,
	timestamp: String,
	is_clear: bool,
}

impl Default for JobTemplate {
	fn default() -> JobTemplate {
		JobTemplate {
			job_id: String::default(),
			pre_hash: "0000000000000000000000000000000000000000000000000000000000000000"
				.to_string(),
			coinbase1: COIN_BASE_PART1.to_string(),
			coinbase2: String::default(),
			merkle_branch: Vec::new(),
			version: "00000000".to_string(),
			bits: String::default(),
			timestamp: String::default(),
			is_clear: false,
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WorkerStatus {
	id: String,
	height: u64,
	difficulty: u64,
	accepted: u64,
	rejected: u64,
	stale: u64,
}

// ----------------------------------------
// Worker Factory Thread Function

// Run in a thread. Adds new connections to the workers list
fn accept_workers(
	id: String,
	address: String,
	workers: &mut Arc<Mutex<Vec<Worker>>>,
	stratum_stats: &mut Arc<RwLock<StratumStats>>,
) {
	let listener = TcpListener::bind(address).expect("Failed to bind to listen address");
	let mut worker_id: u32 = 0;
	for stream in listener.incoming() {
		match stream {
			Ok(stream) => {
				warn!(
					"(Server ID: {}) New connection: {}",
					id,
					stream.peer_addr().unwrap()
				);
				stream
					.set_nonblocking(true)
					.expect("set_nonblocking call failed");
				let worker = Worker::new(worker_id.to_string(), BufStream::new(stream));
				workers.lock().push(worker);
				// stats for this worker (worker stat objects are added and updated but never
				// removed)
				let mut worker_stats = WorkerStats::default();
				worker_stats.is_connected = true;
				worker_stats.id = worker_id.to_string();
				worker_stats.pow_difficulty = 1; // XXX TODO
				let mut stratum_stats = stratum_stats.write();
				stratum_stats.worker_stats.push(worker_stats);
				worker_id = worker_id + 1;
			}
			Err(e) => {
				warn!("(Server ID: {}) Error accepting connection: {:?}", id, e);
			}
		}
	}
	// close the socket server
	drop(listener);
}

// ----------------------------------------
// Worker Object - a connected stratum client - a miner, pool, proxy, etc...

pub struct Worker {
	id: String,
	stream: BufStream<TcpStream>,
	error: bool,
	authenticated: bool,
}

impl Worker {
	/// Creates a new Stratum Worker.
	pub fn new(id: String, stream: BufStream<TcpStream>) -> Worker {
		Worker {
			id: id,
			stream: stream,
			error: false,
			authenticated: false,
		}
	}

	// Get Message from the worker
	fn read_message(&mut self, line: &mut String) -> Option<usize> {
		// Read and return a single message or None
		match self.stream.read_line(line) {
			Ok(n) => {
				return Some(n);
			}
			Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
				// Not an error, just no messages ready
				return None;
			}
			Err(e) => {
				warn!(
					"(Worker ID: {}) Error in connection with stratum client: {}",
					self.id, e
				);
				self.error = true;
				return None;
			}
		}
	}

	// Send Message to the worker
	fn write_message(&mut self, mut message: String) {
		// Write and Flush the message
		if !message.ends_with("\n") {
			message += "\n";
		}
		warn!("Worker ID: {}------write message:{}", self.id, message);
		match self.stream.write(message.as_bytes()) {
			Ok(_) => match self.stream.flush() {
				Ok(_) => {}
				Err(e) => {
					warn!(
						"(Worker ID: {}) Error in connection with stratum client: {}",
						self.id, e
					);
					self.error = true;
				}
			},
			Err(e) => {
				warn!(
					"(Worker ID: {}) Error in connection with stratum client: {}",
					self.id, e
				);
				self.error = true;
				return;
			}
		}
	}
} // impl Worker

// ----------------------------------------
// Grin Stratum Server

pub struct StratumServer {
	id: String,
	config: StratumServerConfig,
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool>>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	current_block_versions: HashMap<Hash, (Block, String)>,
	current_newest_block_hash: Hash,
	current_difficulty: u32,
	current_key_id: Option<keychain::Identifier>,
	workers: Arc<Mutex<Vec<Worker>>>,
	sync_state: Arc<SyncState>,
	stratum_stats: Arc<RwLock<StratumStats>>,
}

impl StratumServer {
	/// Creates a new Stratum Server.
	pub fn new(
		config: StratumServerConfig,
		chain: Arc<chain::Chain>,
		tx_pool: Arc<RwLock<pool::TransactionPool>>,
		verifier_cache: Arc<RwLock<dyn VerifierCache>>,
		stratum_stats: Arc<RwLock<StratumStats>>,
	) -> StratumServer {
		StratumServer {
			id: String::from("0"),
			config,
			chain,
			tx_pool,
			verifier_cache,
			current_block_versions: HashMap::new(),
			current_newest_block_hash: ZERO_HASH,
			current_difficulty: 0,
			current_key_id: None,
			workers: Arc::new(Mutex::new(Vec::new())),
			sync_state: Arc::new(SyncState::new()),
			stratum_stats: stratum_stats,
		}
	}

	// Build and return a JobTemplate for mining the current block
	fn build_block_template(&self) -> JobTemplate {
		let block_pair = self
			.current_block_versions
			.get(&self.current_newest_block_hash);
		match block_pair {
			Some((block, coinbase)) => {
				let job_template = JobTemplate {
					job_id: self.current_newest_block_hash.to_hex(),
					coinbase2: coinbase.to_string(),
					bits: format!("{:08x}", block.header.bits),
					timestamp: format!("{:08x}", block.header.timestamp.timestamp()),
					is_clear: true,
					..Default::default()
				};
				job_template
			}
			_ => JobTemplate::default(),
		}
	}

	// Handle an RPC request message from the worker(s)
	fn handle_rpc_requests(&mut self, stratum_stats: &mut Arc<RwLock<StratumStats>>) {
		let mut workers_l = self.workers.lock();
		let mut the_message = String::with_capacity(4096);
		for num in 0..workers_l.len() {
			match workers_l[num].read_message(&mut the_message) {
				Some(_) => {
					// Decompose the request from the JSONRpc wrapper
					debug!(
						"(Worker ID: {})get request:{}",
						workers_l[num].id,
						the_message.as_str()
					);
					let request: RpcRequest = match serde_json::from_str(&the_message) {
						Ok(request) => request,
						Err(e) => {
							// not a valid JSON RpcRequest - disconnect the worker
							info!(
								"(Server ID: {}) Failed to parse JSONRpc: {} - {:?}",
								self.id,
								e.description(),
								the_message.as_bytes(),
							);
							workers_l[num].error = true;
							the_message.clear();
							continue;
						}
					};

					the_message.clear();

					let mut stratum_stats = stratum_stats.write();
					let worker_stats_id = stratum_stats
						.worker_stats
						.iter()
						.position(|r| r.id == workers_l[num].id)
						.unwrap();
					stratum_stats.worker_stats[worker_stats_id].last_seen = SystemTime::now();

					// Call the handler function for requested method
					let response: Result<Value, Value> = match request.method.as_str() {
						"mining.subscribe" => {
							stratum_stats.worker_stats[worker_stats_id].initial_block_height =
								if let Some((block, _)) = self
									.current_block_versions
									.get(&self.current_newest_block_hash)
								{
									block.header.height
								} else {
									0
								};

							let mut ret: Vec<Value> = Vec::new();
							let mut temp_vec: Vec<Value> = Vec::new();
							temp_vec.push(
								serde_json::to_value(vec![
									"mining.set_difficulty".to_string(),
									"".to_string(),
								])
								.unwrap(),
							);
							temp_vec.push(
								serde_json::to_value(vec![
									"mining.notify".to_string(),
									"".to_string(),
								])
								.unwrap(),
							);
							ret.push(serde_json::to_value(temp_vec).unwrap());
							ret.push(
								serde_json::to_value(COIN_BASE_EXTRA_NOUNCE1.to_string()).unwrap(),
							);
							ret.push(serde_json::to_value(4).unwrap());
							Ok(serde_json::to_value(ret).unwrap())
						}
						"mining.submit" => {
							let res = self.handle_submit(
								request.params,
								&mut workers_l[num],
								&mut stratum_stats.worker_stats[worker_stats_id],
							);
							// this key_id has been used now, reset
							if let Ok((_, true)) = res {
								self.current_key_id = None;
							}
							Ok(serde_json::to_value(true).unwrap())
						}
						"mining.authorize" => {
							workers_l[num].authenticated = true;
							Ok(serde_json::to_value(true).unwrap())
						}
						_ => {
							// Called undefined method
							let e = "Method not found".to_string();
							Err(serde_json::to_value(e).unwrap())
						}
					};

					// Package the reply as RpcResponse json
					let rpc_response: String;
					match response {
						Err(err) => {
							let resp = RpcResponse {
								id: request.id,
								result: None,
								error: Some(err),
							};
							rpc_response = serde_json::to_string(&resp).unwrap();
						}
						Ok(res) => {
							let resp = RpcResponse {
								id: request.id,
								result: Some(res),
								error: None,
							};
							rpc_response = serde_json::to_string(&resp).unwrap();
						}
					}

					// Send the reply
					workers_l[num].write_message(rpc_response);
				}
				None => {} // No message for us from this worker
			}
		}
	}

	// Handle SUBMIT message
	// params contains a solved block header
	// We accept and log valid shares of all difficulty above configured minimum
	// Accepted shares that are full solutions will also be submitted to the
	// network
	fn handle_submit(
		&self,
		params: Option<Value>,
		_worker: &mut Worker,
		worker_stats: &mut WorkerStats,
	) -> Result<(Value, bool), Value> {
		// Validate parameters
		let params: Vec<String> = parse_params(params)?;

		if params.len() != 5 {
			return Err(serde_json::to_value(false).unwrap());
		}

		let job_id = params[1].clone();
		let extra_nonce_2_str = params[2].clone();
		let timestamp_str = params[3].clone();
		let timestamp = u32::from_str_radix(&timestamp_str, 16).unwrap();
		let nonce_str = params[4].clone();
		let nounce = u32::from_str_radix(&nonce_str, 16).unwrap();

		// Find the correct version of the block to match this header
		let submit_hash = Hash::from_hex(&job_id);
		if submit_hash.is_err()
			|| self
				.current_block_versions
				.get(&submit_hash.clone().unwrap())
				.is_none()
		{
			// Return error status
			error!(
				"(Server ID: {}) Share at job_id {} submitted too late",
				self.id, job_id,
			);
			worker_stats.num_stale += 1;
			return Err(serde_json::to_value(false).unwrap());
		}

		let (block, coinbase2) = self
			.current_block_versions
			.get(&submit_hash.unwrap())
			.unwrap();
		let coin_base_str = format!(
			"{}{}{}{}",
			COIN_BASE_PART1, COIN_BASE_EXTRA_NOUNCE1, extra_nonce_2_str, coinbase2
		);
		trace!("build coin base:{}", coin_base_str);
		let coin_base_data = util::from_hex(coin_base_str);
		if coin_base_data.is_err() {
			return Err(serde_json::to_value(false).unwrap());
		}
		let mut submit_block = block.clone();
		submit_block.aux_data.coinbase_tx = coin_base_data.unwrap();
		submit_block.aux_data.aux_header.version = 0;
		submit_block.aux_data.aux_header.prev_hash = ZERO_HASH;
		submit_block.aux_data.aux_header.merkle_root = submit_block
			.aux_data
			.coinbase_tx
			.dhash()
			.dhash_with(ZERO_HASH);
		submit_block.aux_data.aux_header.mine_time = timestamp;
		submit_block.aux_data.aux_header.nbits = block.header.bits;
		submit_block.aux_data.aux_header.nonce = nounce;
		submit_block.aux_data.merkle_branch = vec![ZERO_HASH];

		let btc_header_hash = submit_block.aux_data.aux_header.dhash();
		let cur_diff = hash_to_biguint(btc_header_hash);
		let target_diff_option = compact_to_biguint(submit_block.header.bits);
		if target_diff_option.is_none() {
			return Err(serde_json::to_value(false).unwrap());
		}

		let target_diff = target_diff_option.unwrap();
		if cur_diff > target_diff {
			worker_stats.num_rejected += 1;
			return Err(serde_json::to_value(false).unwrap());
		}

		let res = self
			.chain
			.process_block(submit_block.clone(), chain::Options::MINE);
		if let Err(e) = res {
			// Return error status
			error!(
				"(Server ID: {}) Failed to validate solution at height {}, hash {}, {}: {}",
				self.id,
				submit_block.header.height,
				submit_block.hash(),
				e,
				e.backtrace().unwrap(),
			);
			worker_stats.num_rejected += 1;
			return Err(serde_json::to_value(false).unwrap());
		}
		worker_stats.num_blocks_found += 1;
		// Log message to make it obvious we found a block
		warn!(
			"(Server ID: {}) Solution Found for block {}, hash {} - Yay!!! Worker ID: {}, blocks found: {}, shares: {}",
			self.id,
			submit_block.header.height,
			submit_block.hash(),
			worker_stats.id,
			worker_stats.num_blocks_found,
			worker_stats.num_accepted,
		);

		worker_stats.num_accepted += 1;

		return Ok((serde_json::to_value(true).unwrap(), true));
	} // handle submit a solution

	// Purge dead/sick workers - remove all workers marked in error state
	fn clean_workers(&mut self, stratum_stats: &mut Arc<RwLock<StratumStats>>) -> usize {
		let mut start = 0;
		let mut workers_l = self.workers.lock();
		loop {
			for num in start..workers_l.len() {
				if workers_l[num].error == true {
					warn!(
						"(Server ID: {}) Dropping worker: {}",
						self.id, workers_l[num].id
					);
					// Update worker stats
					let mut stratum_stats = stratum_stats.write();
					let worker_stats_id = stratum_stats
						.worker_stats
						.iter()
						.position(|r| r.id == workers_l[num].id)
						.unwrap();
					stratum_stats.worker_stats[worker_stats_id].is_connected = false;
					// Remove the dead worker
					workers_l.remove(num);
					break;
				}
				start = num + 1;
			}
			if start >= workers_l.len() {
				let mut stratum_stats = stratum_stats.write();
				stratum_stats.num_workers = workers_l.len();
				return stratum_stats.num_workers;
			}
		}
	}

	// Broadcast a jobtemplate RpcRequest to all connected workers - no response
	// expected
	fn broadcast_job(&mut self, clear_job: bool) {
		// Package new block into RpcRequest
		let job_template = self.build_block_template();

		let mut ret: Vec<Value> = Vec::new();
		let merkle_branch: Vec<String> = vec![ZERO_HASH.to_hex()];
		ret.push(serde_json::to_value(job_template.job_id.clone()).unwrap());
		ret.push(serde_json::to_value(job_template.pre_hash).unwrap());
		ret.push(serde_json::to_value(job_template.coinbase1).unwrap());
		ret.push(serde_json::to_value(job_template.coinbase2).unwrap());
		ret.push(serde_json::to_value(merkle_branch).unwrap());
		ret.push(serde_json::to_value(job_template.version).unwrap());
		ret.push(serde_json::to_value(job_template.bits).unwrap());
		ret.push(serde_json::to_value(job_template.timestamp).unwrap());
		ret.push(serde_json::to_value(clear_job).unwrap());

		let response = serde_json::to_value(ret).unwrap();
		let job_request = RpcRequest {
			id: None,
			method: String::from("mining.notify"),
			params: Some(response),
		};

		let job_request_json = serde_json::to_string(&job_request).unwrap();
		debug!(
			"(Server ID: {}) sending block with id {} to stratum clients",
			self.id, job_template.job_id,
		);
		// Push the new block to all connected clients
		// NOTE: We do not give a unique nonce (should we?) so miners need
		//       to choose one for themselves
		let mut workers_l = self.workers.lock();
		for num in 0..workers_l.len() {
			if workers_l[num].authenticated {
				workers_l[num].write_message(job_request_json.clone());
			}
		}
	}

	fn broadcast_difficulty(&mut self) {
		let diff = compact_to_diff(self.current_difficulty);
		let response = serde_json::to_value(vec![diff]).unwrap();
		let diff_request = RpcRequest {
			id: None,
			method: String::from("mining.set_difficulty"),
			params: Some(response),
		};

		let diff_json = serde_json::to_string(&diff_request).unwrap();
		// Push the new block to all connected clients
		// NOTE: We do not give a unique nonce (should we?) so miners need
		//       to choose one for themselves
		let mut workers_l = self.workers.lock();
		for num in 0..workers_l.len() {
			if workers_l[num].authenticated {
				workers_l[num].write_message(diff_json.clone());
			}
		}
	}

	/// "main()" - Starts the stratum-server.  Creates a thread to Listens for
	/// a connection, then enters a loop, building a new block on top of the
	/// existing chain anytime required and sending that to the connected
	/// stratum miner, proxy, or pool, and accepts full solutions to
	/// be submitted.
	pub fn run_loop(&mut self, edge_bits: u32, _proof_size: usize, sync_state: Arc<SyncState>) {
		info!("(Server ID: {}) Starting stratum server", self.id,);

		self.sync_state = sync_state;

		// "globals" for this function
		let attempt_time_per_block = self.config.attempt_time_per_block;
		let mut deadline: i64 = 0;
		// to prevent the wallet from generating a new HD key derivation for each
		// iteration, we keep the returned derivation to provide it back when
		// nothing has changed. We only want to create a key_id for each new block,
		// and reuse it when we rebuild the current block to add new tx.
		let mut num_workers: usize;
		let mut head = self.chain.head().unwrap();
		let mut current_hash = head.prev_block_h;
		let mut latest_hash;
		let listen_addr = self.config.stratum_server_addr.clone().unwrap();
		self.current_block_versions
			.insert(ZERO_HASH, (Block::default(), String::default()));

		// Start a thread to accept new worker connections
		let mut workers_th = self.workers.clone();
		let id_th = self.id.clone();
		let mut stats_th = self.stratum_stats.clone();
		let _listener_th = thread::spawn(move || {
			accept_workers(id_th, listen_addr, &mut workers_th, &mut stats_th);
		});

		// We have started
		{
			let mut stratum_stats = self.stratum_stats.write();
			stratum_stats.is_running = true;
			stratum_stats.edge_bits = edge_bits as u16;
		}

		warn!(
			"Stratum server started on {}",
			self.config.stratum_server_addr.clone().unwrap()
		);

		// Initial Loop. Waiting node complete syncing
		while self.sync_state.is_syncing() {
			self.clean_workers(&mut self.stratum_stats.clone());

			// Handle any messages from the workers
			self.handle_rpc_requests(&mut self.stratum_stats.clone());

			warn!("Stratum server wating for node syncing...");
			thread::sleep(Duration::from_secs(2));
		}

		// Main Loop
		loop {
			// Remove workers with failed connections
			num_workers = self.clean_workers(&mut self.stratum_stats.clone());

			// get the latest chain state
			head = self.chain.head().unwrap();
			latest_hash = head.last_block_h;

			// Build a new block if:
			//    There is a new block on the chain
			// or We are rebuilding the current one to include new transactions
			// and there is at least one worker connected
			if (current_hash != latest_hash || Utc::now().timestamp() >= deadline)
				&& num_workers > 0
			{
				let mut wallet_listener_url: Option<String> = None;
				if !self.config.burn_reward {
					wallet_listener_url = Some(self.config.wallet_listener_url.clone());
				}
				// If this is a new block, clear the current_block version history
				let mut clear_prev_job = false;
				if current_hash != latest_hash {
					self.current_block_versions.clear();
					clear_prev_job = true;
				}

				let mut block_pair: Option<(Block, mine_block::BlockFees)> = None;
				let mut solve = false;
				while !solve {
					// Build the new block (version)
					let (mut new_block, block_fees) = mine_block::get_block(
						&self.chain,
						&self.tx_pool,
						self.verifier_cache.clone(),
						self.current_key_id.clone(),
						wallet_listener_url.clone(),
					);

					let head = self.chain.head_header().unwrap();
					solve = mine_block::get_grin_solution(&mut new_block, &head);
					if solve {
						block_pair = Some((new_block, block_fees));
					}
				}
				let (new_block, block_fees) = block_pair.unwrap();

				self.current_newest_block_hash = new_block.header.hash();
				self.current_difficulty = new_block.header.bits;
				self.current_key_id = block_fees.key_id();
				// Add this new block version to our current block map
				self.current_block_versions.insert(
					self.current_newest_block_hash,
					(
						new_block.clone(),
						get_grin_magic_data_str(self.current_newest_block_hash),
					),
				);

				current_hash = latest_hash;
				// set a new deadline for rebuilding with fresh transactions
				deadline = Utc::now().timestamp() + attempt_time_per_block as i64;

				{
					let mut stratum_stats = self.stratum_stats.write();
					stratum_stats.block_height = new_block.header.height;
					stratum_stats.network_difficulty = self.current_difficulty;
				}

				// Send this job to all connected workers
				self.broadcast_job(clear_prev_job);
				self.broadcast_difficulty();
			}

			// Handle any messages from the workers
			self.handle_rpc_requests(&mut self.stratum_stats.clone());

			// sleep before restarting loop
			thread::sleep(Duration::from_micros(1));
		} // Main Loop
	} // fn run_loop()
} // StratumServer

// Utility function to parse a JSON RPC parameter object, returning a proper
// error if things go wrong.
fn parse_params<T>(params: Option<Value>) -> Result<T, Value>
where
	for<'de> T: serde::Deserialize<'de>,
{
	params
		.and_then(|v| serde_json::from_value(v).ok())
		.ok_or_else(|| {
			let e = "Invalid Request".to_string();
			serde_json::to_value(e).unwrap()
		})
}
