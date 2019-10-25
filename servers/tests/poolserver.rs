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
extern crate log;

use self::core::global::{self, ChainTypes};
use self::p2p::PeerAddr;
use crate::core::core::get_grin_magic_data_str;
use crate::core::core::hash::{Hash, Hashed};
use crate::servers::JobInfo;
use crate::servers::SubmitInfo;
use grin_api as api;
use grin_core as core;
use grin_core::core::BlockAuxData;
use grin_p2p as p2p;
use grin_servers as servers;
use grin_util as util;
use std::net::TcpStream;
use std::{fs, thread, time};

/// return pool server config
#[allow(dead_code)]
pub fn pool_server_config() -> servers::common::types::PoolServerConfig {
	servers::common::types::PoolServerConfig {
		enable_pool_server: true,
		pool_server_addr: String::from("127.0.0.1:13517"),
		wallet_listener_url: None,
		chain_notify_url: vec![String::from("10.0.0.137:13530/test")],
	}
}

/// Just removes all results from previous runs
pub fn clean_all_output(test_name_dir: &str) {
	let target_dir = format!("target/tmp/{}", test_name_dir);
	if let Err(e) = fs::remove_dir_all(target_dir) {
		println!("can't remove output from previous test :{}, may be ok", e);
	}
}

/// Create and return a ServerConfig
#[allow(dead_code)]
pub fn config(n: u16, test_name_dir: &str, seed_n: u16) -> servers::ServerConfig {
	servers::ServerConfig {
		api_http_addr: format!("127.0.0.1:{}", 20000 + n),
		api_secret_path: None,
		db_root: format!("target/tmp/{}/grin-sync-{}", test_name_dir, n),
		p2p_config: p2p::P2PConfig {
			port: 10000 + n,
			seeding_type: p2p::Seeding::List,
			seeds: Some(vec![PeerAddr(
				format!("127.0.0.1:{}", 10000 + seed_n).parse().unwrap(),
			)]),
			..p2p::P2PConfig::default()
		},
		chain_type: core::global::ChainTypes::AutomatedTesting,
		archive_mode: Some(true),
		skip_sync_wait: Some(true),
		..Default::default()
	}
}

// Create a grin server, and a pool server.
// Simulate a few JSONRpc requests and verify the results.
// Validate disconnected workers
// Validate broadcasting new jobs
#[test]
fn test_pool_server() {
	util::init_test_logger();
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let test_name_dir = "pool_server";
	clean_all_output(test_name_dir);

	// Create a server
	let s = servers::Server::new(config(4000, test_name_dir, 0)).unwrap();

	// Get mining config with stratumserver enabled
	let pool_server_cfg = pool_server_config();

	// Start stratum server
	s.start_pool_server(pool_server_cfg.clone());

	// Wait for pool server to start rightly
	loop {
		if let Ok(_stream) = TcpStream::connect(pool_server_cfg.pool_server_addr.as_str()) {
			break;
		} else {
			thread::sleep(time::Duration::from_millis(500));
		}
		// As this stream falls out of scope it will be disconnected
	}
	println!("pool server connected");
	// Wait for pool server find grin solution.
	thread::sleep(time::Duration::from_millis(3 * 1000));

	let uri_get = format!(
		"http://{}/v1/pool/getauxblock",
		pool_server_cfg.pool_server_addr
	);
	let uri_post = format!(
		"http://{}/v1/pool/submitauxblock",
		pool_server_cfg.pool_server_addr
	);

	let res_ret = api::client::get::<JobInfo>(uri_get.as_str(), None);
	let res: JobInfo = res_ret.unwrap();
	let res_str = serde_json::to_string(&res);
	println!("get suc res: {}", res_str.unwrap());

	let mut aux_data = BlockAuxData::default();
	let coin_base = get_grin_magic_data_str(Hash::from_hex(res.cur_hash.as_str()).unwrap());
	aux_data.coinbase_tx = util::from_hex(coin_base.clone()).unwrap();
	aux_data.aux_header.merkle_root = aux_data.coinbase_tx.clone().dhash();
	let submit_info = SubmitInfo {
		header_hash: res.cur_hash,
		btc_header: aux_data.aux_header.to_hex(),
		btc_coinbase: coin_base,
		btc_merkle_branch: "".to_string(),
	};

	let req_str = serde_json::to_string(&submit_info);
	println!(
		"begin post at {}, submit_info:{}",
		uri_post,
		req_str.unwrap()
	);
	let res = api::client::post_no_ret(uri_post.as_str(), None, &submit_info);
	assert!(res.is_ok());
	s.stop();

	thread::sleep(time::Duration::from_millis(3 * 1000));

	println!("test_pool_server test done and ok.");
}
