use crate::chain;
use crate::common::types::PoolServerConfig;
use crate::core::core::verifier_cache::VerifierCache;
use crate::pool;
use crate::util::{Mutex, RwLock, StopState};
use std::sync::Arc;

mod controller;
mod error;
mod handle_block;
mod types;

pub use controller::SubmitInfo;
pub use handle_block::JobInfo;

pub fn start_poolserver_service(
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool>>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	pool_server_config: PoolServerConfig,
	stop_state: Arc<Mutex<StopState>>,
) {
	let handler = handle_block::BlockHandler::new(
		chain,
		tx_pool,
		verifier_cache,
		stop_state,
		pool_server_config.wallet_listener_url,
		pool_server_config.chain_notify_url,
	);

	let result =
		controller::start_pool_server(handler, pool_server_config.pool_server_addr.as_str(), None);

	match result {
		Ok(_) => {
			warn!("start_pool_server suc");
		}
		Err(e) => {
			info!("start_pool_server failed: {:?}", e);
		}
	}
}
