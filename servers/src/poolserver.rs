use crate::chain;
use crate::common::types::PoolServerConfig;
use crate::util::StopState;
use crate::ServerTxPool;
use std::sync::Arc;

pub mod controller;
pub mod handle_block;

pub fn start_poolserver_service(
	chain: Arc<chain::Chain>,
	tx_pool: ServerTxPool,
	pool_server_config: PoolServerConfig,
	stop_state: Arc<StopState>,
) {
	let handler = handle_block::BlockHandler::new(
		chain,
		tx_pool,
		stop_state,
		pool_server_config.wallet_listener_url,
		pool_server_config.chain_notify_url,
		pool_server_config.chain_notify_url_v2.unwrap_or(vec![]),
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
