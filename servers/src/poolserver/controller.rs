use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use crate::api::{
	parse_body, response, result_to_response, ApiServer, Error, ErrorKind,
	/*BasicAuthMiddleware,*/ Handler, QueryParams, ResponseFuture, Router, TLSConfig,
};
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::AuxBitHeader;
use crate::core::global;
use crate::util;
use crate::util::ToHex;

use crate::core::consensus::reward;
use crate::poolserver::handle_block::BlockHandler;
use crate::poolserver::handle_block::{JobInfo, SolveBlockWithholdingJobInfo};

pub fn start_pool_server(
	handler: BlockHandler,
	addr: &str,
	tls_config: Option<TLSConfig>,
) -> Result<(), String> {
	let api_handler = OwnerAPIHandler::new(handler.clone());

	let mut router = Router::new();
	router
		.add_route("/v1/pool/**", Arc::new(api_handler))
		.map_err(|e| format!("pool center add route failed,reason:{}", e).to_string())?;

	let mut apis = ApiServer::new();
	info!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	apis.start(socket_addr, router, tls_config)
		.map_err(|e| format!("api_thread start error:{}", e).to_string())?;

	let _ = thread::Builder::new()
		.name("poolserver_miner".to_string())
		.spawn(move || {
			handler.mining_loop();
		});
	Ok(())
}

#[derive(Clone)]
pub struct OwnerAPIHandler {
	real_handler: BlockHandler,
}

impl OwnerAPIHandler {
	/// Create a new owner API handler for GET methods
	pub fn new(handler: BlockHandler) -> OwnerAPIHandler {
		OwnerAPIHandler {
			real_handler: handler,
		}
	}

	fn get_mining_block_v2(
		&self,
		miner_bits: Vec<u32>,
	) -> Result<SolveBlockWithholdingJobInfo, Error> {
		let job_info = self.real_handler.get_bitmining_block_v2(miner_bits);
		match job_info {
			Ok(job_info) => Ok(job_info),
			Err(e) => Err(ErrorKind::Internal(e).into()),
		}
	}

	fn get_mining_block(&self) -> Result<JobInfo, Error> {
		let new_block = self.real_handler.get_bitmining_block();
		match new_block {
			Ok((block, fee)) => {
				let info = JobInfo {
					height: block.header.height,
					cur_hash: block.header.hash().to_hex(),
					prev_hash: block.header.prev_hash.to_hex(),
					bits: block.header.bits,
					base_rewards: reward(block.header.height, 0),
					transactions_fee: fee,
				};
				Ok(info)
			}
			Err(e) => Err(ErrorKind::Internal(e).into()),
		}
	}

	fn submit_aux_block(&self, job_info: SubmitInfo) -> Result<(), Error> {
		let header_hash = Hash::from_hex(job_info.header_hash.as_str()).map_err(|e| {
			ErrorKind::Internal(format!("fail to decode hash string to Hash:{}", e).to_string())
		})?;

		let mut block_data = self
			.real_handler
			.get_miningblock_by_hash(&header_hash)
			.map_err(|e| ErrorKind::Internal(e))?;

		let btc_header = AuxBitHeader::from_hex(job_info.btc_header.as_str())
			.map_err(|e| ErrorKind::Internal(e))?;

		let btc_coinbase = util::from_hex(job_info.btc_coinbase.as_str()).map_err(|_e| {
			ErrorKind::Internal("btc coinbase fail to deserilise from hex".to_string())
		})?;

		let mut str_vec: Vec<&str> = Vec::new();
		let branch = job_info.btc_merkle_branch.as_str();
		if branch.len() % 64 != 0 {
			return Err(ErrorKind::Internal(
				format!("btc merkle branch len is not right:{}", branch.len()).to_string(),
			)
			.into());
		}

		let mut i = 0;
		while branch.len() > i {
			str_vec.push(branch.get(i..i + 64).unwrap());
			i = i + 64;
		}
		//job_info.btc_merkle_branch.as_str().split('-').collect();
		let mut hash_vec: Vec<Hash> = Vec::new();
		for str in str_vec {
			let mut branch_item = util::from_hex(str).map_err(|_e| {
				ErrorKind::Internal(
					format!("btc merkle branch item can not transfer to vecu8:{}", str).to_string(),
				)
			})?;

			branch_item.reverse();
			let hash = Hash::from_vec(&branch_item);
			hash_vec.push(hash);
		}

		// This is a full solution, submit it to the network
		if block_data.header.height >= global::refactor_header_height() {
			block_data.header.btc_pow.aux_header = btc_header;
			block_data.header.btc_pow.merkle_branch = hash_vec;
			block_data.header.btc_pow.coinbase_tx = btc_coinbase;
		} else {
			block_data.aux_data.aux_header = btc_header;
			block_data.aux_data.merkle_branch = hash_vec;
			block_data.aux_data.coinbase_tx = btc_coinbase;
		};

		match self.real_handler.submit_block(block_data) {
			Ok(_) => Ok(()),
			Err(str) => Err(ErrorKind::Internal(str).into()),
		}
	}
}

impl Handler for OwnerAPIHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		match req
			.uri()
			.path()
			.trim_end_matches("/")
			.rsplit("/")
			.next()
			.unwrap()
		{
			"getauxblock" => result_to_response(self.get_mining_block()),
			"getauxblockv2" => {
				let mut miner_bits: Vec<u32> = vec![];

				let query = match req.uri().query() {
					Some(q) => q,
					None => return response(StatusCode::BAD_REQUEST, ""),
				};

				let params = QueryParams::from(query);
				let mut format_error = false;
				params.process_multival_param("minerbits", |bits| {
					let bits = bits.parse::<u32>();
					match bits {
						Ok(bits) => miner_bits.push(bits),
						Err(_) => format_error = true,
					};
				});
				if format_error {
					response(StatusCode::BAD_REQUEST, "")
				} else {
					result_to_response(self.get_mining_block_v2(miner_bits))
				}
			}
			_ => response(StatusCode::BAD_REQUEST, ""),
		}
	}

	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let owner = self.clone();
		match req
			.uri()
			.path()
			.trim_end_matches("/")
			.rsplit("/")
			.next()
			.unwrap()
		{
			"submitauxblock" => Box::pin(async move {
				match parse_body(req).await {
					Ok(val) => match owner.submit_aux_block(val) {
						Ok(_) => Ok(local_response(StatusCode::OK, "{}")),
						Err(e) => Ok(local_response(
							StatusCode::INTERNAL_SERVER_ERROR,
							format!("submitauxblock failed: {}", e),
						)),
					},
					Err(_) => Ok(local_response(StatusCode::BAD_REQUEST, "")),
				}
			}),
			_ => response(StatusCode::BAD_REQUEST, ""),
		}
	}
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn local_response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
	let mut builder = Response::builder();

	builder = builder
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	builder.body(text.into()).unwrap()
}

/// Pool submit info
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubmitInfo {
	/// grin header hash
	pub header_hash: String,
	/// btc header hex
	pub btc_header: String,
	/// btc coinbase hex
	pub btc_coinbase: String,
	/// btc merkle branch hex
	pub btc_merkle_branch: String,
}
