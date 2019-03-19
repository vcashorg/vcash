use futures::future::{err, ok};
use futures::{Future, Stream};
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use crate::api::{ApiServer, /*BasicAuthMiddleware,*/ Handler, ResponseFuture, Router, TLSConfig,};
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::{AuxBitHeader, Block};
use crate::util;

use crate::core::consensus::reward;
use crate::poolserver::error::{Error, ErrorKind};
use crate::poolserver::handle_block::BlockHandler;
use crate::poolserver::handle_block::JobInfo;

pub fn start_pool_server(
	handler: BlockHandler,
	addr: &str,
	tls_config: Option<TLSConfig>,
) -> Result<(), String> {
	let api_handler = OwnerAPIHandler::new(handler.clone());

	let mut router = Router::new();
	//    if api_secret.is_some() {
	//        let api_basic_auth =
	//            "Basic ".to_string() + &to_base64(&("grin:".to_string() + &api_secret.unwrap()));
	//        let basic_realm = "Basic realm=GrinOwnerAPI".to_string();
	//        let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(api_basic_auth, basic_realm));
	//        router.add_middleware(basic_auth_middleware);
	//    }
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

	fn handle_get_request(&self, req: &Request<Body>) -> Result<Response<Body>, Error> {
		Ok(
			match req
				.uri()
				.path()
				.trim_end_matches("/")
				.rsplit("/")
				.next()
				.unwrap()
			{
				"getauxblock" => {
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
							json_response(&info)
						}
						Err(e) => response(StatusCode::BAD_REQUEST, e),
					}
				}
				_ => response(StatusCode::BAD_REQUEST, ""),
			},
		)
	}

	fn handle_post_request(
		&self,
		req: Request<Body>,
	) -> Box<dyn Future<Item = (), Error = Error> + Send> {
		match req
			.uri()
			.path()
			.trim_end_matches("/")
			.rsplit("/")
			.next()
			.unwrap()
		{
			"submitauxblock" => {
				let clone_handler = self.real_handler.clone();
				Box::new(
					parse_body(req)
						.and_then(move |job_info: SubmitInfo| {
							let header_hash_result = Hash::from_hex(job_info.header_hash.as_str());
							let mut block_data_ref: Option<Block>;
							match header_hash_result.clone() {
								Ok(header_hash) => {
									let result =
										clone_handler.get_miningblock_by_hash(&header_hash);
									match result {
										Ok(block) => block_data_ref = Some(block),
										Err(e) => {
											return err(ErrorKind::GenericError(e).into());
										}
									}
								}
								Err(e) => {
									return err(ErrorKind::GenericError(
										format!("fail to decode hash string to Hash:{}", e)
											.to_string(),
									)
									.into());
								}
							}

							let mut block_data = block_data_ref.unwrap();

							let btc_header_result =
								AuxBitHeader::from_hex(job_info.btc_header.as_str());
							if btc_header_result.is_err() {
								return err(ErrorKind::GenericError(
									btc_header_result.clone().err().unwrap(),
								)
								.into());
							}

							let btc_coinbase_result = util::from_hex(job_info.btc_coinbase.clone());
							if btc_coinbase_result.is_err() {
								return err(ErrorKind::GenericError(
									"btc coinbase fail to deserilise from hex".to_string(),
								)
								.into());
							}

							let mut str_vec: Vec<&str> = Vec::new();
							let branch = job_info.btc_merkle_branch.as_str();
							if branch.len() % 64 != 0 {
								return err(ErrorKind::GenericError(
									format!("btc merkle branch len is not right:{}", branch.len())
										.to_string(),
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
								let branch_item_ret = util::from_hex(str.to_string());
								if branch_item_ret.is_err() {
									return err(ErrorKind::GenericError(
										format!(
											"btc merkle branch item can not transfer to vecu8:{}",
											str
										)
										.to_string(),
									)
									.into());
								}
								let mut branch_item = branch_item_ret.unwrap();
								branch_item.reverse();
								let hash = Hash::from_vec(&branch_item);
								hash_vec.push(hash);
							}

							// This is a full solution, submit it to the network
							block_data.aux_data.aux_header = btc_header_result.unwrap();
							block_data.aux_data.merkle_branch = hash_vec;
							block_data.aux_data.coinbase_tx = btc_coinbase_result.unwrap();
							//pipe::validate_block_auxdata(&block_data);

							let response = match clone_handler.submit_block(block_data) {
								Ok(_) => ok(()),
								Err(str) => err(ErrorKind::GenericError(str).into()),
							};
							response
						})
						.or_else(|e| err(e)),
				)
			}
			_ => Box::new(err(ErrorKind::GenericError("wrong uri".to_string()).into())),
		}
	}
}

impl Handler for OwnerAPIHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		match self.handle_get_request(&req) {
			Ok(r) => Box::new(ok(r)),
			Err(e) => {
				error!("Request Error: {:?}", e);
				Box::new(ok(create_error_response(e)))
			}
		}
	}

	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|_| ok(response(StatusCode::OK, "")))
				.or_else(|e| ok(response(StatusCode::BAD_REQUEST, format!("Error: {:?}", e)))),
		)
	}
}

// Utility to serialize a struct into JSON and produce a sensible Response
// out of it.
fn json_response<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

fn response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
	Response::builder()
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(text.into())
		.unwrap()
}

fn create_error_response(e: Error) -> Response<Body> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(format!("{}", e).into())
		.unwrap()
}

fn parse_body<T>(req: Request<Body>) -> Box<dyn Future<Item = T, Error = Error> + Send>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	Box::new(
		req.into_body()
			.concat2()
			.map_err(|_| ErrorKind::GenericError("Failed to read request".to_owned()).into())
			.and_then(|body| match serde_json::from_reader(&body.to_vec()[..]) {
				Ok(obj) => ok(obj),
				Err(e) => {
					err(ErrorKind::GenericError(format!("Invalid request body: {}", e)).into())
				}
			}),
	)
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
