use std::convert::From;

use crate::api;
use crate::chain;
use crate::core::{core, pow};
use crate::pool;
use crate::wallet;

/// Error type wrapping underlying module errors.
#[derive(Debug)]
pub enum Error {
	/// Error originating from the core implementation.
	Core(core::block::Error),
	/// Error originating from the blockchain implementation.
	Chain(chain::Error),
	/// Error originating from HTTP API calls.
	API(api::Error),
	/// Error originating from wallet API.
	Wallet(wallet::Error),
	/// Error originating from the cuckoo miner
	Cuckoo(pow::Error),
	/// Error originating from the transaction pool.
	Pool(pool::PoolError),
	///// Invalid Arguments.
	//ArgumentError(String),
}

impl From<core::block::Error> for Error {
	fn from(e: core::block::Error) -> Error {
		Error::Core(e)
	}
}
impl From<chain::Error> for Error {
	fn from(e: chain::Error) -> Error {
		Error::Chain(e)
	}
}

impl From<pow::Error> for Error {
	fn from(e: pow::Error) -> Error {
		Error::Cuckoo(e)
	}
}

impl From<api::Error> for Error {
	fn from(e: api::Error) -> Error {
		Error::API(e)
	}
}

impl From<wallet::Error> for Error {
	fn from(e: wallet::Error) -> Error {
		Error::Wallet(e)
	}
}

impl From<pool::PoolError> for Error {
	fn from(e: pool::PoolError) -> Error {
		Error::Pool(e)
	}
}
