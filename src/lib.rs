extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

mod socks_fut;

#[allow(dead_code)]
mod v5;

pub use socks_fut::*;