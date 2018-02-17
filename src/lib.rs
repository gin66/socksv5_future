extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate bytes;

mod socks_fut;

pub use socks_fut::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
