extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate socksv5_future;

use std::net::SocketAddr;
use socksv5_future::socks_handshake;
use futures::{Future,Stream};
use tokio_core::reactor::Core;
use tokio_core::net::{TcpListener,TcpStream};

#[test]
fn test_tcp_connection() {
    let mut lp = Core::new().unwrap();
    let addr: SocketAddr = "127.0.0.1:64000".parse().unwrap();
    let handle = lp.handle();
    let handle2= handle.clone();
    let listener = TcpListener::bind(&addr, &handle).unwrap();
    let server = listener.incoming().for_each(move |(stream, _addr)| {
        handle2.spawn(
            socks_handshake(stream)
                    .then( |_| { Ok(())})
        );
        Ok(())
    }).then( |_| { Ok(())});
    handle.clone().spawn(server);

    let test_conn = TcpStream::connect(&addr, &handle);
    lp.run(test_conn).unwrap();
}
