extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate socksv5_future;

use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;
use socksv5_future::socks_handshake;
use futures::{Future,Stream};
use futures::future::Either;
use tokio_core::reactor::Core;
use tokio_core::net::{TcpListener,TcpStream};
use tokio_io::io::{read_exact, write_all};

#[test]
fn test_tcp_connection_send_v5auth_without_no_auth() {
    let mut lp = Core::new().unwrap();
    let addr: SocketAddr = "127.0.0.1:64002".parse().unwrap();
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

    let test_conn = TcpStream::connect(&addr, &handle)
        .and_then({|stream|
            write_all(stream,[5u8,1u8,1u8])
        })
        .and_then({|(stream,_buf)|
            read_exact(stream,[0u8;2])
        })
        .and_then({|(stream,_buf)|
            read_exact(stream,[0u8;2])
        })
        ;
    let timeout = tokio_core::reactor::Timeout::new(
                    Duration::from_millis(1000), &handle).unwrap();

    let timed_testcase = test_conn.select2(timeout).then(|res| match res {
            Ok(Either::A((got, _timeout))) => Ok(got),
            Ok(Either::B((_timeout_error, _get))) => {
                Err(Error::new(ErrorKind::Other, 
                                "Reserved field in socks5 response is not 0x00"))
            }
            Err(Either::A((get_error, _timeout))) => Err(get_error),
            Err(Either::B((timeout_error, _get))) => Err(From::from(timeout_error)),
        });

    let res = lp.run(timed_testcase);
    match res {
        Ok(_x) => assert!(false),
        Err(error) => 
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof)
    }
}
