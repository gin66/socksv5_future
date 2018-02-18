# socksv5_future

The socks5 protocol consists of a handshake in these steps:
1. Client establish TCP connection to a socks5 server
2. Client sends authentication request with list of supported authentication methods.
3. Server selects an appropriate authentication method and sends this back to client.
4. Client sends socks5 request, which primarily contains destination address and port
5. Server establishes connection to destination and answers client's request

This is the implementation of two Futures:
- SocksHandshake
- SocksConnectHandshake

As per RFC 1928, this is not a compliant socks5 implementation, because
GSSAPI authentication method is not supported.

## SocksHandshake
This is the server side implementation. It implements the step 2 to 4. Step 5 is not performed by this future. Instead the socks5 request is part of the future result.

## SocksConnectHandshake
This is the client side implementation. It performs step 2-5.

## Use case socks5 forwarder
The socks5 request from the client is used unchanged and sent to the forwarded socks proxy.
Here short code segment to show the principal idea (this code will not compile):
```rust
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let addr = "127.0.0.1:8888".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(&addr, &handle2).unwrap();
    let server = listener.incoming().for_each(move |(socket, _addr)| {
        handle.spawn(
            socks_handshake(socket)
                .and_then(move |(source,addr,request,_port,_cmd)| {
                    let proxy = "xx.xx.xx.xx:8888".parse::<SocketAddr>().unwrap();
                    let connect = TcpStream::connect(&proxy,&handle);
                    connect.and_then(move |dest|{
                        socks_connect_handshake(dest,request)
                    })
                    .and_then(|(stream,req_answer)|{
                        write_all(source,req_answer)
                    })
                    .and_then(|(stream,buf)|{
                        // perform transfer source<->stream
                    });
                })
        );
        Ok(())
    });
    handle.spawn(server)
```

[![Build Status](https://travis-ci.org/gin66/socksv5_future.svg?branch=master)](https://travis-ci.org/gin66/socksv5_future)



