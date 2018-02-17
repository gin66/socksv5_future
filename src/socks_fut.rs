// Socks5-Futures for socks5 proxies
// =================================
//
// As per RFC 1928, this is not a compliant implication, because
// GSSAPI authentication method is not supported.
//
// TODO: Return failures for socks5 requests
//

use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_io::io::{read_exact, write_all, ReadExact, WriteAll};
use tokio_core::net::{TcpStream};
use futures::*;
use futures::Async;
use bytes::{BufMut,Bytes,BytesMut};

#[allow(dead_code)]
mod v5 {
    // as per RFC 1928
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;
    pub const METH_NO_ACCEPTABLE_METHOD: u8 = 255;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;

    pub const REP_SUCCEEDED: u8 = 0;
    pub const REP_GENERAL_FAILURE: u8 = 1;
    pub const REP_NOT_ALLOWED: u8 = 2;
    pub const REP_NETWORK_UNREACHABLE: u8 = 3;
    pub const REP_HOST_UNREACHABLE: u8 = 4;
    pub const REP_CONNECTION_REFUSED: u8 = 5;
    pub const REP_TTL_EXPIRED: u8 = 6;
    pub const REP_CMD_NOT_SUPPORTED: u8 = 7;
    pub const REP_ATYP_NOT_SUPPORTED: u8 = 8;

    // 6 Bytes+2 Bytes for DOMAIN
    pub const MIN_REQUEST_SIZE: usize = 6+2;
    // 6 Bytes+addr (1 Byte length + non terminated string)
    pub const MAX_REQUEST_SIZE: usize = 6+1+255;
}

enum ServerState {
    WaitClientAuthentication(ReadExact<TcpStream,Vec<u8>>),
    ReadAuthenticationMethods(ReadExact<TcpStream,Vec<u8>>),
    AnswerNoAuthentication(WriteAll<TcpStream,Vec<u8>>),
    WaitClientRequest(ReadExact<TcpStream,Vec<u8>>)
}

enum ClientState {
    WaitSentAuthentication(WriteAll<TcpStream,Vec<u8>>),
    WaitAuthenticationMethod(ReadExact<TcpStream,Vec<u8>>),
    WaitSentRequest(WriteAll<TcpStream,Vec<u8>>),
    WaitReply(ReadExact<TcpStream,Vec<u8>>)
}

pub struct SocksHandshake {
    request: BytesMut,
    state: ServerState
}

pub struct SocksConnectHandshake {
    request: Bytes,
    state: ClientState,
    response: BytesMut
}

pub fn socks_handshake(stream: TcpStream) -> SocksHandshake {
    SocksHandshake { 
        request: BytesMut::with_capacity(v5::MAX_REQUEST_SIZE),
        state: ServerState::WaitClientAuthentication(
            read_exact(stream,vec!(0u8;2))
        )
    }
}

pub fn socks_connect_handshake(stream: TcpStream,request: Bytes) -> SocksConnectHandshake {
    SocksConnectHandshake { 
        request,
        state: ClientState::WaitSentAuthentication(
            write_all(stream,vec![v5::VERSION,1u8,v5::METH_NO_AUTH])
        ),
        response: BytesMut::with_capacity(v5::MAX_REQUEST_SIZE)
    }
}

pub enum Command {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3
}

pub enum Addr {
    IP(IpAddr),
    DOMAIN(Vec<u8>)
}

impl Future for SocksHandshake {
    type Item = (TcpStream,Addr,BytesMut,u16,Command);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, io::Error> {
        use self::ServerState::*;

        loop {
            self.state = match self.state {
                WaitClientAuthentication(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    if (buf[0] != v5::VERSION) || (buf[1] == 0) {
                        return Err(Error::new(ErrorKind::Other, "Not Socks5 protocol"));
                    }
                    ReadAuthenticationMethods(
                        read_exact(stream,vec![0u8; buf[1] as usize])
                    )
                }
                ReadAuthenticationMethods(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    let answer = if buf.contains(&v5::METH_NO_AUTH) {
                            v5::METH_NO_AUTH
                        }
                        else {
                            v5::METH_NO_ACCEPTABLE_METHOD
                        };
                    AnswerNoAuthentication(
                        write_all(stream, vec![v5::VERSION, answer])
                    )
                }
                AnswerNoAuthentication(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    if buf[1] == v5::METH_NO_ACCEPTABLE_METHOD {
                        return Err(Error::new(ErrorKind::Other,
                                    "Only 'no authentication' supported"));
                    }
                    WaitClientRequest(
                        read_exact(stream,vec![0u8; v5::MIN_REQUEST_SIZE])
                    )
                }
                WaitClientRequest(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    self.request.put_slice(&buf);
                    if self.request[0] != v5::VERSION {
                        return Err(Error::new(ErrorKind::Other, "Not Socks5 request"))
                    };
                    if self.request[2] != 0 {
                        return Err(Error::new(ErrorKind::Other, 
                                "Reserved field in socks5 request is not 0x00"))
                    };
                    let cmd = match self.request[1] {
                        v5::CMD_CONNECT => Command::Connect,
                        v5::CMD_BIND    => Command::Bind,
                        v5::CMD_UDP_ASSOCIATE => Command::UdpAssociate,
                        _ => return Err(Error::new(ErrorKind::Other, "Unknown socks5 command"))
                    };
                    let dst_len =
                        match self.request[3] {
                            v5::ATYP_IPV4   => 4,
                            v5::ATYP_IPV6   => 16,
                            v5::ATYP_DOMAIN => self.request[4]+1,
                            _ => return Err(Error::new(ErrorKind::Other, 
                                                "Unknown address typ in socks5 request"))
                        };
                    let delta = (dst_len as usize) + 6 - self.request.len();
                    if delta > 0 {
                        WaitClientRequest(
                            read_exact(stream,vec![0u8; delta])
                        )
                    }
                    else {
                        let n = self.request.len();
                        let port = ((self.request[n-2] as u16) << 8) | (self.request[n-1] as u16);
                        let addr = match self.request[3] {
                            v5::ATYP_IPV4   => {
                                let ipv4 = IpAddr::V4(Ipv4Addr::new(self.request[4],
                                                                    self.request[5],
                                                                    self.request[6],
                                                                    self.request[7]));
                                Addr::IP(ipv4)
                            },
                            v5::ATYP_IPV6   => {
                                let ipv6 = self.request[4..20].to_vec();
                                let ipv6 = IpAddr::V6(Ipv6Addr::new(
                                                    ((self.request[4] as u16) <<8)+(self.request[5] as u16),
                                                    ((self.request[6] as u16) <<8)+(self.request[7] as u16),
                                                    ((self.request[8] as u16) <<8)+(self.request[9] as u16),
                                                    ((self.request[10] as u16) <<8)+(self.request[11] as u16),
                                                    ((self.request[12] as u16) <<8)+(self.request[13] as u16),
                                                    ((self.request[14] as u16) <<8)+(self.request[15] as u16),
                                                    ((self.request[16] as u16) <<8)+(self.request[17] as u16),
                                                    ((self.request[18] as u16) <<8)+(self.request[19] as u16)
                                                    ));
                                Addr::IP(ipv6)
                            },
                            v5::ATYP_DOMAIN => {
                                let domlen = self.request[4] as usize;
                                let dom: Vec<u8> = self.request[5..(5+domlen)].to_vec();
                                Addr::DOMAIN(dom)
                            },
                            _ =>
                                panic!("Memory mutation happened")
                        };
                        return Ok(Async::Ready(((stream,addr,self.request.take(),
                                                 port,cmd))));
                    }
                }
            }
        }
    }
}

impl Future for SocksConnectHandshake {
    type Item = (TcpStream,Bytes);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, io::Error> {
        use self::ClientState::*;

        loop {
            self.state = match self.state {
                WaitSentAuthentication(ref mut fut) => {
                    let (stream,_buf) = try_ready!(fut.poll());
                    WaitAuthenticationMethod(
                        read_exact(stream,vec![0u8; 2])
                    )
                },
                WaitAuthenticationMethod(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    if (buf[0] != v5::VERSION) || (buf[1] != 0) {
                        return Err(Error::new(ErrorKind::Other, "No Socks5 proxy found"));
                    }
                    WaitSentRequest(
                        write_all(stream,self.request.to_vec())
                    )
                },
                WaitSentRequest(ref mut fut) => {
                    let (stream,_buf) = try_ready!(fut.poll());
                    WaitReply(
                        read_exact(stream,vec![0u8; v5::MIN_REQUEST_SIZE])
                    )
                },
                WaitReply(ref mut fut) => {
                    let (stream,buf) = try_ready!(fut.poll());
                    self.response.put_slice(&buf);
                    if self.response[0] != v5::VERSION {
                        return Err(Error::new(ErrorKind::Other, "Not Socks5 response"))
                    };
                    if self.response[2] != 0 {
                        return Err(Error::new(ErrorKind::Other, 
                                "Reserved field in socks5 response is not 0x00"))
                    };
                    if self.response[2] != self.response[2] {
                        return Err(Error::new(ErrorKind::Other, "Response command differs from request"))
                    };
                    let dst_len =
                        match self.response[3] {
                            v5::ATYP_IPV4   => 4,
                            v5::ATYP_IPV6   => 16,
                            v5::ATYP_DOMAIN => self.response[4]+1,
                            _ => return Err(Error::new(ErrorKind::Other, 
                                                "Unknown address typ in socks5 response"))
                        };
                    let delta = (dst_len as usize) + 6 - self.response.len();
                    if delta > 0 {
                        WaitReply(
                            read_exact(stream,vec![0u8; delta])
                        )
                    }
                    else {
                        return Ok(Async::Ready((stream,self.response.take().freeze())));
                    }
                }
            }
        }
    }
}