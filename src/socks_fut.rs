// Futures for socks5
// ==================
//
// As per RFC 1928, this is not a compliant implementation, because
// GSSAPI authentication method is not supported.
//
// TODO: Return failures for socks5 requests
// TODO: create a struct for socksv5_request message with
//       get functions for port, cmd,....
//

use std::io;
use std::io::{Error, ErrorKind};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio_io::io::{read_exact, write_all, ReadExact, WriteAll};
use tokio_core::net::{TcpStream};
use futures::*;
use futures::Async;

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

pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Unknown(u8)
}

pub struct SocksRequestResponse {
    pub bytes: Vec<u8>
}

impl SocksRequestResponse {
    pub fn port(&self) -> u16 {
        let n = self.bytes.len();
        ((self.bytes[n-2] as u16) << 8) | (self.bytes[n-1] as u16)
    }

    pub fn ipaddr(&self) -> Option<IpAddr> {
        match self.bytes[3] {
            v5::ATYP_IPV4   => {
                Some(IpAddr::V4(Ipv4Addr::new(self.bytes[4],
                                                    self.bytes[5],
                                                    self.bytes[6],
                                                    self.bytes[7])))
            },
            v5::ATYP_IPV6   => {
                Some(IpAddr::V6(Ipv6Addr::new(
                                    ((self.bytes[4] as u16) <<8)+(self.bytes[5] as u16),
                                    ((self.bytes[6] as u16) <<8)+(self.bytes[7] as u16),
                                    ((self.bytes[8] as u16) <<8)+(self.bytes[9] as u16),
                                    ((self.bytes[10] as u16) <<8)+(self.bytes[11] as u16),
                                    ((self.bytes[12] as u16) <<8)+(self.bytes[13] as u16),
                                    ((self.bytes[14] as u16) <<8)+(self.bytes[15] as u16),
                                    ((self.bytes[16] as u16) <<8)+(self.bytes[17] as u16),
                                    ((self.bytes[18] as u16) <<8)+(self.bytes[19] as u16)
                                    )))
            },
            _ => None
        }
    }

    pub fn socketaddr(&self) -> Option<SocketAddr> {
        match self.ipaddr() {
            Some(ip) => Some(SocketAddr::new(ip, self.port())),
            None => None
        }
    }

    pub fn hostname(&self) -> Option<&[u8]> {
        match self.bytes[3] {
            v5::ATYP_DOMAIN   => {
                let domlen = self.bytes[4] as usize;
                Some(&self.bytes[5..(5+domlen)])
            },
            _ => None
        }
    }

    pub fn command(&self) -> Command {
        match self.bytes[1] {
            v5::CMD_CONNECT       => Command::Connect,
            v5::CMD_BIND          => Command::Bind,
            v5::CMD_UDP_ASSOCIATE => Command::UdpAssociate,
            cmd                   => Command::Unknown(cmd)
        }
    }

    pub fn clone(&self) -> SocksRequestResponse {
        SocksRequestResponse {
            bytes: self.bytes.clone()
        }
    }
}

pub struct SocksHandshake {
    request: SocksRequestResponse,
    state: ServerState
}

pub struct SocksConnectHandshake {
    request: SocksRequestResponse,
    state: ClientState,
    response: SocksRequestResponse
}

pub fn socks_handshake(stream: TcpStream) -> SocksHandshake {
    SocksHandshake { 
        request: SocksRequestResponse {
            bytes: Vec::with_capacity(v5::MAX_REQUEST_SIZE)
        },
        state: ServerState::WaitClientAuthentication(
            read_exact(stream,vec!(0u8;2))
        )
    }
}

pub fn socks_connect_handshake(stream: TcpStream,request: SocksRequestResponse)
                                                         -> SocksConnectHandshake {
    SocksConnectHandshake { 
        request,
        state: ClientState::WaitSentAuthentication(
            write_all(stream,vec![v5::VERSION,1u8,v5::METH_NO_AUTH])
        ),
        response: SocksRequestResponse {
            bytes: Vec::with_capacity(v5::MAX_REQUEST_SIZE)
        }
    }
}

impl Future for SocksHandshake {
    type Item = (TcpStream,SocksRequestResponse);
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
                    self.request.bytes.extend_from_slice(&buf);
                    if self.request.bytes[0] != v5::VERSION {
                        return Err(Error::new(ErrorKind::Other, "Not Socks5 request"))
                    };
                    if self.request.bytes[2] != 0 {
                        return Err(Error::new(ErrorKind::Other, 
                                "Reserved field in socks5 request is not 0x00"))
                    };
                    let dst_len =
                        match self.request.bytes[3] {
                            v5::ATYP_IPV4   => 4,
                            v5::ATYP_IPV6   => 16,
                            v5::ATYP_DOMAIN => self.request.bytes[4]+1,
                            _ => return Err(Error::new(ErrorKind::Other, 
                                            "Unknown address type in socks5 request"))
                        };
                    let delta = (dst_len as usize) + 6 - self.request.bytes.len();
                    if delta == 0 {
                        let sr = mem::replace(&mut self.request,SocksRequestResponse{ bytes:vec!()});
                        return Ok(Async::Ready(((stream,sr))));
                    }
                    WaitClientRequest(
                        read_exact(stream,vec![0u8; delta])
                    )
                }
            }
        }
    }
}

impl Future for SocksConnectHandshake {
    type Item = (TcpStream,SocksRequestResponse);
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
                       write_all(stream,self.request.bytes.clone())
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
                    self.response.bytes.extend_from_slice(&buf);
                    if self.response.bytes[0] != v5::VERSION {
                        return Err(Error::new(ErrorKind::Other, "Not Socks5 response"))
                    };
                    if self.response.bytes[2] != 0 {
                        return Err(Error::new(ErrorKind::Other, 
                                "Reserved field in socks5 response is not 0x00"))
                    };
                    if self.response.bytes[2] != self.response.bytes[2] {
                        return Err(Error::new(ErrorKind::Other, "Response command differs from request"))
                    };
                    let dst_len =
                        match self.response.bytes[3] {
                            v5::ATYP_IPV4   => 4,
                            v5::ATYP_IPV6   => 16,
                            v5::ATYP_DOMAIN => self.response.bytes[4]+1,
                            _ => return Err(Error::new(ErrorKind::Other, 
                                                "Unknown address typ in socks5 response"))
                        };
                    let delta = (dst_len as usize) + 6 - self.response.bytes.len();
                    if delta == 0 {
                        let sr = mem::replace(&mut self.response,SocksRequestResponse{ bytes:vec!()});
                        return Ok(Async::Ready((stream,sr)));
                    }
                    WaitReply(
                        read_exact(stream,vec![0u8; delta])
                    )
                }
            }
        }
    }
}
