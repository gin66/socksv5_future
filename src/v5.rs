#[allow(dead_code)]
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