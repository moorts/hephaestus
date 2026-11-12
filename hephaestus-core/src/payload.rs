use color_eyre::eyre::{eyre, Result};

/// Maximum allowed length for ConnectionIds in QUIC V1.
pub const SIRF_MAX_CID_LEN: usize = 20;

/*
pub struct Payload {
    pub scid: Vec<u8>,
    pub dcid: Vec<u8>,
    pub version: u32,
}
*/

#[derive(Clone)]
/// Controllable fields of QUIC packet.
pub enum Payload {
    /// Server Initial Request Forgery
    Sirf {
        scid: Vec<u8>
    },
    /// Version Negotiation Request Forgery
    Vnrf {
        scid: Vec<u8>,
        dcid: Vec<u8>,
        version: u32,
    },
    /// Connection Migration Request Forgery
    Cmrf {
        scid: Vec<u8>,
        threshold: u32,
    },
}
