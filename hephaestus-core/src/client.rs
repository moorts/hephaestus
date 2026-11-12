use std::future::Future;
use std::{error::Error, net::SocketAddr};

use crate::payload::Payload;

use color_eyre::eyre::Result;

/// A QUIC client that allows manually setting packet contents.
pub trait Client
where
    Self: Sized + Send,
{
    /// Create a new client.
    fn new(addr: SocketAddr) -> std::io::Result<Self>;

    /// Make a connection and use values from payload.
    fn connect(
        &mut self,
        remote: SocketAddr,
        server_name: &str,
        payload: Payload,
    ) -> impl Future<Output = Result<()>> + Send;
}
