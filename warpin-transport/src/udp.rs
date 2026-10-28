//! Whole UDP datagrams; send completion never means peer receipt.
use crate::Limits;
use std::{net::SocketAddr, time::SystemTime};
use tokio::{net::UdpSocket, time::timeout};
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
/// Explicit receive policy; address filtering is not authentication.
pub enum Sources {
    Any,
    Only(Vec<SocketAddr>),
}
pub struct Datagram {
    /// Unmodified protocol bytes; no unit or business decoding is applied.
    pub payload: Vec<u8>,
    /// Network address reported by the receiving socket.
    pub peer: SocketAddr,
    /// Local wall-clock receive time, not a device sampling timestamp.
    pub received_at: SystemTime,
}
pub struct Socket {
    socket: UdpSocket,
    limits: Limits,
    sources: Sources,
}
impl Socket {
    /// Binds the configured local address after validating resource limits.
    pub async fn bind(address: SocketAddr, limits: Limits, sources: Sources) -> Result<Self> {
        let limits = limits.validate()?;
        if limits.max_frame_bytes > 65507
            || matches!(&sources,Sources::Only(v) if v.is_empty()||v.len()>65536)
        {
            return Err(ProtocolError::new(Kind::Configuration, Phase::Configure));
        }
        let socket = UdpSocket::bind(address).await.map_err(|source| {
            ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
        })?;
        Ok(Self {
            socket,
            limits,
            sources,
        })
    }
    /// Returns the actual bound address, including an operating-system-assigned port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(|source| {
            ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
        })
    }
    /// Receives one complete datagram or an explicit limit/source/deadline error.
    pub async fn recv(&self) -> Result<Datagram> {
        // Full ordinary UDP payload buffer detects oversize even when application cap is small.
        let mut b = vec![0u8; 65536];
        let (n, peer) = timeout(self.limits.timeout, self.socket.recv_from(&mut b))
            .await
            .map_err(|source| ProtocolError::new(Kind::Timeout, Phase::Read).with_source(source))?
            .map_err(|source| {
                ProtocolError::new(Kind::Connection, Phase::Read).with_source(source)
            })?;
        if n > self.limits.max_frame_bytes {
            return Err(ProtocolError::new(Kind::Capacity, Phase::Read));
        }
        if matches!(&self.sources,Sources::Only(v) if !v.contains(&peer)) {
            return Err(ProtocolError::new(Kind::Rejected, Phase::Read));
        }
        b.truncate(n);
        Ok(Datagram {
            payload: b,
            peer,
            received_at: SystemTime::now(),
        })
    }
    /// Sends one datagram; success does not acknowledge remote receipt.
    pub async fn send(&self, peer: SocketAddr, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.limits.max_frame_bytes {
            return Err(ProtocolError::new(Kind::Capacity, Phase::Write));
        }
        match timeout(self.limits.timeout, self.socket.send_to(bytes, peer)).await {
            Ok(Ok(n)) if n == bytes.len() => Ok(()),
            _ => Err(ProtocolError::new(Kind::OutcomeUnknown, Phase::Write)),
        }
    }
}
