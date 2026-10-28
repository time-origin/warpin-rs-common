//! Bounded TCP streams. Dropping an in-flight operation poisons that direction.
use crate::{Limits, codec::FrameDecoder};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
/// A caller-owned connection; no implicit reconnect or replay.
pub struct Connection<S> {
    stream: S,
    limits: Limits,
    buffer: Vec<u8>,
    read_busy: bool,
    write_busy: bool,
    closed: bool,
    _permit: Option<OwnedSemaphorePermit>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Upgrade before reading/writing; the listener's capacity permit remains held.
    pub async fn accept_tls(
        self,
        tls: &crate::tls::ServerTls,
    ) -> Result<Connection<tokio_rustls::server::TlsStream<S>>> {
        if self.closed || self.read_busy || self.write_busy || !self.buffer.is_empty() {
            return Err(ProtocolError::new(Kind::Closed, Phase::Connect));
        }
        let mut secured = tls.accept(self.stream, self.limits).await?;
        secured._permit = self._permit;
        Ok(secured)
    }
    /// Upgrade before any plaintext I/O, preserving the capacity permit.
    pub async fn connect_tls(
        self,
        tls: &crate::tls::ClientTls,
        name: &str,
    ) -> Result<Connection<tokio_rustls::client::TlsStream<S>>> {
        if self.closed || self.read_busy || self.write_busy || !self.buffer.is_empty() {
            return Err(ProtocolError::new(Kind::Closed, Phase::Connect));
        }
        let mut secured = tls.connect(self.stream, name, self.limits).await?;
        secured._permit = self._permit;
        Ok(secured)
    }
    /// Reads a bounded byte chunk; chunks are NOT messages. Do not mix with framed reads.
    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        if self.closed || self.read_busy || self.write_busy {
            return Err(ProtocolError::new(Kind::Closed, Phase::Read));
        }
        if !self.buffer.is_empty() {
            return Ok(std::mem::take(&mut self.buffer));
        }
        self.read_busy = true;
        let mut buf = vec![0; self.limits.max_frame_bytes.min(4096)];
        match timeout(self.limits.timeout, self.stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.truncate(n);
                self.read_busy = false;
                Ok(buf)
            }
            Ok(Ok(_)) => {
                self.closed = true;
                Err(ProtocolError::new(Kind::Closed, Phase::Read))
            }
            Ok(Err(_)) => {
                self.closed = true;
                Err(ProtocolError::new(Kind::Connection, Phase::Read))
            }
            Err(_) => {
                self.closed = true;
                Err(ProtocolError::new(Kind::Timeout, Phase::Read))
            }
        }
    }
    /// Validates all required configuration before constructing local state.
    pub fn new(stream: S, limits: Limits) -> Result<Self> {
        Ok(Self {
            stream,
            limits: limits.validate()?,
            buffer: Vec::new(),
            read_busy: false,
            write_busy: false,
            closed: false,
            _permit: None,
        })
    }
    /// Entire operation shares one deadline. Cancelled reads require reconnect.
    pub async fn read_frame(&mut self, decoder: &mut impl FrameDecoder) -> Result<Vec<u8>> {
        if self.closed || self.read_busy || self.write_busy {
            return Err(ProtocolError::new(Kind::Closed, Phase::Read));
        }
        self.read_busy = true;
        let maximum = self.limits.max_frame_bytes;
        let result = timeout(self.limits.timeout, async {
            loop {
                if let Some(n) = decoder.frame_len(&self.buffer, maximum)? {
                    if n == 0 || n > self.buffer.len() || n > maximum {
                        return Err(ProtocolError::new(Kind::Protocol, Phase::Decode));
                    }
                    return Ok(self.buffer.drain(..n).collect());
                }
                if self.buffer.len() >= maximum {
                    return Err(ProtocolError::new(Kind::Capacity, Phase::Read));
                }
                let mut chunk = [0u8; 4096];
                let len = chunk.len().min(maximum - self.buffer.len());
                let n = self
                    .stream
                    .read(&mut chunk[..len])
                    .await
                    .map_err(|source| {
                        ProtocolError::new(Kind::Connection, Phase::Read).with_source(source)
                    })?;
                if n == 0 {
                    return Err(ProtocolError::new(
                        if self.buffer.is_empty() {
                            Kind::Closed
                        } else {
                            Kind::Protocol
                        },
                        Phase::Read,
                    ));
                }
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .map_err(|source| ProtocolError::new(Kind::Timeout, Phase::Read).with_source(source))
        .and_then(|r| r);
        if result.is_ok() {
            self.read_busy = false;
        } else {
            self.closed = true;
        }
        result
    }
    /// Writes a complete wire frame. Failure/cancellation may have sent a prefix.
    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed || self.write_busy || self.read_busy {
            return Err(ProtocolError::new(Kind::Closed, Phase::Write));
        }
        if frame.len() > self.limits.max_frame_bytes {
            return Err(ProtocolError::new(Kind::Capacity, Phase::Write));
        }
        self.write_busy = true;
        match timeout(self.limits.timeout, self.stream.write_all(frame)).await {
            Ok(Ok(())) => {
                self.write_busy = false;
                Ok(())
            }
            _ => {
                self.closed = true;
                Err(ProtocolError::new(Kind::OutcomeUnknown, Phase::Write))
            }
        }
    }
    /// Closes this transport within its configured deadline.
    pub async fn close(&mut self) -> Result<()> {
        self.closed = true;
        timeout(self.limits.timeout, self.stream.shutdown())
            .await
            .map_err(|source| ProtocolError::new(Kind::Timeout, Phase::Close).with_source(source))?
            .map_err(|source| {
                ProtocolError::new(Kind::Connection, Phase::Close).with_source(source)
            })
    }
}
impl Connection<TcpStream> {
    /// SocketAddr avoids implicit DNS or unbounded resolution; caller controls destinations.
    pub async fn connect(address: SocketAddr, limits: Limits) -> Result<Self> {
        let limits = limits.validate()?;
        let stream = timeout(limits.timeout, TcpStream::connect(address))
            .await
            .map_err(|source| {
                ProtocolError::new(Kind::Timeout, Phase::Connect).with_source(source)
            })?
            .map_err(|source| {
                ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
            })?;
        Self::new(stream, limits)
    }
}
/// Connection limit includes accepted live connections. Caller owns accept loop.
pub struct Listener {
    listener: TcpListener,
    permits: Arc<Semaphore>,
    limits: Limits,
}
impl Listener {
    /// Binds the configured local address after validating resource limits.
    pub async fn bind(address: SocketAddr, max_connections: usize, limits: Limits) -> Result<Self> {
        let limits = limits.validate()?;
        if max_connections == 0 || max_connections > 65536 {
            return Err(ProtocolError::new(Kind::Configuration, Phase::Configure));
        }
        let listener = TcpListener::bind(address).await.map_err(|source| {
            ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
        })?;
        Ok(Self {
            listener,
            permits: Arc::new(Semaphore::new(max_connections)),
            limits,
        })
    }
    /// Returns the actual bound address, including an operating-system-assigned port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(|source| {
            ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
        })
    }
    /// Accepts one peer while holding a permit for its entire connection lifetime.
    pub async fn accept(&self) -> Result<(Connection<TcpStream>, SocketAddr)> {
        let permit = self.permits.clone().try_acquire_owned().map_err(|source| {
            ProtocolError::new(Kind::Capacity, Phase::Connect).with_source(source)
        })?;
        let (stream, peer) = timeout(self.limits.timeout, self.listener.accept())
            .await
            .map_err(|source| {
                ProtocolError::new(Kind::Timeout, Phase::Connect).with_source(source)
            })?
            .map_err(|source| {
                ProtocolError::new(Kind::Connection, Phase::Connect).with_source(source)
            })?;
        let mut connection = Connection::new(stream, self.limits)?;
        connection._permit = Some(permit);
        Ok((connection, peer))
    }
}
