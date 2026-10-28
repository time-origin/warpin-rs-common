#![doc = include_str!("../README.md")]
//! Bounded, serial Modbus clients. No automatic operation replay.
pub mod registers;
mod validation;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
pub use tokio_modbus::{ExceptionCode, Request, Response};
use tokio_modbus::{
    client::{Client as _, Context},
    prelude::Slave,
};
pub use tokio_serial::{DataBits, FlowControl, Parity, StopBits};
use warpin_errors::{
    ServiceError,
    protocol::{Kind, Phase, ProtocolError},
};
/// Safe transport failure or exact standard remote exception.
#[derive(Debug)]
pub enum Error {
    Transport(ProtocolError),
    Exception(ExceptionCode),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => e.fmt(f),
            Self::Exception(e) => write!(f, "Modbus exception: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Transport(e)
    }
}
impl From<Error> for ServiceError {
    fn from(e: Error) -> Self {
        match e {
            Error::Transport(e) => e.into(),
            Error::Exception(_) => ProtocolError::new(Kind::Rejected, Phase::Read).into(),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn failure(k: Kind, p: Phase) -> Error {
    ProtocolError::new(k, p).into()
}
fn validate(unit: u8, deadline: Duration, rtu: bool) -> Result<()> {
    if unit == 0
        || (rtu && unit > 247)
        || deadline.is_zero()
        || deadline > Duration::from_secs(86400)
    {
        return Err(failure(Kind::Configuration, Phase::Configure));
    }
    Ok(())
}
/// A single in-flight request per connection. Cancellation destroys the context.
pub struct Client {
    context: Option<Context>,
    deadline: Duration,
}
impl Client {
    /// Explicit plaintext TCP connection. No DNS, retry, or broadcast writes.
    pub async fn connect_tcp_plaintext(
        address: SocketAddr,
        unit: u8,
        deadline: Duration,
    ) -> Result<Self> {
        validate(unit, deadline, false)?;
        let context = timeout(
            deadline,
            tokio_modbus::client::tcp::connect_slave(address, Slave(unit)),
        )
        .await
        .map_err(|_| failure(Kind::Timeout, Phase::Connect))?
        .map_err(|_| failure(Kind::Connection, Phase::Connect))?;
        Ok(Self {
            context: Some(context),
            deadline,
        })
    }
    /// Attach an already secured or explicitly plaintext TCP stream.
    pub fn attach_tcp<S: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug + 'static>(
        stream: S,
        unit: u8,
        deadline: Duration,
    ) -> Result<Self> {
        validate(unit, deadline, false)?;
        Ok(Self {
            context: Some(tokio_modbus::client::tcp::attach_slave(stream, Slave(unit))),
            deadline,
        })
    }
    /// Caller owns exclusive access to the physical bus and its resynchronization.
    pub fn attach_rtu<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        unit: u8,
        deadline: Duration,
    ) -> Result<Self> {
        validate(unit, deadline, true)?;
        Ok(Self {
            context: Some(tokio_modbus::client::rtu::attach_slave(stream, Slave(unit))),
            deadline,
        })
    }
    /// Synchronous OS open: call during startup or from a supervised blocking task.
    pub fn open_rtu(settings: SerialSettings, unit: u8, deadline: Duration) -> Result<Self> {
        use tokio_serial::SerialPortBuilderExt;
        validate(unit, deadline, true)?;
        if settings.path.is_empty()
            || settings.path.len() > 4096
            || settings.path.contains('\0')
            || settings.baud_rate == 0
        {
            return Err(failure(Kind::Configuration, Phase::Configure));
        }
        let stream = tokio_serial::new(settings.path, settings.baud_rate)
            .data_bits(settings.data_bits)
            .parity(settings.parity)
            .stop_bits(settings.stop_bits)
            .flow_control(settings.flow_control)
            .timeout(deadline)
            .open_native_async()
            .map_err(|_| failure(Kind::Connection, Phase::Connect))?;
        Self::attach_rtu(stream, unit, deadline)
    }
    /// Standard functions 1–6, 15, 16, 22 and 23 only. Addresses are zero based.
    /// A write failure after dispatch is OutcomeUnknown; it must not be retried automatically.
    pub async fn call(&mut self, request: Request<'_>) -> Result<Response> {
        let read_only = validation::request(&request)?;
        let mut context = self
            .context
            .take()
            .ok_or_else(|| failure(Kind::Closed, Phase::Write))?;
        let result = timeout(self.deadline, context.call(request.clone())).await;
        match result {
            Ok(Ok(Ok(mut response))) => {
                if !validation::response(&request, &mut response) {
                    return Err(failure(
                        if read_only {
                            Kind::Protocol
                        } else {
                            Kind::OutcomeUnknown
                        },
                        Phase::Read,
                    ));
                }
                self.context = Some(context);
                Ok(response)
            }
            Ok(Ok(Err(exception))) => {
                self.context = Some(context);
                Err(Error::Exception(exception))
            }
            Ok(Err(e)) => Err(failure(
                if !read_only {
                    Kind::OutcomeUnknown
                } else {
                    match e {
                        tokio_modbus::Error::Protocol(_) => Kind::Protocol,
                        tokio_modbus::Error::Transport(_) => Kind::Connection,
                    }
                },
                Phase::Read,
            )),
            Err(_) => Err(failure(
                if read_only {
                    Kind::Timeout
                } else {
                    Kind::OutcomeUnknown
                },
                Phase::Read,
            )),
        }
    }
    /// Closed also means a request was cancelled or transport synchronization was lost.
    pub fn is_closed(&self) -> bool {
        self.context.is_none()
    }
    /// Closes this transport within its configured deadline.
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut context) = self.context.take() {
            timeout(self.deadline, context.disconnect())
                .await
                .map_err(|_| failure(Kind::Timeout, Phase::Close))?
                .map_err(|_| failure(Kind::Connection, Phase::Close))?;
        }
        Ok(())
    }
}
/// Serial configuration; no inferred port, unit, baud rate or parity.
pub struct SerialSettings {
    /// Explicit serial device path; opening does not infer a port.
    pub path: String,
    /// Explicit nonzero baud rate, further validated by the OS driver.
    pub baud_rate: u32,
    /// Serial data-bit count chosen by the device protocol.
    pub data_bits: DataBits,
    /// Serial parity chosen by the device protocol.
    pub parity: Parity,
    /// Serial stop-bit count chosen by the device protocol.
    pub stop_bits: StopBits,
    /// Explicit serial flow-control mode.
    pub flow_control: FlowControl,
}
