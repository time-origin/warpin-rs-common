#![doc = include_str!("../README.md")]
//! Caller-owned TCP/UDP communication; no detached tasks or automatic replay.
pub mod codec;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::time::Duration;
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
/// Explicit bounds; all values are required and validated before I/O.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Total deadline for each complete operation, including all partial reads/writes.
    pub timeout: Duration,
    /// Maximum complete wire frame; protocol-specific constructors may impose a lower cap.
    pub max_frame_bytes: usize,
}
impl Limits {
    /// Rejects zero, excessive or inconsistent resource limits.
    pub fn validate(self) -> Result<Self> {
        if self.timeout.is_zero()
            || self.timeout > Duration::from_secs(86400)
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > 16 * 1024 * 1024
        {
            return Err(ProtocolError::new(Kind::Configuration, Phase::Configure));
        }
        Ok(self)
    }
}
