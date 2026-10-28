//! Safe, typed connectivity errors. Never include peer payloads or credentials.
use crate::ServiceError;

/// Operation phase, including whether delivery may already have happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Configure,
    Connect,
    Read,
    Write,
    Decode,
    Close,
}
/// Stable error classification independent of a particular wire protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Configuration,
    Connection,
    Authentication,
    Timeout,
    Protocol,
    Rejected,
    Capacity,
    Closed,
    OutcomeUnknown,
}
/// A redacted protocol error. Internal source is retained only when supplied; Debug/Display never print it.
#[derive(Clone)]
pub struct ProtocolError {
    /// Stable failure category; never infer success from a transport error.
    pub kind: Kind,
    /// Operation stage at which the failure was detected.
    pub phase: Phase,
    source: Option<std::sync::Arc<dyn std::error::Error + Send + Sync>>,
}
impl ProtocolError {
    pub const fn new(kind: Kind, phase: Phase) -> Self {
        Self {
            kind,
            phase,
            source: None,
        }
    }
    pub const fn message(&self) -> &'static str {
        match self.kind {
            Kind::Configuration => "Protocol configuration is invalid",
            Kind::Connection => "Protocol connection failed",
            Kind::Authentication => "Protocol authentication failed",
            Kind::Timeout => "Protocol operation deadline exceeded",
            Kind::Protocol => "Protocol response is invalid",
            Kind::Rejected => "Protocol operation was rejected",
            Kind::Capacity => "Protocol resource limit exceeded",
            Kind::Closed => "Protocol connection is closed",
            Kind::OutcomeUnknown => {
                "Protocol operation outcome is unknown; do not automatically retry"
            }
        }
    }
    /// HTTP-compatible service boundary mapping; kind remains available internally.
    pub fn service_error(&self) -> ServiceError {
        let code = match self.kind {
            Kind::Configuration => 400,
            Kind::Authentication => 401,
            Kind::Rejected => 422,
            Kind::Capacity => 429,
            Kind::Timeout => 504,
            Kind::Protocol => 502,
            Kind::Connection | Kind::Closed | Kind::OutcomeUnknown => 503,
        };
        ServiceError::with_message(code, self.message())
    }
}
impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.message(), self.phase)
    }
}
impl std::fmt::Debug for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolError")
            .field("kind", &self.kind)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl ProtocolError {
    /// Retain internal diagnostic cause. Never serialize or log the raw source at a public boundary.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(std::sync::Arc::new(source));
        self
    }
}
impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}
impl From<ProtocolError> for ServiceError {
    fn from(e: ProtocolError) -> Self {
        e.service_error()
    }
}
/// Connectivity result with a stable, credential-safe error.
pub type Result<T> = std::result::Result<T, ProtocolError>;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internal_source_is_retained_but_never_rendered() {
        let e = ProtocolError::new(Kind::Connection, Phase::Connect)
            .with_source(std::io::Error::other("SECRET-TOKEN-EXAMPLE"));
        assert!(std::error::Error::source(&e).is_some());
        assert!(!format!("{e:?} {e}").contains("SECRET-TOKEN-EXAMPLE"));
        assert!(!e.service_error().message.contains("SECRET-TOKEN-EXAMPLE"));
    }
    #[test]
    fn mappings_are_explicit() {
        for (kind, code) in [
            (Kind::Configuration, 400),
            (Kind::Authentication, 401),
            (Kind::Rejected, 422),
            (Kind::Capacity, 429),
            (Kind::Timeout, 504),
            (Kind::Protocol, 502),
            (Kind::Connection, 503),
            (Kind::Closed, 503),
            (Kind::OutcomeUnknown, 503),
        ] {
            let e = ProtocolError::new(kind, Phase::Write);
            let s = e.service_error();
            assert_eq!(s.code, code);
            assert_eq!(s.message, e.message());
        }
    }
}
