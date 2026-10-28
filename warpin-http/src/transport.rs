#![doc = include_str!("../TRANSPORT.md")]
//! General-purpose HTTP transport, separate from model endpoint adapters.
//! No fallback, redirects, implicit proxy, automatic retries or vendor envelope.
use bytes::Bytes;
use reqwest::{Client, Method, StatusCode, header::HeaderMap};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout_at},
};
use url::Url;
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
/// Explicit connection and resource limits.
#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    /// Connection establishment deadline; must not exceed the total deadline.
    pub connect_timeout: Duration,
    /// Maximum time waiting for response data within the total deadline.
    pub read_timeout: Duration,
    /// Deadline covering request start through response consumption.
    pub total_timeout: Duration,
    /// Maximum caller-supplied request body size.
    pub max_request_bytes: usize,
    /// Cumulative response-body byte budget across all chunks.
    pub max_response_bytes: usize,
    /// Maximum outstanding protocol work; zero is rejected.
    pub max_in_flight: usize,
}
impl HttpLimits {
    fn validate(self) -> Result<Self> {
        if [self.connect_timeout, self.read_timeout, self.total_timeout]
            .iter()
            .any(|d| d.is_zero() || *d > Duration::from_secs(86400))
            || self.connect_timeout > self.total_timeout
            || self.read_timeout > self.total_timeout
            || self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_request_bytes > 64 * 1024 * 1024
            || self.max_response_bytes > 64 * 1024 * 1024
            || self.max_in_flight == 0
            || self.max_in_flight > 65536
        {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        Ok(self)
    }
}
fn error(k: Kind, p: Phase) -> ProtocolError {
    ProtocolError::new(k, p)
}
/// Credentials are redacted, and retained only on the configured origin.
pub enum Authentication {
    None,
    Bearer(String),
    Header {
        name: reqwest::header::HeaderName,
        value: reqwest::header::HeaderValue,
    },
}
/// Explicit trust policy. Private plaintext networks must opt in.
pub enum Security {
    Https,
    CustomTls(warpin_transport::tls::ClientTls),
    PlaintextAllowed,
}
#[derive(Clone)]
pub struct HttpTransport {
    client: Client,
    base: Url,
    headers: HeaderMap,
    limits: HttpLimits,
    permits: Arc<Semaphore>,
}
impl HttpTransport {
    /// Base URLs come from trusted application configuration, never an arbitrary end user.
    pub fn new(
        base: &str,
        security: Security,
        authentication: Authentication,
        limits: HttpLimits,
    ) -> Result<Self> {
        let limits = limits.validate()?;
        let base = Url::parse(base).map_err(|_| error(Kind::Configuration, Phase::Configure))?;
        if !matches!(base.scheme(), "http" | "https")
            || (!matches!(security, Security::PlaintextAllowed) && base.scheme() != "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.path().ends_with('/')
        {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        let mut headers = HeaderMap::new();
        match authentication {
            Authentication::None => {}
            Authentication::Bearer(token) => {
                if token.trim().is_empty() {
                    return Err(error(Kind::Configuration, Phase::Configure));
                }
                let mut h = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| error(Kind::Configuration, Phase::Configure))?;
                h.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, h);
            }
            Authentication::Header { name, mut value } => {
                if matches!(
                    name.as_str(),
                    "host" | "content-length" | "transfer-encoding" | "connection"
                ) {
                    return Err(error(Kind::Configuration, Phase::Configure));
                }
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        let builder = Client::builder()
            .connect_timeout(limits.connect_timeout)
            .read_timeout(limits.read_timeout)
            .timeout(limits.total_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();
        let builder = match security {
            Security::CustomTls(tls) => builder.use_preconfigured_tls((*tls.config()).clone()),
            _ => builder,
        };
        let client = builder
            .build()
            .map_err(|_| error(Kind::Configuration, Phase::Configure))?;
        Ok(Self {
            client,
            base,
            headers,
            limits,
            permits: Arc::new(Semaphore::new(limits.max_in_flight)),
        })
    }
    fn url(&self, path: &str) -> Result<Url> {
        // Reject encoded ambiguity rather than normalizing a route across trust boundaries.
        if path.starts_with('/')
            || path.contains(['\\', '#', '%'])
            || path
                .split('?')
                .next()
                .is_some_and(|p| p.split('/').any(|s| s == "." || s == ".."))
        {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        let url = self
            .base
            .join(path)
            .map_err(|_| error(Kind::Configuration, Phase::Configure))?;
        if url.origin() != self.base.origin() || !url.path().starts_with(self.base.path()) {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        Ok(url)
    }
    /// Acquires a bounded slot immediately. Non-success statuses are retained for caller interpretation.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Response> {
        let url = self.url(path)?;
        if body.len() > self.limits.max_request_bytes {
            return Err(error(Kind::Capacity, Phase::Write));
        }
        if headers.keys().any(|n| {
            matches!(
                n.as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) || self.headers.contains_key(n)
        }) {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| error(Kind::Capacity, Phase::Connect))?;
        let deadline = Instant::now() + self.limits.total_timeout;
        let read_only = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
        let response = timeout_at(
            deadline,
            self.client
                .request(method, url)
                .headers(self.headers.clone())
                .headers(headers)
                .body(body)
                .send(),
        )
        .await
        .map_err(|_| {
            error(
                if read_only {
                    Kind::Timeout
                } else {
                    Kind::OutcomeUnknown
                },
                Phase::Write,
            )
        })?
        .map_err(|e| {
            error(
                if e.is_connect() {
                    Kind::Connection
                } else if !read_only {
                    Kind::OutcomeUnknown
                } else if e.is_timeout() {
                    Kind::Timeout
                } else {
                    Kind::Protocol
                },
                Phase::Write,
            )
        })?;
        if response
            .content_length()
            .is_some_and(|n| n > self.limits.max_response_bytes as u64)
        {
            return Err(error(Kind::Capacity, Phase::Read));
        }
        Ok(Response {
            response,
            deadline,
            remaining: self.limits.max_response_bytes,
            _permit: permit,
            failed: false,
        })
    }
}
/// Bounded streaming response. Drop releases the slot and cancels further reading.
pub struct Response {
    response: reqwest::Response,
    deadline: Instant,
    remaining: usize,
    _permit: OwnedSemaphorePermit,
    failed: bool,
}
impl Response {
    /// Returns the actual HTTP status without imposing a vendor success convention.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }
    /// Borrows response headers; values may contain sensitive remote metadata.
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }
    /// Reads the next chunk under the shared deadline and remaining byte budget.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        if self.failed {
            return Err(error(Kind::Closed, Phase::Read));
        }
        self.failed = true;
        let chunk = timeout_at(self.deadline, self.response.chunk())
            .await
            .map_err(|_| error(Kind::Timeout, Phase::Read))?
            .map_err(|e| {
                error(
                    if e.is_timeout() {
                        Kind::Timeout
                    } else {
                        Kind::Protocol
                    },
                    Phase::Read,
                )
            })?;
        if let Some(b) = &chunk {
            self.remaining = self
                .remaining
                .checked_sub(b.len())
                .ok_or(error(Kind::Capacity, Phase::Read))?;
        }
        self.failed = false;
        Ok(chunk)
    }
    /// Collects the response while checking every chunk against the byte budget.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(c) = self.chunk().await? {
            out.extend_from_slice(&c);
        }
        Ok(out)
    }
    /// Decodes a bounded response without interpreting a vendor envelope.
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        serde_json::from_slice(&self.bytes().await?)
            .map_err(|_| error(Kind::Protocol, Phase::Decode))
    }
}
