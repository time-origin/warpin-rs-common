pub mod adapter;
pub mod apidoc;
pub mod client;
pub mod endpoint;
mod headers;
mod middleware;
mod response;
mod router;
mod server;

pub use apidoc::{ApiDoc, ApiDocTheme};
pub use headers::{
    HEADER_INTERNAL_CALLER, HEADER_INTERNAL_TOKEN, HEADER_REQUEST_ID, HEADER_SCOPE_ID,
    HEADER_SESSION_ID, HEADER_TENANT_ID, HEADER_TRACE_ID, HEADER_USER_ID,
};
pub use middleware::{RequestContext, request_context_from_headers};
pub use response::{ApiError, ApiResult, DeletePayload, FileOutputPayload, ServiceResult};
pub use router::{
    ProbeHooks, ProbeResult, ServiceMetadata, ServiceState, build_http_app,
    build_http_app_with_root,
};
pub use server::serve;

// ── Model endpoint abstraction ──────────────────────────────────────
pub use adapter::{ApiAdapter, OpenAICompatibleAdapter};
pub use client::EndpointClient;
pub use endpoint::{ResolvedEndpoint, build_auth_headers};
