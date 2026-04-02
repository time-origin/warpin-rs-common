use crate::{middleware::inject_request_context, response::ServiceResult};
use axum::routing::MethodRouter;
use axum::{
    Json, Router, extract::State, http::StatusCode, middleware, response::IntoResponse,
    routing::get,
};
use serde::Serialize;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone, Debug, Serialize)]
pub struct ServiceMetadata {
    pub name: String,
    pub version: String,
    pub environment: String,
}

impl ServiceMetadata {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        environment: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            environment: environment.into(),
        }
    }
}

#[derive(Debug)]
pub struct ServiceState<S> {
    pub metadata: Arc<ServiceMetadata>,
    pub inner: Arc<S>,
    pub probe_hooks: ProbeHooks<S>,
}

impl<S> ServiceState<S> {
    pub fn new(metadata: ServiceMetadata, inner: S) -> Self {
        Self {
            metadata: Arc::new(metadata),
            inner: Arc::new(inner),
            probe_hooks: ProbeHooks::default(),
        }
    }

    pub fn inner(&self) -> &S {
        self.inner.as_ref()
    }

    pub fn with_probe_hooks(mut self, probe_hooks: ProbeHooks<S>) -> Self {
        self.probe_hooks = probe_hooks;
        self
    }
}

impl<S> Clone for ServiceState<S> {
    fn clone(&self) -> Self {
        Self {
            metadata: Arc::clone(&self.metadata),
            inner: Arc::clone(&self.inner),
            probe_hooks: self.probe_hooks.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ProbeResponse {
    probe: &'static str,
    status: &'static str,
    service: String,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct ServiceInfoResponse {
    service: String,
    version: String,
    environment: String,
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    status: ProbeStatus,
    detail: Option<String>,
}

impl ProbeResult {
    pub fn ok() -> Self {
        Self {
            status: ProbeStatus::Ok,
            detail: None,
        }
    }

    pub fn degraded(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Degraded,
            detail: Some(detail.into()),
        }
    }

    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Fail,
            detail: Some(detail.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeStatus {
    Ok,
    Degraded,
    Fail,
}

impl ProbeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Fail => "fail",
        }
    }

    fn is_available(self) -> bool {
        !matches!(self, Self::Fail)
    }
}

type ProbeFn<S> = Arc<dyn Fn(&S) -> ProbeResult + Send + Sync>;

pub struct ProbeHooks<S> {
    health: ProbeFn<S>,
    live: ProbeFn<S>,
    ready: ProbeFn<S>,
}

impl<S> ProbeHooks<S> {
    pub fn with_health<F>(mut self, health: F) -> Self
    where
        F: Fn(&S) -> ProbeResult + Send + Sync + 'static,
    {
        self.health = Arc::new(health);
        self
    }

    pub fn with_live<F>(mut self, live: F) -> Self
    where
        F: Fn(&S) -> ProbeResult + Send + Sync + 'static,
    {
        self.live = Arc::new(live);
        self
    }

    pub fn with_ready<F>(mut self, ready: F) -> Self
    where
        F: Fn(&S) -> ProbeResult + Send + Sync + 'static,
    {
        self.ready = Arc::new(ready);
        self
    }
}

impl<S> Default for ProbeHooks<S> {
    fn default() -> Self {
        Self {
            health: Arc::new(|_| ProbeResult::ok()),
            live: Arc::new(|_| ProbeResult::ok()),
            ready: Arc::new(|_| ProbeResult::ok()),
        }
    }
}

impl<S> Clone for ProbeHooks<S> {
    fn clone(&self) -> Self {
        Self {
            health: Arc::clone(&self.health),
            live: Arc::clone(&self.live),
            ready: Arc::clone(&self.ready),
        }
    }
}

impl<S> std::fmt::Debug for ProbeHooks<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeHooks").finish()
    }
}

pub fn build_http_app<S>(state: ServiceState<S>, service_routes: Router<ServiceState<S>>) -> Router
where
    S: Send + Sync + 'static,
{
    build_http_app_with_root(state, service_routes, get(root::<S>))
}

pub fn build_http_app_with_root<S>(
    state: ServiceState<S>,
    service_routes: Router<ServiceState<S>>,
    root_route: MethodRouter<ServiceState<S>>,
) -> Router
where
    S: Send + Sync + 'static,
{
    Router::new()
        .route("/", root_route)
        .route("/health", get(health::<S>))
        .route("/live", get(live::<S>))
        .route("/ready", get(ready::<S>))
        .route("/v1/system/info", get(service_info::<S>))
        .merge(service_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(middleware::from_fn(inject_request_context)),
        )
        .with_state(state)
}

async fn root<S>(State(state): State<ServiceState<S>>) -> ServiceResult<ServiceInfoResponse>
where
    S: Send + Sync + 'static,
{
    ServiceResult::success(ServiceInfoResponse {
        service: state.metadata.name.clone(),
        version: state.metadata.version.clone(),
        environment: state.metadata.environment.clone(),
    })
}

async fn health<S>(State(state): State<ServiceState<S>>) -> impl IntoResponse
where
    S: Send + Sync + 'static,
{
    run_probe(state, ProbeKind::Health)
}

async fn live<S>(State(state): State<ServiceState<S>>) -> impl IntoResponse
where
    S: Send + Sync + 'static,
{
    run_probe(state, ProbeKind::Live)
}

async fn ready<S>(State(state): State<ServiceState<S>>) -> impl IntoResponse
where
    S: Send + Sync + 'static,
{
    run_probe(state, ProbeKind::Ready)
}

async fn service_info<S>(State(state): State<ServiceState<S>>) -> ServiceResult<ServiceInfoResponse>
where
    S: Send + Sync + 'static,
{
    ServiceResult::success(ServiceInfoResponse {
        service: state.metadata.name.clone(),
        version: state.metadata.version.clone(),
        environment: state.metadata.environment.clone(),
    })
}

#[derive(Clone, Copy)]
enum ProbeKind {
    Health,
    Live,
    Ready,
}

impl ProbeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Live => "live",
            Self::Ready => "ready",
        }
    }
}

fn run_probe<S>(state: ServiceState<S>, probe: ProbeKind) -> impl IntoResponse
where
    S: Send + Sync + 'static,
{
    let result = match probe {
        ProbeKind::Health => (state.probe_hooks.health)(state.inner()),
        ProbeKind::Live => (state.probe_hooks.live)(state.inner()),
        ProbeKind::Ready => (state.probe_hooks.ready)(state.inner()),
    };

    let status = if result.status.is_available() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let payload = ServiceResult::success(ProbeResponse {
        probe: probe.as_str(),
        status: result.status.as_str(),
        service: state.metadata.name.clone(),
        detail: result.detail,
    });

    (status, Json(payload))
}
