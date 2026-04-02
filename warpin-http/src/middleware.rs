use crate::headers::{
    HEADER_REQUEST_ID, HEADER_SCOPE_ID, HEADER_SESSION_ID, HEADER_TENANT_ID, HEADER_TRACE_ID,
    HEADER_USER_ID,
};
use axum::{body::Body, extract::Request, http::HeaderMap, middleware::Next, response::Response};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct RequestContext {
    pub request_id: String,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub scope_id: Option<String>,
    pub user_id: Option<String>,
}

pub async fn inject_request_context(mut request: Request<Body>, next: Next) -> Response {
    let request_context = request_context_from_headers(request.headers());
    request.extensions_mut().insert(request_context.clone());

    let mut response = next.run(request).await;
    set_response_header(
        response.headers_mut(),
        HEADER_REQUEST_ID,
        Some(request_context.request_id),
    );
    set_response_header(
        response.headers_mut(),
        HEADER_TRACE_ID,
        request_context.trace_id,
    );
    set_response_header(
        response.headers_mut(),
        HEADER_SESSION_ID,
        request_context.session_id,
    );
    set_response_header(
        response.headers_mut(),
        HEADER_USER_ID,
        request_context.user_id,
    );

    response
}

pub fn request_context_from_headers(headers: &HeaderMap) -> RequestContext {
    RequestContext {
        request_id: header_value(headers, HEADER_REQUEST_ID)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        trace_id: header_value(headers, HEADER_TRACE_ID),
        session_id: header_value(headers, HEADER_SESSION_ID),
        tenant_id: header_value(headers, HEADER_TENANT_ID),
        scope_id: header_value(headers, HEADER_SCOPE_ID),
        user_id: header_value(headers, HEADER_USER_ID),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn set_response_header(headers: &mut HeaderMap, name: &'static str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };
    let Ok(value) = value.parse() else {
        return;
    };

    headers.insert(name, value);
}

#[cfg(test)]
mod tests {
    use super::request_context_from_headers;
    use crate::{
        HEADER_REQUEST_ID, HEADER_SCOPE_ID, HEADER_SESSION_ID, HEADER_TENANT_ID, HEADER_TRACE_ID,
        HEADER_USER_ID,
    };
    use axum::{
        Router,
        body::Body,
        extract::Extension,
        http::{HeaderMap, HeaderValue, Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::get,
    };
    use tower::ServiceExt;

    #[test]
    fn request_context_from_headers_reads_traceability_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("req-123"));
        headers.insert(HEADER_TRACE_ID, HeaderValue::from_static("trace-123"));
        headers.insert(HEADER_SESSION_ID, HeaderValue::from_static("session-123"));
        headers.insert(HEADER_TENANT_ID, HeaderValue::from_static("tenant-a"));
        headers.insert(HEADER_SCOPE_ID, HeaderValue::from_static("scope-nb"));
        headers.insert(HEADER_USER_ID, HeaderValue::from_static("user-a"));

        let context = request_context_from_headers(&headers);

        assert_eq!(context.request_id, "req-123");
        assert_eq!(context.trace_id.as_deref(), Some("trace-123"));
        assert_eq!(context.session_id.as_deref(), Some("session-123"));
        assert_eq!(context.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(context.scope_id.as_deref(), Some("scope-nb"));
        assert_eq!(context.user_id.as_deref(), Some("user-a"));
    }

    #[test]
    fn request_context_from_headers_ignores_empty_traceability_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_TRACE_ID, HeaderValue::from_static(""));
        headers.insert(HEADER_SESSION_ID, HeaderValue::from_static(""));

        let context = request_context_from_headers(&headers);

        assert!(!context.request_id.trim().is_empty());
        assert!(context.trace_id.is_none());
        assert!(context.session_id.is_none());
    }

    #[tokio::test]
    async fn inject_request_context_round_trips_user_id_header() {
        let app = Router::new()
            .route(
                "/",
                get(
                    |Extension(context): Extension<crate::RequestContext>| async move {
                        assert_eq!(context.user_id.as_deref(), Some("user-a"));
                        StatusCode::NO_CONTENT.into_response()
                    },
                ),
            )
            .layer(middleware::from_fn(
                crate::middleware::inject_request_context,
            ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HEADER_USER_ID, "user-a")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get(HEADER_USER_ID),
            Some(&HeaderValue::from_static("user-a"))
        );
    }
}
