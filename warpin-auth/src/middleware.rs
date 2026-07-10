//! Axum middleware for JWT authentication.
//!
//! Provides:
//! - `JwtAuthLayer`: Tower layer that validates JWT tokens on incoming requests
//! - `AuthUser`: Axum extractor for accessing the authenticated user's claims

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{FromRequestParts, Request},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use tower::Layer;

use crate::jwt::{Claims, JwtManager};

/// Axum extractor that provides the authenticated user's JWT claims.
///
/// Use this in handler functions to access the current user:
///
/// ```ignore
/// async fn my_handler(auth: AuthUser) -> impl IntoResponse {
///     let user_id = auth.claims.user_id();
///     let tenant = auth.claims.tenant_id();
///     // ...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub claims: Claims,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "authentication required"))
    }
}

/// Tower layer that validates JWT tokens on incoming requests.
///
/// Extracts the `Authorization: Bearer <token>` header, verifies the token,
/// and injects `AuthUser` into the request extensions for downstream handlers.
///
/// On failure, returns 401 Unauthorized.
#[derive(Clone)]
pub struct JwtAuthLayer {
    jwt_manager: Arc<JwtManager>,
}

impl JwtAuthLayer {
    /// Create a new JWT auth layer.
    pub fn new(jwt_manager: JwtManager) -> Self {
        Self {
            jwt_manager: Arc::new(jwt_manager),
        }
    }

    /// Create from an Arc'd JwtManager (for sharing across layers).
    pub fn from_arc(jwt_manager: Arc<JwtManager>) -> Self {
        Self { jwt_manager }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            jwt_manager: Arc::clone(&self.jwt_manager),
        }
    }
}

/// The middleware service created by `JwtAuthLayer`.
#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    inner: S,
    jwt_manager: Arc<JwtManager>,
}

impl<S> tower::Service<Request<Body>> for JwtAuthMiddleware<S>
where
    S: tower::Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let jwt_manager = Arc::clone(&self.jwt_manager);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract the Authorization header
            let auth_header = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string());

            let token = match auth_header {
                Some(ref h) if h.starts_with("Bearer ") => &h[7..],
                _ => {
                    tracing::debug!("missing or malformed Authorization header");
                    return Ok(unauthorized("missing or invalid authorization header"));
                }
            };

            // Verify the token
            match jwt_manager.verify_token(token) {
                Ok(claims) => {
                    tracing::trace!(
                        user_id = %claims.sub,
                        tenant_id = %claims.tenant_id,
                        role = %claims.role,
                        "JWT verified"
                    );
                    // Inject AuthUser into request extensions
                    request.extensions_mut().insert(AuthUser { claims });
                    inner.call(request).await
                }
                Err(e) => {
                    tracing::debug!(error = %e, "JWT verification failed");
                    Ok(unauthorized("invalid or expired token"))
                }
            }
        })
    }
}

/// Helper to create a 401 response with a JSON body.
fn unauthorized(message: &str) -> Response {
    let body = serde_json::json!({
        "code": 401,
        "msg": message,
        "data": serde_json::Value::Null,
    });
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtConfig;
    use axum::{Router, routing::get};
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_jwt_manager() -> JwtManager {
        JwtManager::new(&JwtConfig {
            secret: "test-secret-key-at-least-32-characters-long".to_string(),
            issuer: "test-issuer".to_string(),
            expiration_hours: 24,
        })
    }

    fn test_app() -> Router {
        let jwt = test_jwt_manager();
        Router::new()
            .route(
                "/protected",
                get(|auth: AuthUser| async move { format!("hello {}", auth.claims.user_id()) }),
            )
            .layer(JwtAuthLayer::new(jwt))
    }

    #[tokio::test]
    async fn request_without_auth_header_returns_401() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_invalid_token_returns_401() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", "Bearer invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_valid_token_succeeds() {
        let jwt = test_jwt_manager();
        let user_id = Uuid::new_v4();
        let token = jwt.generate_token(user_id, "tenant-a", "admin").unwrap();

        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains(&user_id.to_string()));
    }

    #[tokio::test]
    async fn request_with_malformed_auth_header_returns_401() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
