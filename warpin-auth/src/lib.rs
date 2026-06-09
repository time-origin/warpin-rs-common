//! Authentication and authorization primitives for the Warpin framework.
//!
//! Provides:
//! - JWT token generation and verification via `JwtManager`
//! - `Claims` struct for encoding user identity and tenant scope
//! - Axum middleware for extracting and validating JWT from requests
//! - `AuthUser` extractor for handler functions

mod jwt;
mod middleware;

pub use jwt::{Claims, JwtConfig, JwtManager};
pub use middleware::{AuthUser, JwtAuthLayer};
