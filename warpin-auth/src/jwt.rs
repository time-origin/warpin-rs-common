//! JWT token generation, verification, and claims management.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct JwtConfig {
    /// HMAC secret key for signing tokens.
    pub secret: String,
    /// Token issuer (e.g., "ttc-customer-service").
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// Token expiration in hours (default: 24).
    #[serde(default = "default_expiration_hours")]
    pub expiration_hours: i64,
}

fn default_issuer() -> String {
    "ttc-service".to_string()
}

fn default_expiration_hours() -> i64 {
    24
}

/// JWT claims payload embedded in every token.
///
/// Uses the standard `sub`, `exp`, `iss`, `iat` fields, plus custom TTC fields
/// for tenant scope and user role.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: user ID (UUID).
    pub sub: Uuid,
    /// Tenant/customer ID.
    pub tenant_id: String,
    /// User role (e.g., "admin", "operator", "viewer").
    #[serde(default)]
    pub role: String,
    /// Token issuer.
    #[serde(default)]
    pub iss: String,
    /// Issued at (Unix timestamp).
    #[serde(default)]
    pub iat: i64,
    /// Expiration (Unix timestamp) — required by jsonwebtoken for validation.
    pub exp: i64,
}

impl Claims {
    /// Check if the token has expired relative to the given time.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now.timestamp() >= self.exp
    }

    /// Get the user ID.
    pub fn user_id(&self) -> Uuid {
        self.sub
    }

    /// Get the tenant ID.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Get the user role.
    pub fn role(&self) -> &str {
        &self.role
    }
}

/// Errors during JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token encoding failed: {0}")]
    EncodingFailed(#[source] jsonwebtoken::errors::Error),

    #[error("token decoding failed: {0}")]
    DecodingFailed(#[source] jsonwebtoken::errors::Error),

    #[error("token has expired")]
    Expired,

    #[error("invalid token format")]
    InvalidFormat,
}

/// JWT manager for generating and verifying tokens.
///
/// Thread-safe and cheaply cloneable — share via `Arc` or `Clone`.
#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    expiration_hours: i64,
    validation: Validation,
}

impl JwtManager {
    /// Create a new JWT manager from configuration.
    pub fn new(config: &JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.validate_exp = true;

        Self {
            encoding_key,
            decoding_key,
            issuer: config.issuer.clone(),
            expiration_hours: config.expiration_hours,
            validation,
        }
    }

    /// Generate a JWT token for the given user.
    ///
    /// The token includes user ID, tenant scope, role, and expiration.
    pub fn generate_token(
        &self,
        user_id: Uuid,
        tenant_id: &str,
        role: &str,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            sub: user_id,
            tenant_id: tenant_id.to_string(),
            role: role.to_string(),
            iss: self.issuer.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(JwtError::EncodingFailed)
    }

    /// Verify and decode a JWT token.
    ///
    /// Returns the decoded claims if the token is valid, not expired,
    /// and was issued by the expected issuer.
    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(JwtError::DecodingFailed)?;

        Ok(token_data.claims)
    }

    /// Get the configured issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

impl std::fmt::Debug for JwtManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtManager")
            .field("issuer", &self.issuer)
            .field("expiration_hours", &self.expiration_hours)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        JwtConfig {
            secret: "test-secret-key-at-least-32-characters-long".to_string(),
            issuer: "test-issuer".to_string(),
            expiration_hours: 24,
        }
    }

    #[test]
    fn generate_and_verify_token() {
        let manager = JwtManager::new(&test_config());
        let user_id = Uuid::new_v4();

        let token = manager
            .generate_token(user_id, "tenant-a", "admin")
            .expect("should generate token");

        let claims = manager.verify_token(&token).expect("should verify token");

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.tenant_id, "tenant-a");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.iss, "test-issuer");
        assert!(!claims.is_expired(Utc::now()));
    }

    #[test]
    fn verify_invalid_token_fails() {
        let manager = JwtManager::new(&test_config());
        let result = manager.verify_token("not-a-valid-token");
        assert!(result.is_err());
    }

    #[test]
    fn verify_token_with_wrong_secret_fails() {
        let config1 = test_config();
        let mut config2 = test_config();
        config2.secret = "different-secret-key-at-least-32-chars".to_string();

        let manager1 = JwtManager::new(&config1);
        let manager2 = JwtManager::new(&config2);

        let token = manager1
            .generate_token(Uuid::new_v4(), "t1", "user")
            .unwrap();

        assert!(manager2.verify_token(&token).is_err());
    }

    #[test]
    fn verify_token_with_wrong_issuer_fails() {
        let config1 = test_config();
        let mut config2 = test_config();
        config2.issuer = "wrong-issuer".to_string();

        let manager1 = JwtManager::new(&config1);
        let manager2 = JwtManager::new(&config2);

        let token = manager1
            .generate_token(Uuid::new_v4(), "t1", "user")
            .unwrap();

        assert!(manager2.verify_token(&token).is_err());
    }

    #[test]
    fn claims_is_expired() {
        let past = Utc::now() - Duration::hours(1);
        let claims = Claims {
            sub: Uuid::new_v4(),
            tenant_id: "t1".into(),
            role: "user".into(),
            iss: "test".into(),
            iat: past.timestamp() - 3600,
            exp: past.timestamp(),
        };
        assert!(claims.is_expired(Utc::now()));
    }

    #[test]
    fn claims_not_expired() {
        let future = Utc::now() + Duration::hours(1);
        let claims = Claims {
            sub: Uuid::new_v4(),
            tenant_id: "t1".into(),
            role: "user".into(),
            iss: "test".into(),
            iat: Utc::now().timestamp(),
            exp: future.timestamp(),
        };
        assert!(!claims.is_expired(Utc::now()));
    }

    #[test]
    fn claims_accessors() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id,
            tenant_id: "my-tenant".into(),
            role: "operator".into(),
            iss: "test".into(),
            iat: 0,
            exp: i64::MAX,
        };
        assert_eq!(claims.user_id(), user_id);
        assert_eq!(claims.tenant_id(), "my-tenant");
        assert_eq!(claims.role(), "operator");
    }

    #[test]
    fn jwt_manager_debug_does_not_leak_secret() {
        let manager = JwtManager::new(&test_config());
        let debug_str = format!("{:?}", manager);
        assert!(!debug_str.contains("test-secret"));
        assert!(debug_str.contains("test-issuer"));
    }
}
