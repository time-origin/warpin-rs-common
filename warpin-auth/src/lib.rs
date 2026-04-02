use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub tenant_id: String,
    pub exp: DateTime<Utc>,
}

impl Claims {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.exp
    }
}
