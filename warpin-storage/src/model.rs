use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseModel {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

pub fn new_base_model() -> BaseModel {
    let now = Utc::now();

    BaseModel {
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        deleted_at: None,
    }
}
