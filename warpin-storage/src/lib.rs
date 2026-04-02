pub mod auto_schema;
mod connector;
mod model;
mod query_helper;
mod repository;
pub mod runtime;
mod transaction;
mod validator;

pub use auto_schema::{SchemaPlan, SchemaSyncReport, sync_schema};
pub use connector::{DatabaseSettings, connect, health_check};
pub use model::{BaseModel, new_base_model};
pub use query_helper::{PageRequest, SortDirection, SortSpec, apply_pagination};
pub use repository::{
    CrudRepository, DatabaseRepository, ListResult, build_list_result, execute_statement,
    fetch_all, fetch_count, fetch_optional, hard_delete_by_id, postgres_statement,
    soft_delete_by_id,
};
pub use runtime::{
    DatabaseBootstrapOptions, DatabaseRuntime, DatabaseRuntimeState, DatabaseRuntimeStatus,
};
pub use transaction::run_in_transaction;
pub use validator::{ensure_non_empty, ensure_unique_absent};

use anyhow::{Result, anyhow};

pub fn object_key(namespace: &str, name: &str) -> Result<String> {
    if namespace.is_empty() || name.is_empty() {
        return Err(anyhow!("namespace and name must not be empty"));
    }

    Ok(format!("{namespace}/{name}"))
}
