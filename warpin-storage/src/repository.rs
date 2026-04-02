use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use futures::try_join;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, ExecResult, FromQueryResult, Statement, Value,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc};
use uuid::Uuid;

use crate::DatabaseRuntime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListResult<T> {
    pub items: Vec<T>,
    pub total: u64,
}

impl<T> ListResult<T> {
    pub fn new(items: Vec<T>, total: u64) -> Self {
        Self { items, total }
    }
}

#[derive(Clone, Debug)]
pub struct DatabaseRepository {
    connection: Arc<DatabaseConnection>,
}

impl DatabaseRepository {
    pub fn new(connection: Arc<DatabaseConnection>) -> Self {
        Self { connection }
    }

    pub fn from_runtime(runtime: &DatabaseRuntime) -> Option<Self> {
        runtime.connection_arc().map(Self::new)
    }

    pub fn connection(&self) -> &DatabaseConnection {
        self.connection.as_ref()
    }
}

#[derive(Debug, FromQueryResult)]
struct CountRow {
    count: i64,
}

pub fn postgres_statement(
    sql: impl Into<String>,
    values: impl IntoIterator<Item = Value>,
) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql.into(), values)
}

pub async fn execute_statement(
    connection: &DatabaseConnection,
    sql: impl Into<String>,
    values: impl IntoIterator<Item = Value>,
) -> Result<ExecResult> {
    let statement = postgres_statement(sql, values);

    connection
        .execute_raw(statement)
        .await
        .with_context(|| "failed to execute sql statement")
}

pub async fn fetch_optional<T>(
    connection: &DatabaseConnection,
    sql: impl Into<String>,
    values: impl IntoIterator<Item = Value>,
) -> Result<Option<T>>
where
    T: FromQueryResult + Send + Sync,
{
    T::find_by_statement(postgres_statement(sql, values))
        .one(connection)
        .await
        .with_context(|| "failed to fetch optional row")
}

pub async fn fetch_all<T>(
    connection: &DatabaseConnection,
    sql: impl Into<String>,
    values: impl IntoIterator<Item = Value>,
) -> Result<Vec<T>>
where
    T: FromQueryResult + Send + Sync,
{
    T::find_by_statement(postgres_statement(sql, values))
        .all(connection)
        .await
        .with_context(|| "failed to fetch rows")
}

pub async fn fetch_count(
    connection: &DatabaseConnection,
    sql: impl Into<String>,
    values: impl IntoIterator<Item = Value>,
) -> Result<u64> {
    let row: Option<CountRow> = fetch_optional(connection, sql, values).await?;
    let count = row.map(|value| value.count).unwrap_or_default();

    u64::try_from(count).with_context(|| "count query returned a negative value")
}

pub async fn soft_delete_by_id(
    connection: &DatabaseConnection,
    table: &str,
    id: Uuid,
) -> Result<bool> {
    let now = Utc::now();
    let sql = format!(
        "UPDATE {table} \
         SET updated_at = $1, deleted_at = $2 \
         WHERE id = $3 AND deleted_at IS NULL"
    );
    let result = execute_statement(connection, sql, [now.into(), now.into(), id.into()]).await?;

    Ok(result.rows_affected() > 0)
}

pub async fn hard_delete_by_id(
    connection: &DatabaseConnection,
    table: &str,
    id: Uuid,
) -> Result<bool> {
    let sql = format!("DELETE FROM {table} WHERE id = $1");
    let result = execute_statement(connection, sql, [id.into()]).await?;

    Ok(result.rows_affected() > 0)
}

pub async fn build_list_result<Condition, Dto, ListFuture, CountFuture, ListFn, CountFn>(
    condition: Condition,
    list_fn: ListFn,
    count_fn: CountFn,
) -> Result<ListResult<Dto>>
where
    Condition: Clone + Send,
    ListFn: FnOnce(Condition) -> ListFuture,
    CountFn: FnOnce(Condition) -> CountFuture,
    ListFuture: Future<Output = Result<Vec<Dto>>> + Send,
    CountFuture: Future<Output = Result<u64>> + Send,
{
    let (items, total) = try_join!(list_fn(condition.clone()), count_fn(condition))?;
    Ok(ListResult::new(items, total))
}

#[async_trait]
pub trait CrudRepository<Id, Dto, Condition>: Send + Sync
where
    Dto: Send,
{
    async fn create(&self, input: Dto) -> Result<Dto>;
    async fn find_by_id(&self, id: Id) -> Result<Option<Dto>>;
    async fn update_by_id(&self, id: Id, input: Dto) -> Result<Option<Dto>>;
    async fn soft_delete_by_id(&self, id: Id) -> Result<bool>;
    async fn hard_delete_by_id(&self, id: Id) -> Result<bool>;
    async fn list_by_condition(&self, condition: Condition) -> Result<Vec<Dto>>;
    async fn count_by_condition(&self, condition: Condition) -> Result<u64>;
    async fn list_with_total(&self, condition: Condition) -> Result<ListResult<Dto>>;
}
