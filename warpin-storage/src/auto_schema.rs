//! Automatic database schema synchronization from SeaORM entity definitions.
//!
//! Provides JPA-like `ddl-auto=update` behavior:
//! - Creates tables that don't exist based on entity definitions
//! - Adds columns that are missing from existing tables
//! - Never drops tables or columns (additive only, safe for production)
//!
//! This module is designed as a **generic, reusable** component — it has no
//! business-specific logic and can be used by any project that uses SeaORM
//! with PostgreSQL.
//!
//! # Usage
//!
//! ```ignore
//! use warpin_storage::{SchemaPlan, DatabaseRuntime};
//!
//! let plan = SchemaPlan::new()
//!     .register::<user::Entity>()
//!     .register::<task::Entity>();
//!
//! let db = DatabaseRuntime::bootstrap(&settings, &options, &plan).await;
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use sea_orm::sea_query::Table;
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, FromQueryResult, Schema,
    Statement,
};
use serde::Serialize;
use std::marker::PhantomData;
use tracing::info;

// ─── Report ──────────────────────────────────────────────────────────────────

/// Summary of all schema sync operations performed during a single bootstrap cycle.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SchemaSyncReport {
    /// Total number of entities registered in the plan
    pub entities_registered: usize,
    /// Number of tables created (did not exist before)
    pub tables_created: usize,
    /// Number of tables updated (columns added)
    pub tables_updated: usize,
    /// Total number of columns added across all tables
    pub columns_added: usize,
}

// ─── Internal: per-table sync result ─────────────────────────────────────────

enum TableSyncAction {
    Created,
    Updated { columns_added: Vec<String> },
    Unchanged,
}

// ─── Internal: type-erased entity sync trait ─────────────────────────────────

#[async_trait]
trait SchemaEntity: Send + Sync {
    fn table_name(&self) -> String;
    async fn sync(&self, db: &DatabaseConnection) -> Result<TableSyncAction>;
}

// ─── Internal: generic implementation for any SeaORM entity ──────────────────

struct EntitySchemaSync<E: EntityTrait> {
    _marker: PhantomData<E>,
}

impl<E: EntityTrait> EntitySchemaSync<E> {
    fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<E> SchemaEntity for EntitySchemaSync<E>
where
    E: EntityTrait + Default + Send + Sync + 'static,
{
    fn table_name(&self) -> String {
        E::default().table_name().to_string()
    }

    async fn sync(&self, db: &DatabaseConnection) -> Result<TableSyncAction> {
        let backend = db.get_database_backend();
        let entity = E::default();
        let table_name = entity.table_name().to_string();
        let schema_name = entity.schema_name().unwrap_or("public").to_string();

        if !table_exists(db, &schema_name, &table_name).await? {
            create_table::<E>(db, backend).await?;
            return Ok(TableSyncAction::Created);
        }

        let added = sync_columns::<E>(db, backend, &schema_name, &table_name).await?;
        if added.is_empty() {
            Ok(TableSyncAction::Unchanged)
        } else {
            Ok(TableSyncAction::Updated {
                columns_added: added,
            })
        }
    }
}

// ─── Internal: schema operations ─────────────────────────────────────────────

async fn create_table<E>(db: &DatabaseConnection, backend: DatabaseBackend) -> Result<()>
where
    E: EntityTrait + Default,
{
    let schema = Schema::new(backend);
    let create_stmt = schema
        .create_table_from_entity(E::default())
        .if_not_exists()
        .to_owned();

    db.execute(&create_stmt)
        .await
        .with_context(|| format!("failed to create table '{}'", E::default().table_name()))?;

    Ok(())
}

async fn sync_columns<E>(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    schema_name: &str,
    table_name: &str,
) -> Result<Vec<String>>
where
    E: EntityTrait + Default,
{
    let existing = get_existing_columns(db, schema_name, table_name).await?;
    let mut added = Vec::new();

    // Generate CREATE TABLE statement to extract properly built column definitions.
    // Schema::create_table_from_entity produces ColumnDefs with correct names and types.
    let schema = Schema::new(backend);
    let create_stmt = schema.create_table_from_entity(E::default());

    for col_def in create_stmt.get_columns() {
        let col_name = col_def.get_column_name().to_string();

        if existing.contains(&col_name) {
            continue;
        }

        let mut alter_col_def = col_def.clone();
        let alter_stmt = Table::alter()
            .table(E::default().table_ref())
            .add_column(&mut alter_col_def)
            .to_owned();

        db.execute(&alter_stmt).await.with_context(|| {
            format!(
                "failed to add column '{}' to table '{}'",
                col_name, table_name
            )
        })?;

        added.push(col_name);
    }

    Ok(added)
}

// ─── Internal: information_schema queries ────────────────────────────────────

#[derive(Debug, FromQueryResult)]
struct CountResult {
    count: i64,
}

async fn table_exists(
    db: &DatabaseConnection,
    schema_name: &str,
    table_name: &str,
) -> Result<bool> {
    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"SELECT COUNT(*)::bigint AS count
           FROM information_schema.tables
           WHERE table_schema = $1 AND table_name = $2"#,
        [
            schema_name.to_string().into(),
            table_name.to_string().into(),
        ],
    );

    let result = CountResult::find_by_statement(stmt)
        .one(db)
        .await
        .with_context(|| format!("failed to check existence of table '{}'", table_name))?;

    Ok(result.map(|r| r.count > 0).unwrap_or(false))
}

#[derive(Debug, FromQueryResult)]
struct ColumnRow {
    column_name: String,
}

async fn get_existing_columns(
    db: &DatabaseConnection,
    schema_name: &str,
    table_name: &str,
) -> Result<Vec<String>> {
    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"SELECT column_name
           FROM information_schema.columns
           WHERE table_schema = $1 AND table_name = $2"#,
        [
            schema_name.to_string().into(),
            table_name.to_string().into(),
        ],
    );

    let rows = ColumnRow::find_by_statement(stmt)
        .all(db)
        .await
        .with_context(|| format!("failed to query columns of table '{}'", table_name))?;

    Ok(rows.into_iter().map(|r| r.column_name).collect())
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Declarative schema plan that registers SeaORM entities for automatic DDL sync.
///
/// On bootstrap, the plan iterates registered entities and ensures the database
/// schema matches the entity definitions:
/// - Missing tables are created with all columns, primary keys, and indexes
/// - Missing columns in existing tables are added via `ALTER TABLE`
/// - No destructive operations are ever performed (no `DROP TABLE`/`COLUMN`)
///
/// # Example
///
/// ```ignore
/// let plan = SchemaPlan::new()
///     .register::<satellite::Entity>()
///     .register::<ground_station::Entity>()
///     .register::<pass_plan::Entity>();
/// ```
pub struct SchemaPlan {
    entities: Vec<Box<dyn SchemaEntity>>,
}

impl Default for SchemaPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaPlan {
    /// Create an empty schema plan with no entities registered.
    pub fn new() -> Self {
        Self {
            entities: Vec::new(),
        }
    }

    /// Register a SeaORM entity for automatic schema synchronization.
    ///
    /// The entity's table will be created if it doesn't exist, and missing
    /// columns will be added to existing tables. Entities are synced in
    /// registration order — register parent tables before child tables
    /// if foreign key constraints exist.
    pub fn register<E>(mut self) -> Self
    where
        E: EntityTrait + Default + Send + Sync + 'static,
    {
        self.entities.push(Box::new(EntitySchemaSync::<E>::new()));
        self
    }

    /// Number of entities registered in this plan.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Returns true if no entities are registered.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }
}

/// Execute schema synchronization against the database.
///
/// Iterates all registered entities in order, creating tables and adding
/// columns as needed. Operations are **additive only** — nothing is ever dropped.
///
/// Returns a [`SchemaSyncReport`] summarizing what was done.
pub async fn sync_schema(db: &DatabaseConnection, plan: &SchemaPlan) -> Result<SchemaSyncReport> {
    let mut report = SchemaSyncReport {
        entities_registered: plan.len(),
        ..Default::default()
    };

    if plan.is_empty() {
        info!("schema sync: no entities registered, skipping");
        return Ok(report);
    }

    info!("schema sync: synchronizing {} entities", plan.len());

    for entity in &plan.entities {
        let table_name = entity.table_name();
        match entity.sync(db).await? {
            TableSyncAction::Created => {
                info!("schema sync: created table '{}'", table_name);
                report.tables_created += 1;
            }
            TableSyncAction::Updated { columns_added } => {
                info!(
                    "schema sync: updated table '{}', added columns: {:?}",
                    table_name, columns_added
                );
                report.tables_updated += 1;
                report.columns_added += columns_added.len();
            }
            TableSyncAction::Unchanged => {
                info!("schema sync: table '{}' is up to date", table_name);
            }
        }
    }

    info!(
        "schema sync: completed — {} created, {} updated, {} columns added",
        report.tables_created, report.tables_updated, report.columns_added
    );

    Ok(report)
}
