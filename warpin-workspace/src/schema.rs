//! Explicit operator migration; runtime can only verify the fixed catalog and
//! read its immutable receipt. A drifted/partial schema is never repaired here.
use anyhow::{Context, Result, ensure};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, Statement, Value as DbValue,
};
use serde_json::Value;
use warpin_integrity::{Sha256Digest, digest_bytes, digest_typed};
use warpin_storage::{postgres_statement, run_in_transaction};

use crate::ledger::SCHEMA_SQL;

pub const MIGRATION_ID: &str = "warpin-workspace/ledger/v1";
const VERSION_SQL: &str = include_str!("schema/version.sql");
const CATALOG_SQL: &str = include_str!("schema/catalog.sql");
const BASELINE_CATALOG: &str = include_str!("schema/catalog-baseline-v1.json");
const CURRENT_CATALOG: &str = include_str!("schema/catalog-current-v1.json");
pub mod roles;

async fn require_owner(tx: &DatabaseTransaction, schema: &WorkspaceSchema) -> Result<()> {
    let owner = tx.query_one_raw(postgres_statement(
        "SELECT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname=$1 AND pg_has_role(current_user,n.nspowner,'USAGE')) AS owns_schema",
        [schema.as_str().to_owned().into()],
    )).await?.context("workspace schema owner absent")?;
    ensure!(
        owner.try_get::<bool>("", "owns_schema")?,
        "workspace migration requires schema owner"
    );
    Ok(())
}

/// Explicit administrator-owned PostgreSQL namespace. Never derived from a
/// connection search_path, task payload, temporary relation or user identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSchema(String);

impl WorkspaceSchema {
    pub fn parse(name: &str) -> Result<Self> {
        ensure!(
            !name.is_empty()
                && name.len() <= 63
                && name.as_bytes()[0].is_ascii_lowercase()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && name != "public"
                && name != "pg_catalog"
                && name != "information_schema"
                && !name.starts_with("pg_"),
            "invalid workspace owning schema"
        );
        Ok(Self(name.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
    fn qualify(&self, sql: &str) -> String {
        let mut qualified = sql.to_owned();
        for table in [
            "warpin_workspace_pools_v1",
            "warpin_workspace_allocations_v1",
            "warpin_workspace_pool_authorities_v1",
            "warpin_workspace_schema_versions_v1",
        ] {
            qualified = qualified.replace(table, &format!("{}.\"{}\"", self.quoted(), table));
        }
        qualified
    }
    async fn pin_search_path(&self, tx: &DatabaseTransaction) -> Result<()> {
        tx.execute_unprepared(&format!(
            "SET LOCAL search_path TO pg_catalog, {}, pg_temp",
            self.quoted()
        ))
        .await?;
        Ok(())
    }
}

/// Only fixed workspace-owned SQL is passed by crate internals. Reuse the
/// public PostgreSQL binder after binding each table to the owning namespace.
pub(crate) fn statement(
    schema: &WorkspaceSchema,
    sql: &str,
    values: impl IntoIterator<Item = DbValue>,
) -> Statement {
    postgres_statement(schema.qualify(sql), values)
}

pub fn migration_checksum() -> Sha256Digest {
    // Length delimiter binds both source files without ambiguous concatenation.
    digest_bytes(format!("{}\n{}\n{}", SCHEMA_SQL.len(), SCHEMA_SQL, VERSION_SQL).as_bytes())
}

fn expected_catalog() -> Result<Value> {
    Ok(serde_json::from_str(CURRENT_CATALOG)?)
}

async fn catalog(tx: &DatabaseTransaction, schema: &WorkspaceSchema) -> Result<Value> {
    let row = tx
        .query_one_raw(postgres_statement(
            CATALOG_SQL,
            [schema.as_str().to_owned().into()],
        ))
        .await?
        .context("workspace schema catalog absent")?;
    Ok(row.try_get("", "catalog")?)
}

async fn receipt(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    observed: &Value,
) -> Result<()> {
    let rows = tx
        .query_all_raw(statement(schema,
            "SELECT migration_id,migration_checksum,catalog_digest FROM warpin_workspace_schema_versions_v1",
            [],
        ))
        .await?;
    ensure!(rows.len() == 1, "workspace migration receipt count differs");
    let row = &rows[0];
    ensure!(
        row.try_get::<String>("", "migration_id")? == MIGRATION_ID
            && row.try_get::<String>("", "migration_checksum")? == migration_checksum().as_str()
            && row.try_get::<String>("", "catalog_digest")? == digest_typed(observed)?.as_str(),
        "workspace migration receipt checksum differs"
    );
    Ok(())
}

/// Runtime check inside the same transaction as a ledger mutation. Shared
/// migration locks exclude governed operator DDL; ACCESS SHARE blocks ordinary
/// AccessExclusive DDL without granting metadata/table-wide UPDATE to runtime.
/// Superuser DDL bypassing this protocol is outside that concurrency guarantee.
pub(crate) async fn check_transaction(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
) -> Result<()> {
    schema.pin_search_path(tx).await?;
    tx.execute_raw(postgres_statement("SELECT pg_advisory_xact_lock_shared(hashtextextended($1||'/warpin-workspace-migration',0))", [schema.as_str().to_owned().into()])).await?;
    tx.execute_unprepared(&schema.qualify("LOCK TABLE warpin_workspace_pools_v1,warpin_workspace_allocations_v1,warpin_workspace_pool_authorities_v1,warpin_workspace_schema_versions_v1 IN ACCESS SHARE MODE")).await?;
    let observed = catalog(tx, schema).await?;
    ensure!(
        observed == expected_catalog()?,
        "workspace schema catalog drift"
    );
    receipt(tx, schema, &observed).await
}

pub async fn verify(database: &DatabaseConnection, schema: &WorkspaceSchema) -> Result<()> {
    let schema = schema.clone();
    run_in_transaction(database, move |tx| {
        Box::pin(async move { check_transaction(tx, &schema).await })
    })
    .await
}

/// Operator only. Empty schemas or the exact unpublished three-table baseline
/// may be installed; any partial or altered state rejects before mutation.
pub async fn install(database: &DatabaseConnection, schema: &WorkspaceSchema) -> Result<()> {
    let schema = schema.clone();
    run_in_transaction(database, move |tx| Box::pin(async move {
        schema.pin_search_path(tx).await?;
        require_owner(tx, &schema).await?;
        tx.execute_raw(postgres_statement("SELECT pg_advisory_xact_lock(hashtextextended($1||'/warpin-workspace-migration',0))", [schema.as_str().to_owned().into()])).await?;
        let before = catalog(tx, &schema).await?;
        let empty = before["tables"].as_array().is_some_and(Vec::is_empty)
            && ["columns","constraints","indexes","triggers","inheritance","functions"].iter().all(|key| before[key].as_array().is_some_and(Vec::is_empty));
        if before == expected_catalog()? {
            return check_transaction(tx, &schema).await;
        }
        let baseline: Value = serde_json::from_str(BASELINE_CATALOG)?;
        ensure!(empty || before == baseline, "workspace partial/baseline schema drift");
        // Hold the preexisting baseline against concurrent operator DDL too.
        if !empty {
            tx.execute_unprepared(&schema.qualify("LOCK TABLE warpin_workspace_pools_v1,warpin_workspace_allocations_v1,warpin_workspace_pool_authorities_v1 IN SHARE MODE")).await?;
            ensure!(catalog(tx, &schema).await? == baseline, "workspace baseline changed across migration lock");
        }
        tx.execute_unprepared(&schema.qualify(SCHEMA_SQL)).await?;
        tx.execute_unprepared(&schema.qualify(VERSION_SQL)).await?;
        let observed = catalog(tx, &schema).await?;
        ensure!(observed == expected_catalog()?, "workspace installed catalog differs");
        tx.execute_raw(statement(&schema,
            "INSERT INTO warpin_workspace_schema_versions_v1(migration_id,migration_checksum,catalog_digest) VALUES($1,$2,$3)",
            [MIGRATION_ID.into(),migration_checksum().to_string().into(),digest_typed(&observed)?.to_string().into()],
        )).await?;
        check_transaction(tx, &schema).await
    })).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn explicit_owning_schema_rejects_search_path_injection_and_system_names() {
        for value in [
            "",
            "A",
            "pg_temp",
            "pg_catalog",
            "information_schema",
            "a,b",
            "a\";DROP SCHEMA x;--",
            "a.b",
        ] {
            assert!(super::WorkspaceSchema::parse(value).is_err());
        }
        let schema = super::WorkspaceSchema::parse("resource_ledger").unwrap();
        assert_eq!(
            schema.qualify("SELECT * FROM warpin_workspace_pools_v1"),
            "SELECT * FROM \"resource_ledger\".\"warpin_workspace_pools_v1\""
        );
    }
    #[test]
    fn source_checksum_and_reference_catalog_are_explicit() {
        assert!(super::migration_checksum().as_str().starts_with("sha256:"));
        let current = super::expected_catalog().unwrap();
        let baseline: serde_json::Value = serde_json::from_str(super::BASELINE_CATALOG).unwrap();
        assert_eq!(current["tables"].as_array().unwrap().len(), 4);
        assert_eq!(baseline["tables"].as_array().unwrap().len(), 3);
        assert!(current["triggers"].as_array().unwrap().is_empty());
    }
}
