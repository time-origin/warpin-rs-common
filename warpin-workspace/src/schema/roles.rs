//! Dedicated runtime-role grants. No database-wide/PUBLIC role changes, role
//! creation, membership editing or credentials are performed by this module.
use anyhow::{Context, Result, ensure};
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction};
use warpin_storage::{postgres_statement, run_in_transaction};

use super::{WorkspaceSchema, check_transaction, expected_catalog, require_owner};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRole(WorkspaceSchema);

impl RuntimeRole {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(Self(WorkspaceSchema::parse(name)?))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

const TABLES: [&str; 4] = [
    "warpin_workspace_pools_v1",
    "warpin_workspace_allocations_v1",
    "warpin_workspace_pool_authorities_v1",
    "warpin_workspace_schema_versions_v1",
];

async fn attributes(tx: &DatabaseTransaction, role: &RuntimeRole) -> Result<()> {
    let row = tx.query_one_raw(postgres_statement(
        "SELECT NOT (r.rolsuper OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls) AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid) AS restricted FROM pg_roles r WHERE r.rolname=$1",
        [role.as_str().to_owned().into()],
    )).await?.context("workspace runtime role absent")?;
    ensure!(
        row.try_get::<bool>("", "restricted")?,
        "workspace runtime role attributes/membership exceed authority"
    );
    Ok(())
}

fn columns(table: &str) -> Result<Vec<String>> {
    expected_catalog()?["columns"]
        .as_array()
        .context("workspace expected columns absent")?
        .iter()
        .filter(|row| row["table"] == table)
        .map(|row| {
            row["name"]
                .as_str()
                .context("workspace expected column name absent")
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>>>()
}

async fn verify_transaction(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    role: &RuntimeRole,
) -> Result<()> {
    check_transaction(tx, schema).await?;
    attributes(tx, role).await?;
    let row = tx.query_one_raw(postgres_statement(
        "SELECT has_schema_privilege($1,$2,'USAGE') AND NOT has_schema_privilege($1,$2,'CREATE') AND NOT has_schema_privilege($1,$2,'USAGE WITH GRANT OPTION') AND NOT has_schema_privilege($1,$2,'CREATE WITH GRANT OPTION') AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname=$2 AND a.grantee=0) AS safe",
        [role.as_str().to_owned().into(),schema.as_str().to_owned().into()],
    )).await?.context("workspace runtime schema privilege absent")?;
    ensure!(
        row.try_get::<bool>("", "safe")?,
        "workspace runtime schema privileges exceed authority"
    );
    for table in TABLES {
        let relation = format!("{}.\"{}\"", schema.quoted(), table);
        let row = tx.query_one_raw(postgres_statement(
            "SELECT NOT EXISTS(SELECT 1 FROM pg_class c,LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=$1::regclass AND a.grantee=0) AND NOT EXISTS(SELECT 1 FROM pg_attribute p,LATERAL aclexplode(p.attacl) a WHERE p.attrelid=$1::regclass AND a.grantee=0) AS private",
            [relation.clone().into()],
        )).await?.context("workspace table privilege absent")?;
        ensure!(
            row.try_get::<bool>("", "private")?,
            "workspace PUBLIC ledger grant exceeds authority"
        );
        for privilege in [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            let row = tx
                .query_one_raw(postgres_statement(
                    "SELECT has_table_privilege($1,$2,$3) AS permitted, has_table_privilege($1,$2,$3||' WITH GRANT OPTION') AS delegable",
                    [
                        role.as_str().to_owned().into(),
                        relation.clone().into(),
                        privilege.into(),
                    ],
                ))
                .await?
                .context("workspace table privilege absent")?;
            ensure!(
                row.try_get::<bool>("", "permitted")? == (privilege == "SELECT")
                    && !row.try_get::<bool>("", "delegable")?,
                "workspace runtime table privilege differs"
            );
        }
        for column in columns(table)? {
            for privilege in ["SELECT", "INSERT", "UPDATE", "REFERENCES"] {
                let expected = privilege == "SELECT"
                    || privilege == "INSERT"
                        && matches!(
                            table,
                            "warpin_workspace_allocations_v1"
                                | "warpin_workspace_pool_authorities_v1"
                        )
                    || privilege == "UPDATE"
                        && (table == "warpin_workspace_pools_v1"
                            && matches!(column.as_str(), "reserved_bytes" | "reserved_inodes")
                            || table == "warpin_workspace_allocations_v1"
                                && matches!(
                                    column.as_str(),
                                    "state" | "record_json" | "record_digest"
                                ));
                let row = tx
                    .query_one_raw(postgres_statement(
                        "SELECT has_column_privilege($1,$2,$3,$4) AS permitted, has_column_privilege($1,$2,$3,$4||' WITH GRANT OPTION') AS delegable",
                        [
                            role.as_str().to_owned().into(),
                            relation.clone().into(),
                            column.clone().into(),
                            privilege.into(),
                        ],
                    ))
                    .await?
                    .context("workspace column privilege absent")?;
                ensure!(
                    row.try_get::<bool>("", "permitted")? == expected
                        && !row.try_get::<bool>("", "delegable")?,
                    "workspace runtime column privilege differs"
                );
            }
        }
    }
    Ok(())
}

pub async fn verify(
    database: &DatabaseConnection,
    schema: &WorkspaceSchema,
    role: &RuntimeRole,
) -> Result<()> {
    let schema = schema.clone();
    let role = role.clone();
    run_in_transaction(database, move |tx| {
        Box::pin(async move {
            let caller = tx
                .query_one_raw(postgres_statement(
                    "SELECT current_user::text AS role, session_user::text AS session_role",
                    [],
                ))
                .await?
                .context("workspace runtime session identity absent")?;
            ensure!(
                caller.try_get::<String>("", "role")? == role.as_str()
                    && caller.try_get::<String>("", "session_role")? == role.as_str(),
                "workspace runtime session differs from configured role"
            );
            verify_transaction(tx, &schema, &role).await
        })
    })
    .await
}

/// Explicit owner action on this dedicated schema and named runtime role only.
/// Existing role attributes/memberships are checked, never changed implicitly.
pub async fn grant(
    database: &DatabaseConnection,
    schema: &WorkspaceSchema,
    role: &RuntimeRole,
) -> Result<()> {
    let schema = schema.clone();
    let role = role.clone();
    run_in_transaction(database, move |tx| Box::pin(async move {
        require_owner(tx, &schema).await?;
        tx.execute_raw(postgres_statement("SELECT pg_advisory_xact_lock(hashtextextended($1||'/warpin-workspace-migration',0))", [schema.as_str().to_owned().into()])).await?;
        check_transaction(tx, &schema).await?;
        attributes(tx, &role).await?;
        let name = role.0.quoted();
        tx.execute_unprepared(&format!("REVOKE ALL ON SCHEMA {} FROM PUBLIC; REVOKE ALL ON SCHEMA {} FROM {}; GRANT USAGE ON SCHEMA {} TO {}",schema.quoted(),schema.quoted(),name,schema.quoted(),name)).await?;
        for table in TABLES {
            let relation = format!("{}.\"{}\"", schema.quoted(), table);
            let column_names = columns(table)?.iter().map(|name| format!("\"{}\"", name)).collect::<Vec<_>>().join(",");
            tx.execute_unprepared(&format!("REVOKE ALL ON TABLE {relation} FROM PUBLIC,{name}; REVOKE ALL ({column_names}) ON TABLE {relation} FROM PUBLIC,{name}; GRANT SELECT ON TABLE {relation} TO {name}")).await?;
            let writes = match table {
                "warpin_workspace_pools_v1" => "UPDATE (reserved_bytes,reserved_inodes)",
                "warpin_workspace_allocations_v1" => "INSERT (allocation_id,pool_id,reserved_bytes,reserved_inodes,state,record_json,record_digest), UPDATE (state,record_json,record_digest)",
                "warpin_workspace_pool_authorities_v1" => "INSERT (pool_id,authority_json,authority_digest)",
                _ => continue,
            };
            tx.execute_unprepared(&format!("GRANT {writes} ON TABLE {relation} TO {name}")).await?;
        }
        verify_transaction(tx, &schema, &role).await
    })).await
}
