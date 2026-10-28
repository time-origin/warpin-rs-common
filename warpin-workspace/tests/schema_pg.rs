//! Ordinary, uniquely named database fixtures; no physical manager or device.
use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use std::sync::Arc;
use uuid::Uuid;
use warpin_workspace::{
    AllocationIdentity, AllocationRequest, VolumeBudget, WorkspacePolicy,
    ledger::PostgresAllocationLedger,
    schema::{
        WorkspaceSchema,
        roles::{self, RuntimeRole},
    },
};

fn request(pool: &str) -> Result<AllocationRequest> {
    let v = VolumeBudget {
        capacity_bytes: 32 * 1024 * 1024,
        maximum_inodes: 128,
    };
    let policy = WorkspacePolicy {
        schema_version: "warpin.workspace-policy/v1".into(),
        backend: "fixed-ext4-image/v1".into(),
        inputs: v.clone(),
        scratch: v.clone(),
        outputs: v,
    };
    let mut r = AllocationRequest {
        allocation_id: Uuid::new_v4(),
        pool_id: pool.into(),
        identity: AllocationIdentity {
            tenant_id: "test-tenant".into(),
            scope_id: "test-scope".into(),
            job_id: Uuid::new_v4().to_string(),
            attempt_id: "test-attempt".into(),
            fence: "1".into(),
            release_ref: "test-release".into(),
            release_digest: format!("sha256:{}", "b".repeat(64)),
        },
        policy_digest: policy.digest()?.to_string(),
        policy,
        deadline: Utc::now() + Duration::minutes(5),
    };
    r.allocation_id = r.expected_allocation_id()?;
    Ok(r)
}

async fn role_connection(url: &str, role: &str) -> Result<Arc<DatabaseConnection>> {
    let mut options = ConnectOptions::new(url.to_owned());
    options
        .max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);
    let db = Arc::new(Database::connect(options).await?);
    // Test-owned, generated canonical role. One connection keeps SET ROLE fixed.
    db.execute_unprepared(&format!("SET ROLE \"{role}\"; SET search_path TO public"))
        .await?;
    Ok(db)
}

async fn qualification(
    admin: &DatabaseConnection,
    operator: Arc<DatabaseConnection>,
    runtime: Arc<DatabaseConnection>,
    impersonated: Arc<DatabaseConnection>,
    schema: WorkspaceSchema,
    runtime_name: &str,
) -> Result<()> {
    let owner = PostgresAllocationLedger::new(operator.clone(), schema.clone());
    let role = RuntimeRole::parse(runtime_name)?;
    owner
        .install_schema()
        .await
        .context("initial operator migration")?;
    owner
        .install_schema()
        .await
        .context("exact operator migration replay")?;
    let r = request("fixed-pool")?;
    owner
        .configure_pool(
            "fixed-pool",
            r.policy.total_bytes()?,
            r.policy.total_inodes()?,
        )
        .await?;
    roles::grant(&operator, &schema, &role)
        .await
        .context("operator runtime grants")?;
    ensure!(
        roles::verify(admin, &schema, &role).await.is_err(),
        "admin session impersonated approved runtime role"
    );
    ensure!(
        roles::verify(&impersonated, &schema, &role).await.is_err(),
        "admin SET ROLE impersonated real runtime login"
    );
    roles::verify(&runtime, &schema, &role)
        .await
        .context("runtime grant verification")?;
    let worker = PostgresAllocationLedger::new(runtime.clone(), schema.clone());
    worker
        .verify_schema()
        .await
        .context("runtime initial schema verification")?;
    ensure!(
        worker.install_schema().await.is_err(),
        "runtime installed operator migration"
    );
    ensure!(
        worker.configure_pool("forbidden-pool", 1, 1).await.is_err(),
        "runtime configured pool"
    );
    let allocation = worker.reserve(r.clone()).await.context("runtime reserve")?;
    worker
        .retain(&allocation.token()?)
        .await
        .context("runtime retain")?;
    // A temporary shadow and altered connection search_path cannot move access
    // away from the explicit owning schema or free the actual retained budget.
    runtime.execute_unprepared("CREATE TEMP TABLE warpin_workspace_pools_v1 (pool_id text, reserved_bytes bigint); INSERT INTO warpin_workspace_pools_v1 VALUES('fixed-pool',0); SET search_path TO pg_temp,public").await?;
    ensure!(
        worker
            .read(&allocation.token()?)
            .await
            .context("runtime temporary-shadow read")?
            .state
            == warpin_workspace::AllocationState::Retained,
        "temporary shadow redirected ledger"
    );
    ensure!(
        worker.reserve(request("fixed-pool")?).await.is_err(),
        "temporary shadow bypassed capacity"
    );
    let namespace = format!("\"{}\"", schema.as_str());
    // Every allowed privilege class is nondelegable. WITH GRANT OPTION is an
    // additional authority even when its base permission is already approved.
    let options = [
        (format!("USAGE ON SCHEMA {namespace}"), "schema USAGE"),
        (
            format!("SELECT ON TABLE {namespace}.warpin_workspace_pools_v1"),
            "pool table SELECT",
        ),
        (
            format!("SELECT ON TABLE {namespace}.warpin_workspace_allocations_v1"),
            "allocation table SELECT",
        ),
        (
            format!("SELECT ON TABLE {namespace}.warpin_workspace_pool_authorities_v1"),
            "authority table SELECT",
        ),
        (
            format!("SELECT ON TABLE {namespace}.warpin_workspace_schema_versions_v1"),
            "migration table SELECT",
        ),
        (
            format!("SELECT(pool_id) ON TABLE {namespace}.warpin_workspace_pools_v1"),
            "pool column SELECT",
        ),
        (
            format!("SELECT(record_json) ON TABLE {namespace}.warpin_workspace_allocations_v1"),
            "allocation column SELECT",
        ),
        (
            format!(
                "SELECT(authority_json) ON TABLE {namespace}.warpin_workspace_pool_authorities_v1"
            ),
            "authority column SELECT",
        ),
        (
            format!(
                "SELECT(migration_checksum) ON TABLE {namespace}.warpin_workspace_schema_versions_v1"
            ),
            "migration column SELECT",
        ),
        (
            format!(
                "UPDATE(reserved_bytes,reserved_inodes) ON TABLE {namespace}.warpin_workspace_pools_v1"
            ),
            "pool counter UPDATE",
        ),
        (
            format!(
                "UPDATE(state,record_json,record_digest) ON TABLE {namespace}.warpin_workspace_allocations_v1"
            ),
            "allocation state UPDATE",
        ),
        (
            format!(
                "INSERT(allocation_id,pool_id,reserved_bytes,reserved_inodes,state,record_json,record_digest) ON TABLE {namespace}.warpin_workspace_allocations_v1"
            ),
            "allocation INSERT",
        ),
        (
            format!(
                "INSERT(pool_id,authority_json,authority_digest) ON TABLE {namespace}.warpin_workspace_pool_authorities_v1"
            ),
            "first authority INSERT",
        ),
    ];
    for (privileges, case) in options {
        operator
            .execute_unprepared(&format!(
                "GRANT {privileges} TO \"{runtime_name}\" WITH GRANT OPTION"
            ))
            .await?;
        let rejected = roles::verify(&runtime, &schema, &role).await.is_err();
        operator
            .execute_unprepared(&format!(
                "REVOKE GRANT OPTION FOR {privileges} FROM \"{runtime_name}\""
            ))
            .await?;
        ensure!(rejected, "allowed privilege delegated: {case}");
        roles::verify(&runtime, &schema, &role)
            .await
            .context(case)?;
    }
    // SQL GRANT may return a warning rather than an error. Verify its actual
    // effect on the recipient instead of accepting command completion as proof.
    let delegate = format!("workspace_delegate_{}", Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE ROLE \"{delegate}\" NOLOGIN NOINHERIT"))
        .await?;
    let attempted = runtime.execute_unprepared(&format!("GRANT SELECT ON {namespace}.warpin_workspace_pools_v1 TO \"{delegate}\"; GRANT UPDATE(state) ON {namespace}.warpin_workspace_allocations_v1 TO \"{delegate}\"; GRANT USAGE ON SCHEMA {namespace} TO \"{delegate}\"")).await;
    let row = admin.query_one_raw(warpin_storage::postgres_statement(
        "SELECT has_table_privilege($1,$2,'SELECT') OR has_column_privilege($1,$3,'state','UPDATE') OR has_schema_privilege($1,$4,'USAGE') AS delegated",
        [delegate.clone().into(),format!("{namespace}.warpin_workspace_pools_v1").into(),format!("{namespace}.warpin_workspace_allocations_v1").into(),schema.as_str().to_owned().into()],
    )).await?.context("fixture delegation readback absent")?;
    let delegated = row.try_get::<bool>("", "delegated")?;
    // Remove only this owned fixture role's ACL if an assertion would fail.
    admin.execute_unprepared(&format!("REVOKE ALL ON {namespace}.warpin_workspace_pools_v1,{namespace}.warpin_workspace_allocations_v1 FROM \"{delegate}\"; REVOKE ALL(state) ON {namespace}.warpin_workspace_allocations_v1 FROM \"{delegate}\"; REVOKE ALL ON SCHEMA {namespace} FROM \"{delegate}\"; DROP ROLE \"{delegate}\"")).await?;
    let _ = attempted;
    ensure!(
        !delegated,
        "restricted actual LOGIN delegated approved privileges"
    );
    operator
        .execute_unprepared(&format!("GRANT USAGE ON SCHEMA {namespace} TO PUBLIC"))
        .await?;
    let public_rejected = roles::verify(&runtime, &schema, &role).await.is_err();
    operator
        .execute_unprepared(&format!("REVOKE USAGE ON SCHEMA {namespace} FROM PUBLIC"))
        .await?;
    ensure!(public_rejected, "PUBLIC schema privilege accepted");
    for sql in [
        format!("CREATE TABLE {namespace}.forbidden(x int)"),
        format!("UPDATE {namespace}.warpin_workspace_pools_v1 SET maximum_bytes=1"),
        format!("UPDATE {namespace}.warpin_workspace_allocations_v1 SET reserved_bytes=1"),
        format!(
            "UPDATE {namespace}.warpin_workspace_schema_versions_v1 SET migration_checksum='sha256:{}'",
            "c".repeat(64)
        ),
        format!("DELETE FROM {namespace}.warpin_workspace_allocations_v1"),
        format!("DROP TABLE {namespace}.warpin_workspace_schema_versions_v1"),
    ] {
        ensure!(
            runtime.execute_unprepared(&sql).await.is_err(),
            "runtime unexpected write permitted"
        );
    }
    // Extra column grants, PUBLIC grants and inherited memberships reject.
    operator.execute_unprepared(&format!("GRANT UPDATE(maximum_bytes) ON {namespace}.warpin_workspace_pools_v1 TO \"{runtime_name}\"")).await?;
    ensure!(
        roles::verify(&runtime, &schema, &role).await.is_err(),
        "extra column grant accepted"
    );
    operator.execute_unprepared(&format!("REVOKE UPDATE(maximum_bytes) ON {namespace}.warpin_workspace_pools_v1 FROM \"{runtime_name}\"; GRANT SELECT(migration_checksum) ON {namespace}.warpin_workspace_schema_versions_v1 TO PUBLIC")).await?;
    ensure!(
        roles::verify(&runtime, &schema, &role).await.is_err(),
        "PUBLIC column grant accepted"
    );
    operator.execute_unprepared(&format!("REVOKE SELECT(migration_checksum) ON {namespace}.warpin_workspace_schema_versions_v1 FROM PUBLIC")).await?;
    admin
        .execute_unprepared(&format!("ALTER ROLE \"{runtime_name}\" INHERIT"))
        .await?;
    ensure!(
        roles::verify(&runtime, &schema, &role).await.is_err(),
        "inherited role attributes accepted"
    );
    admin
        .execute_unprepared(&format!("ALTER ROLE \"{runtime_name}\" NOINHERIT"))
        .await?;
    let group = format!("workspace_group_{}", Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!(
            "CREATE ROLE \"{group}\" NOLOGIN; GRANT \"{group}\" TO \"{runtime_name}\""
        ))
        .await?;
    operator
        .execute_unprepared(&format!(
            "GRANT SELECT ON {namespace}.warpin_workspace_pools_v1 TO \"{group}\" WITH GRANT OPTION"
        ))
        .await?;
    let rejected = roles::verify(&runtime, &schema, &role).await.is_err();
    operator
        .execute_unprepared(&format!(
            "REVOKE ALL ON {namespace}.warpin_workspace_pools_v1 FROM \"{group}\""
        ))
        .await?;
    admin
        .execute_unprepared(&format!(
            "REVOKE \"{group}\" FROM \"{runtime_name}\"; DROP ROLE \"{group}\""
        ))
        .await?;
    ensure!(rejected, "runtime membership accepted even with NOINHERIT");
    // Metadata checksum and catalog drift cannot silently migrate or alter data.
    operator.execute_unprepared(&format!("UPDATE {namespace}.warpin_workspace_schema_versions_v1 SET migration_checksum='sha256:{}'", "c".repeat(64))).await?;
    ensure!(
        worker.verify_schema().await.is_err() && owner.install_schema().await.is_err(),
        "changed migration checksum accepted"
    );
    operator
        .execute_unprepared(&format!(
            "UPDATE {namespace}.warpin_workspace_schema_versions_v1 SET migration_checksum='{}'",
            warpin_workspace::schema::migration_checksum()
        ))
        .await?;
    operator.execute_unprepared(&format!("ALTER TABLE {namespace}.warpin_workspace_pools_v1 DROP CONSTRAINT warpin_workspace_pools_v1_maximum_bytes_check")).await?;
    ensure!(
        worker.read(&allocation.token()?).await.is_err() && owner.install_schema().await.is_err(),
        "constraint drift silently accepted/repaired"
    );
    operator.execute_unprepared(&format!("ALTER TABLE {namespace}.warpin_workspace_pools_v1 ADD CONSTRAINT warpin_workspace_pools_v1_maximum_bytes_check CHECK(maximum_bytes>0)")).await?;
    operator
        .execute_unprepared(&format!(
            "CREATE TABLE {namespace}.child_pool() INHERITS({namespace}.warpin_workspace_pools_v1)"
        ))
        .await?;
    ensure!(
        worker.verify_schema().await.is_err(),
        "inherited table accepted"
    );
    operator.execute_unprepared(&format!("DROP TABLE {namespace}.child_pool; CREATE FUNCTION {namespace}.unexpected() RETURNS int LANGUAGE SQL SECURITY DEFINER AS 'SELECT 1'")).await?;
    ensure!(
        worker.verify_schema().await.is_err(),
        "unexpected function accepted"
    );
    operator
        .execute_unprepared(&format!("DROP FUNCTION {namespace}.unexpected()"))
        .await?;
    roles::verify(&runtime, &schema, &role).await?;
    worker.verify_schema().await?;
    ensure!(
        worker.read(&allocation.token()?).await?.state
            == warpin_workspace::AllocationState::Retained,
        "schema validation lost retained allocation"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires explicitly owned PostgreSQL fixture and fixture role-creation authority"]
async fn migration_role_catalog_checksum_and_shadowing_fail_closed() {
    let url = std::env::var("WARPIN_WORKSPACE_TEST_DATABASE_URL").unwrap();
    let mut admin_options = ConnectOptions::new(url.clone());
    admin_options.sqlx_logging(false);
    let admin = Database::connect(admin_options).await.unwrap();
    let id = Uuid::new_v4().simple().to_string();
    let schema_name = format!("workspace_schema_{id}");
    let operator_name = format!("workspace_operator_{id}");
    let runtime_name = format!("workspace_runtime_{id}");
    // CSPRNG-backed UUID v4: 244 random bits, hex only. Credentials exist only
    // in this server-side test process and PostgreSQL's hashed role credential.
    let password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    assert!(admin.execute_unprepared(&format!("CREATE ROLE \"{operator_name}\" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS; CREATE ROLE \"{runtime_name}\" LOGIN PASSWORD '{password}' NOINHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS; CREATE SCHEMA \"{schema_name}\" AUTHORIZATION \"{operator_name}\"")).await.is_ok(), "owned role fixture setup failed");
    let operator = role_connection(&url, &operator_name).await.unwrap();
    let impersonated = role_connection(&url, &runtime_name).await.unwrap();
    let mut runtime_url = url::Url::parse(&url).unwrap();
    assert!(runtime_url.set_username(&runtime_name).is_ok());
    assert!(runtime_url.set_password(Some(&password)).is_ok());
    let mut runtime_options = ConnectOptions::new(runtime_url.as_str().to_owned());
    runtime_options
        .max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);
    let runtime = Arc::new(Database::connect(runtime_options).await.unwrap());
    let result = qualification(
        &admin,
        operator.clone(),
        runtime.clone(),
        impersonated.clone(),
        WorkspaceSchema::parse(&schema_name).unwrap(),
        &runtime_name,
    )
    .await;
    operator.execute_unprepared("RESET ROLE").await.unwrap();
    runtime
        .execute_unprepared("DROP TABLE IF EXISTS pg_temp.warpin_workspace_pools_v1; RESET ROLE")
        .await
        .unwrap();
    drop(operator);
    drop(runtime);
    impersonated.execute_unprepared("RESET ROLE").await.unwrap();
    drop(impersonated);
    admin.execute_unprepared(&format!("DROP SCHEMA \"{schema_name}\" CASCADE; DROP ROLE \"{runtime_name}\"; DROP ROLE \"{operator_name}\"")).await.unwrap();
    result.unwrap();
}
