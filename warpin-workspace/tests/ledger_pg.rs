use chrono::{Duration, Utc};
use sea_orm::{ConnectOptions, ConnectionTrait, Database};
use std::sync::Arc;
use uuid::Uuid;
use warpin_workspace::{
    AllocationIdentity, AllocationRequest, AllocationState, VolumeBudget, WorkspacePolicy,
    ledger::PostgresAllocationLedger,
};

fn request(pool: &str) -> AllocationRequest {
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
    let mut request = AllocationRequest {
        allocation_id: Uuid::new_v4(),
        pool_id: pool.into(),
        identity: AllocationIdentity {
            tenant_id: "tenant-a".into(),
            scope_id: "scope-a".into(),
            job_id: Uuid::new_v4().to_string(),
            attempt_id: "attempt-a".into(),
            fence: "7".into(),
            release_ref: "neutral-release".into(),
            release_digest: format!("sha256:{}", "c".repeat(64)),
        },
        policy_digest: policy.digest().unwrap().to_string(),
        policy,
        deadline: Utc::now() + Duration::minutes(5),
    };
    request.allocation_id = request.expected_allocation_id().unwrap();
    request
}
#[tokio::test]
#[ignore = "Requires explicitly owned PostgreSQL development fixture"]
async fn real_pg_atomic_capacity_exact_replay_foreign_fence_and_retained_reservation() {
    let url = std::env::var("WARPIN_WORKSPACE_TEST_DATABASE_URL")
        .expect("development database URL required");
    let admin = Database::connect(url.clone()).await.unwrap();
    let schema = format!("workspace_{}", Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options
        .max_connections(8)
        .set_schema_search_path(schema.clone());
    let db = Arc::new(Database::connect(options).await.unwrap());
    let ledger = PostgresAllocationLedger::new(
        db.clone(),
        warpin_workspace::schema::WorkspaceSchema::parse(&schema).unwrap(),
    );
    ledger.install_schema().await.unwrap();
    let pool = format!("pool-{}", Uuid::new_v4());
    let r = request(&pool);
    ledger
        .configure_pool(
            &pool,
            r.policy.total_bytes().unwrap(),
            r.policy.total_inodes().unwrap(),
        )
        .await
        .unwrap();
    ledger
        .configure_pool(
            &pool,
            r.policy.total_bytes().unwrap(),
            r.policy.total_inodes().unwrap(),
        )
        .await
        .unwrap();
    assert!(
        ledger
            .configure_pool(
                &pool,
                r.policy.total_bytes().unwrap() + 4096,
                r.policy.total_inodes().unwrap()
            )
            .await
            .is_err()
    );
    let first = ledger.reserve(r.clone()).await.unwrap();
    assert_eq!(first.state, AllocationState::Reserved);
    assert_eq!(ledger.reserve(r.clone()).await.unwrap(), first);
    let mut foreign = r.clone();
    foreign.identity.fence = "8".into();
    assert!(ledger.reserve(foreign).await.is_err());
    let mut foreign = first.token().unwrap();
    foreign.identity_digest = format!("sha256:{}", "a".repeat(64));
    assert!(ledger.read(&foreign).await.is_err());
    // SQL projection drift must be rejected even if canonical JSON/digest is
    // untouched. This own fixture restores the exact original row afterwards.
    db.execute_unprepared(&format!(
        "UPDATE warpin_workspace_allocations_v1 SET reserved_bytes=reserved_bytes+4096 WHERE allocation_id='{}'", first.request.allocation_id
    )).await.unwrap();
    assert!(ledger.read(&first.token().unwrap()).await.is_err());
    db.execute_unprepared(&format!(
        "UPDATE warpin_workspace_allocations_v1 SET reserved_bytes=reserved_bytes-4096 WHERE allocation_id='{}'", first.request.allocation_id
    )).await.unwrap();
    db.execute_unprepared(&format!(
        "UPDATE warpin_workspace_pools_v1 SET reserved_bytes=reserved_bytes-4096 WHERE pool_id='{pool}'"
    )).await.unwrap();
    assert!(ledger.reserve(request(&pool)).await.is_err());
    db.execute_unprepared(&format!(
        "UPDATE warpin_workspace_pools_v1 SET reserved_bytes=reserved_bytes+4096 WHERE pool_id='{pool}'"
    )).await.unwrap();
    assert_eq!(ledger.read(&first.token().unwrap()).await.unwrap(), first);
    let mut changed_policy = r.clone();
    changed_policy.policy.scratch.capacity_bytes += 4096;
    changed_policy.policy_digest = changed_policy.policy.digest().unwrap().to_string();
    assert!(ledger.reserve(changed_policy).await.is_err());
    let mut expired = request(&pool);
    expired.deadline = Utc::now() - Duration::seconds(1);
    assert!(ledger.reserve(expired).await.is_err());
    let retained = ledger.retain(&first.token().unwrap()).await.unwrap();
    assert_eq!(retained.state, AllocationState::Retained);
    assert!(ledger.reserve(request(&pool)).await.is_err());
    assert_eq!(
        ledger.read(&first.token().unwrap()).await.unwrap().state,
        AllocationState::Retained
    );
    let concurrent = format!("concurrent-{}", Uuid::new_v4());
    ledger
        .configure_pool(
            &concurrent,
            r.policy.total_bytes().unwrap(),
            r.policy.total_inodes().unwrap(),
        )
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let ledger = ledger.clone();
        let barrier = barrier.clone();
        let request = request(&concurrent);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            ledger.reserve(request).await
        }));
    }
    let mut successes = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
