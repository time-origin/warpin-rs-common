use chrono::{Duration, Utc};
use uuid::Uuid;
use warpin_workspace::{
    AllocationIdentity, AllocationRecord, AllocationRequest, AllocationState, VolumeBudget,
    WorkspacePolicy,
};

fn request() -> AllocationRequest {
    let volume = VolumeBudget {
        capacity_bytes: 32 * 1024 * 1024,
        maximum_inodes: 128,
    };
    let policy = WorkspacePolicy {
        schema_version: "warpin.workspace-policy/v1".into(),
        backend: "fixed-ext4-image/v1".into(),
        inputs: volume.clone(),
        scratch: volume.clone(),
        outputs: volume,
    };
    let mut request = AllocationRequest {
        allocation_id: Uuid::new_v4(),
        pool_id: "neutral-test-pool".into(),
        identity: AllocationIdentity {
            tenant_id: "tenant-a".into(),
            scope_id: "scope-a".into(),
            job_id: "job-a".into(),
            attempt_id: "attempt-a".into(),
            fence: "1".into(),
            release_ref: "release-a".into(),
            release_digest: format!("sha256:{}", "a".repeat(64)),
        },
        policy_digest: policy.digest().unwrap().to_string(),
        policy,
        deadline: Utc::now() + Duration::minutes(5),
    };
    request.allocation_id = request.expected_allocation_id().unwrap();
    request
}
#[test]
fn validates_complete_exact_resource_identity_and_policy_digest() {
    let r = request();
    r.validate(Utc::now()).unwrap();
    assert_eq!(r.policy.total_bytes().unwrap(), 96 * 1024 * 1024);
    assert_eq!(r.policy.total_inodes().unwrap(), 384);
    let value = serde_json::to_value(&r).unwrap();
    assert_eq!(
        serde_json::from_value::<AllocationRequest>(value).unwrap(),
        r
    );
}
#[test]
fn rejects_missing_or_foreign_fence_scope_policy_and_deadline() {
    let r = request();
    for fence in ["0", "01", "-1", "18446744073709551616", "1.0"] {
        let mut bad = r.clone();
        bad.identity.fence = fence.into();
        assert!(bad.validate(Utc::now()).is_err());
    }
    let mut different_id = r.clone();
    different_id.allocation_id = Uuid::new_v4();
    assert!(different_id.validate(Utc::now()).is_err());
    let mut bad = r.clone();
    bad.policy.scratch.capacity_bytes += 4096;
    assert!(bad.validate(Utc::now()).is_err());
    let mut bad = r.clone();
    bad.deadline = Utc::now() - Duration::seconds(1);
    assert!(bad.validate(Utc::now()).is_err());
    let record = AllocationRecord {
        request: r,
        state: AllocationState::Reserved,
        provisioning: None,
        inputs_sealed: false,
        execution: None,
    };
    let mut token = record.token().unwrap();
    token.identity_digest = format!("sha256:{}", "b".repeat(64));
    assert!(record.verify_token(&token).is_err());
}
#[test]
fn rejects_unknown_fields_unbounded_or_unrepresentable_volumes() {
    let r = request();
    let mut value = serde_json::to_value(&r).unwrap();
    value["path"] = serde_json::json!("/foreign");
    assert!(serde_json::from_value::<AllocationRequest>(value).is_err());
    for budget in [
        VolumeBudget {
            capacity_bytes: 0,
            maximum_inodes: 128,
        },
        VolumeBudget {
            capacity_bytes: 32 * 1024 * 1024 + 1,
            maximum_inodes: 128,
        },
        VolumeBudget {
            capacity_bytes: 32 * 1024 * 1024,
            maximum_inodes: 0,
        },
        VolumeBudget {
            capacity_bytes: 32 * 1024 * 1024,
            maximum_inodes: 32768,
        },
    ] {
        let mut bad = r.policy.clone();
        bad.scratch = budget;
        assert!(bad.validate().is_err());
    }
    let mut huge = r.policy.clone();
    huge.inputs.capacity_bytes = u64::MAX;
    huge.scratch.capacity_bytes = u64::MAX;
    assert!(huge.total_bytes().is_err());
    assert!(huge.digest().is_err());
}
#[test]
fn record_digest_binds_namespace_state_and_policy() {
    let r = request();
    let mut record = AllocationRecord {
        request: r,
        state: AllocationState::Reserved,
        provisioning: None,
        inputs_sealed: false,
        execution: None,
    };
    let first = record.record_digest().unwrap();
    record.state = AllocationState::Retained;
    assert_ne!(record.record_digest().unwrap(), first);
}

#[test]
fn rejects_impossible_inode_geometry_before_any_node_io() {
    let r = request();
    let mut policy = r.policy;
    policy.scratch.capacity_bytes = 2 * 1024 * 1024 * 1024;
    policy.scratch.maximum_inodes = 128;
    assert!(policy.validate().is_err());
    policy.scratch.maximum_inodes = 4096;
    policy.validate().unwrap();
}
