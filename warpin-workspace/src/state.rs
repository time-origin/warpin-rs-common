use crate::{AllocationIdentity, AllocationRequest, PoolAuthority};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpin_integrity::{CanonicalProfile, digest_typed_with_profile};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllocationState {
    Reserved,
    Provisioned,
    Launching,
    Active,
    Retained,
    Quiescent,
    Released,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationToken {
    pub allocation_id: Uuid,
    pub pool_id: String,
    pub identity_digest: String,
    pub policy_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemReceipt {
    pub filesystem_uuid: Uuid,
    pub filesystem_bytes: u64,
    pub filesystem_inodes: u64,
    pub backing_device_major: u32,
    pub backing_device_minor: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvisioningReceipt {
    pub allocation_id: Uuid,
    pub identity_digest: String,
    pub policy_digest: String,
    pub inputs: FilesystemReceipt,
    pub scratch: FilesystemReceipt,
    pub outputs: FilesystemReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionBinding {
    pub boot_id: Uuid,
    pub init_pid: u32,
    pub start_ticks: String,
    pub pid_namespace_inode: String,
    pub observer_pid_namespace_inode: String,
}

/// Cannot be deserialized or constructed by an RPC caller. Linux observation
/// creates this only for the exact previously captured namespace init identity.
#[derive(Clone, Debug)]
pub struct VerifiedNamespaceDeath {
    pub(crate) pool_authority: Option<PoolAuthority>,
    pub(crate) binding: ExecutionBinding,
    pub(crate) observed_boot_id: Uuid,
}

impl VerifiedNamespaceDeath {
    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }
    pub fn observed_boot_id(&self) -> Uuid {
        self.observed_boot_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationRecord {
    pub request: AllocationRequest,
    pub state: AllocationState,
    pub provisioning: Option<ProvisioningReceipt>,
    pub inputs_sealed: bool,
    pub execution: Option<ExecutionBinding>,
}

impl AllocationRecord {
    pub fn token(&self) -> Result<ReservationToken> {
        Ok(ReservationToken {
            allocation_id: self.request.allocation_id,
            pool_id: self.request.pool_id.clone(),
            identity_digest: self.request.identity.digest()?.to_string(),
            policy_digest: self.request.policy_digest.clone(),
        })
    }
    pub fn verify_token(&self, token: &ReservationToken) -> Result<()> {
        ensure!(
            self.token()? == *token,
            "workspace reservation scope/fence mismatch"
        );
        Ok(())
    }
    pub fn record_digest(&self) -> Result<String> {
        Ok(digest_typed_with_profile(self, CanonicalProfile::IJsonSafeIntegers)?.to_string())
    }
    pub fn identity(&self) -> &AllocationIdentity {
        &self.request.identity
    }
}

/// Created only by a real Linux observer; not a caller-supplied PID assertion.
#[derive(Clone, Debug)]
pub struct VerifiedExecutionBinding {
    pub(crate) pool_authority: Option<PoolAuthority>,
    pub(crate) binding: ExecutionBinding,
}
impl VerifiedExecutionBinding {
    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }
}

/// Created only after exact owned filesystem teardown readback.
#[derive(Clone, Debug)]
pub struct VerifiedFilesystemTeardown {
    pub(crate) pool_authority: PoolAuthority,
    pub(crate) token: ReservationToken,
}
impl VerifiedFilesystemTeardown {
    pub fn token(&self) -> &ReservationToken {
        &self.token
    }
}

impl ProvisioningReceipt {
    pub fn validate(&self, record: &AllocationRecord) -> Result<()> {
        let token = record.token()?;
        ensure!(
            self.allocation_id == token.allocation_id
                && self.identity_digest == token.identity_digest
                && self.policy_digest == token.policy_digest,
            "workspace filesystem scope mismatch"
        );
        let volumes = [
            (&self.inputs, &record.request.policy.inputs),
            (&self.scratch, &record.request.policy.scratch),
            (&self.outputs, &record.request.policy.outputs),
        ];
        let mut uuids = std::collections::BTreeSet::new();
        for (receipt, budget) in volumes {
            ensure!(
                !receipt.filesystem_uuid.is_nil()
                    && uuids.insert(receipt.filesystem_uuid)
                    && receipt.filesystem_bytes == budget.capacity_bytes
                    && receipt.filesystem_inodes > 0
                    && receipt.filesystem_inodes <= budget.maximum_inodes,
                "workspace hard filesystem capacity differs"
            );
        }
        Ok(())
    }
}

/// Created only by the hard backend after exact filesystem/mount readback.
#[derive(Clone, Debug)]
pub struct VerifiedProvisioningReceipt {
    pub(crate) pool_authority: PoolAuthority,
    pub(crate) receipt: ProvisioningReceipt,
}
impl VerifiedProvisioningReceipt {
    pub fn receipt(&self) -> &ProvisioningReceipt {
        &self.receipt
    }
}

/// Created only after the exact inputs filesystem is actually read-only.
#[derive(Clone, Debug)]
pub struct VerifiedInputSeal {
    pub(crate) pool_authority: PoolAuthority,
    pub(crate) token: ReservationToken,
    pub(crate) filesystem_uuid: Uuid,
}
