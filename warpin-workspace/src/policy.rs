use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpin_integrity::{CanonicalProfile, Sha256Digest, digest_typed_with_profile};

/// Hard volume capacity, including filesystem metadata; useful data capacity is
/// strictly smaller. Publishers must account for measured metadata overhead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VolumeBudget {
    pub capacity_bytes: u64,
    pub maximum_inodes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspacePolicy {
    pub schema_version: String,
    pub backend: String,
    pub inputs: VolumeBudget,
    pub scratch: VolumeBudget,
    pub outputs: VolumeBudget,
}

impl WorkspacePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == "warpin.workspace-policy/v1"
                && self.backend == "fixed-ext4-image/v1",
            "unsupported workspace policy"
        );
        for volume in [&self.inputs, &self.scratch, &self.outputs] {
            ensure!(
                volume.capacity_bytes >= 32 * 1024 * 1024
                    && volume.capacity_bytes % 4096 == 0
                    && volume.capacity_bytes < (1_u64 << 53)
                    && volume.maximum_inodes >= 128
                    && volume.maximum_inodes <= volume.capacity_bytes / 4096,
                "invalid fixed-filesystem budget"
            );
        }
        for volume in [&self.inputs, &self.scratch, &self.outputs] {
            let alignment = (volume.capacity_bytes / 4096).div_ceil(32768) * 16;
            ensure!(
                volume.maximum_inodes / alignment * alignment >= 128,
                "workspace inode budget cannot represent fixed ext4 geometry"
            );
        }
        self.total_bytes()?;
        self.total_inodes()?;
        Ok(())
    }

    pub fn total_bytes(&self) -> Result<u64> {
        self.inputs
            .capacity_bytes
            .checked_add(self.scratch.capacity_bytes)
            .and_then(|n| n.checked_add(self.outputs.capacity_bytes))
            .ok_or_else(|| anyhow::anyhow!("workspace byte overflow"))
    }

    pub fn total_inodes(&self) -> Result<u64> {
        self.inputs
            .maximum_inodes
            .checked_add(self.scratch.maximum_inodes)
            .and_then(|n| n.checked_add(self.outputs.maximum_inodes))
            .ok_or_else(|| anyhow::anyhow!("workspace inode overflow"))
    }

    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(digest_typed_with_profile(
            self,
            CanonicalProfile::IJsonSafeIntegers,
        )?)
    }
}

/// IDs are labels, never paths. The application authenticates this exact scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationIdentity {
    pub tenant_id: String,
    pub scope_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub fence: String,
    pub release_ref: String,
    pub release_digest: String,
}

impl AllocationIdentity {
    pub fn validate(&self) -> Result<()> {
        for label in [
            &self.tenant_id,
            &self.scope_id,
            &self.job_id,
            &self.attempt_id,
            &self.release_ref,
        ] {
            ensure!(
                !label.is_empty() && label.len() <= 256 && !label.chars().any(char::is_control),
                "invalid allocation identity label"
            );
        }
        let fence: u64 = self.fence.parse()?;
        ensure!(
            fence > 0 && fence.to_string() == self.fence,
            "invalid allocation fence"
        );
        let _: Sha256Digest = self.release_digest.parse()?;
        Ok(())
    }

    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Ok(digest_typed_with_profile(
            self,
            CanonicalProfile::IJsonSafeIntegers,
        )?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationRequest {
    pub allocation_id: Uuid,
    pub pool_id: String,
    pub identity: AllocationIdentity,
    pub policy: WorkspacePolicy,
    pub policy_digest: String,
    pub deadline: DateTime<Utc>,
}

impl AllocationRequest {
    /// One workspace per exact pool/job-attempt/fence/release identity. Lost
    /// responses cannot create another allocation by selecting a new UUID.
    pub fn expected_allocation_id(&self) -> Result<Uuid> {
        let digest = self.identity.digest()?;
        Ok(Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("warpin.workspace-allocation/v1/{}/{}", self.pool_id, digest).as_bytes(),
        ))
    }
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        self.identity.validate()?;
        ensure!(
            !self.allocation_id.is_nil()
                && !self.pool_id.is_empty()
                && self.pool_id.len() <= 128
                && self
                    .pool_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "invalid allocation/pool identity"
        );
        ensure!(
            self.allocation_id == self.expected_allocation_id()?,
            "workspace allocation ID differs from immutable identity"
        );
        ensure!(self.deadline > now, "workspace admission deadline expired");
        ensure!(
            self.policy.digest()?.as_str() == self.policy_digest,
            "workspace policy digest mismatch"
        );
        ensure!(
            self.policy.total_bytes()? <= i64::MAX as u64
                && self.policy.total_inodes()? <= i64::MAX as u64,
            "workspace reservation exceeds database range"
        );
        Ok(())
    }
}
