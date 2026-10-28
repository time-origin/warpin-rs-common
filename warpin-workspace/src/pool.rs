//! Current-boot physical pool identity. This does not attest host continuity
//! across reboot; a changed boot/root requires separate trusted reconciliation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpin_integrity::{CanonicalProfile, digest_typed_with_profile};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PoolAuthority {
    pub schema_version: String,
    pub backend: String,
    pub pool_id: String,
    pub kernel_boot_id: Uuid,
    pub canonical_root: String,
    pub root_device_major: u32,
    pub root_device_minor: u32,
    pub root_inode: String,
    pub run_uid: u32,
    pub run_gid: u32,
}
impl PoolAuthority {
    pub fn validate(&self) -> Result<()> {
        let inode: u64 = self.root_inode.parse()?;
        ensure!(
            self.schema_version == "warpin.workspace-pool-authority/v1"
                && self.backend == "fixed-ext4-image/v1"
                && !self.pool_id.is_empty()
                && self.pool_id.len() <= 128
                && self
                    .pool_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                && !self.kernel_boot_id.is_nil()
                && std::path::Path::new(&self.canonical_root).is_absolute()
                && inode > 0
                && inode.to_string() == self.root_inode
                && self.run_uid > 0
                && self.run_gid > 0,
            "invalid physical pool authority"
        );
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest_typed_with_profile(self, CanonicalProfile::IJsonSafeIntegers)?.to_string())
    }
}
/// Minted only by Linux readback, not caller-supplied RPC metadata.
#[derive(Clone, Debug)]
pub struct VerifiedPoolAuthority {
    pub(crate) authority: PoolAuthority,
}
impl VerifiedPoolAuthority {
    pub fn authority(&self) -> &PoolAuthority {
        &self.authority
    }
}
