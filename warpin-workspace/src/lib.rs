//! Reusable workspace resource boundaries. Applications retain authentication,
//! immutable release admission, job authority and transport authorization.
//!
//! A reservation is not a filesystem, and a filesystem is not proof that its
//! execution namespace has died. Both receipts are required before release.
pub mod ledger;
#[cfg(target_os = "linux")]
pub mod linux;
mod policy;
mod pool;
pub mod schema;
mod state;

pub use policy::{AllocationIdentity, AllocationRequest, VolumeBudget, WorkspacePolicy};
pub use pool::{PoolAuthority, VerifiedPoolAuthority};
pub use state::{
    AllocationRecord, AllocationState, ExecutionBinding, FilesystemReceipt, ProvisioningReceipt,
    ReservationToken, VerifiedExecutionBinding, VerifiedFilesystemTeardown, VerifiedInputSeal,
    VerifiedNamespaceDeath, VerifiedProvisioningReceipt,
};
