mod contract;
pub mod s3_adapter;
mod storage;

pub use contract::{
    ArtifactEncryptionContextId, ArtifactEncryptionPolicy, EncryptionAttestation,
    EncryptionAttestationView, EncryptionPolicyError, EncryptionRequirement,
    EncryptionRequirementView, EncryptionVerifiedObjectWriteReceipt, ImmutableObjectWrite,
    ManagedEncryptionProfileId, ObjectDeleteOutcome, ObjectDeleteReceipt, ObjectKey,
    ObjectStorageError, ObjectWriteReceipt, VerifiedObject, VerifiedObjectDelete,
};
pub use storage::{ObjectStoreSettings, VerifiedObjectStorage};

pub(crate) use contract::{ObservedOperation, ObserverRequestBinding, WriteBinding};
#[cfg(feature = "aws")]
pub(crate) use storage::map_backend_configuration_error;

#[cfg(test)]
mod tests;
