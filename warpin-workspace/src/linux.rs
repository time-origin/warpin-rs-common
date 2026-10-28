//! Trusted Linux management boundary. No management daemon is installed here.
mod filesystem;
mod manager;
mod namespace;
pub use filesystem::FixedExt4Backend;
pub use namespace::LinuxNamespaceHandle;

pub use manager::FixedExt4AllocationManager;
