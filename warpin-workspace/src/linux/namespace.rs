use crate::{
    ExecutionBinding, PoolAuthority, VerifiedExecutionBinding, VerifiedNamespaceDeath,
    VerifiedPoolAuthority,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
};
use uuid::Uuid;

/// A pidfd pins the exact verified namespace init, avoiding PID reuse ambiguity.
/// Management code supplies its own captured launch PID, never an RPC PID.
pub struct LinuxNamespaceHandle {
    fd: OwnedFd,
    verified: VerifiedExecutionBinding,
}

fn boot_id() -> Result<Uuid> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .parse()?)
}
fn snapshot(pid: u32) -> Result<ExecutionBinding> {
    ensure!(pid > 1, "host init cannot be a workspace namespace");
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .context("namespace process stat malformed")?;
    let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
    let start = fields
        .get(19)
        .context("namespace process start ticks missing")?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let nspid = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .context("namespace process NSpid missing")?;
    let ids: Vec<_> = nspid.split_whitespace().collect();
    ensure!(
        ids.len() >= 2 && ids.last() == Some(&"1"),
        "workspace process must be isolated PID namespace init"
    );
    let inode = fs::metadata(format!("/proc/{pid}/ns/pid"))?.ino();
    ensure!(
        inode != fs::metadata("/proc/self/ns/pid")?.ino(),
        "host PID namespace cannot be a workspace"
    );
    Ok(ExecutionBinding {
        boot_id: boot_id()?,
        init_pid: pid,
        start_ticks: (*start).to_owned(),
        pid_namespace_inode: inode.to_string(),
        observer_pid_namespace_inode: fs::metadata("/proc/self/ns/pid")?.ino().to_string(),
    })
}
impl LinuxNamespaceHandle {
    pub fn capture(pid: u32) -> Result<Self> {
        let first = snapshot(pid)?;
        // SAFETY: pidfd_open takes a numeric PID and zero flags; the successful
        // returned descriptor is uniquely transferred into OwnedFd below.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        ensure!(raw >= 0, "workspace pidfd open failed");
        // SAFETY: the syscall just returned this live owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        ensure!(
            snapshot(pid)? == first,
            "workspace namespace identity changed during capture"
        );
        Ok(Self {
            fd,
            verified: VerifiedExecutionBinding {
                pool_authority: None,
                binding: first,
            },
        })
    }
    pub(super) fn associate(mut self, verified: &VerifiedPoolAuthority) -> Result<Self> {
        ensure!(
            self.verified.binding.boot_id == verified.authority.kernel_boot_id,
            "workspace namespace and physical pool boot differ"
        );
        self.verified.pool_authority = Some(verified.authority.clone());
        Ok(self)
    }
    pub(super) fn pool_authority(&self) -> Option<&PoolAuthority> {
        self.verified.pool_authority.as_ref()
    }
    pub fn verified_binding(&self) -> &VerifiedExecutionBinding {
        &self.verified
    }
    pub fn observe_death(&self) -> Result<Option<VerifiedNamespaceDeath>> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized stack pollfd for the call.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        ensure!(result >= 0, "workspace pidfd observation failed");
        if result == 0 {
            return Ok(None);
        }
        ensure!(
            poll.revents & libc::POLLIN != 0 && poll.revents & libc::POLLNVAL == 0,
            "workspace pidfd death unconfirmed"
        );
        Ok(Some(VerifiedNamespaceDeath {
            pool_authority: self.verified.pool_authority.clone(),
            binding: self.verified.binding.clone(),
            observed_boot_id: boot_id()?,
        }))
    }
}

/// Recovery observes only a binding already read from the authenticated ledger.
/// A different proc/PID namespace view is insufficient evidence, never death.
pub(super) fn observe_previous_death(
    binding: &ExecutionBinding,
) -> Result<Option<VerifiedNamespaceDeath>> {
    let boot = boot_id()?;
    ensure!(
        boot == binding.boot_id,
        "workspace different boot lacks trusted same-host death proof"
    );
    ensure!(
        fs::metadata("/proc/self/ns/pid")?.ino().to_string()
            == binding.observer_pid_namespace_inode,
        "workspace recovery observer namespace differs"
    );
    let path = format!("/proc/{}/stat", binding.init_pid);
    let old_gone = match fs::read_to_string(path) {
        Ok(text) => {
            let end = text.rfind(')').context("recovery process stat malformed")?;
            let state = text[end + 1..]
                .split_whitespace()
                .next()
                .context("recovery process state absent")?;
            let start = text[end + 1..]
                .split_whitespace()
                .nth(19)
                .context("recovery process start ticks absent")?;
            start != binding.start_ticks || matches!(state, "Z" | "X")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    if old_gone {
        Ok(Some(VerifiedNamespaceDeath {
            pool_authority: None,
            binding: binding.clone(),
            observed_boot_id: boot,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_host_process_binding_and_live_or_foreign_recovery_claims() {
        assert!(LinuxNamespaceHandle::capture(std::process::id()).is_err());
        let stat = fs::read_to_string("/proc/self/stat").unwrap();
        let end = stat.rfind(')').unwrap();
        let start = stat[end + 1..]
            .split_whitespace()
            .nth(19)
            .unwrap()
            .to_owned();
        let mut claim = ExecutionBinding {
            boot_id: boot_id().unwrap(),
            init_pid: std::process::id(),
            start_ticks: start,
            pid_namespace_inode: fs::metadata("/proc/self/ns/pid").unwrap().ino().to_string(),
            observer_pid_namespace_inode: fs::metadata("/proc/self/ns/pid")
                .unwrap()
                .ino()
                .to_string(),
        };
        assert!(observe_previous_death(&claim).unwrap().is_none());
        let original_boot = claim.boot_id;
        claim.boot_id = Uuid::new_v4();
        assert!(observe_previous_death(&claim).is_err());
        claim.boot_id = original_boot;
        claim.observer_pid_namespace_inode = "0".into();
        assert!(observe_previous_death(&claim).is_err());
    }
}
