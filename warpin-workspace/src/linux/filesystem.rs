use crate::{
    AllocationRecord, AllocationState, FilesystemReceipt, PoolAuthority, ProvisioningReceipt,
    VerifiedFilesystemTeardown, VerifiedInputSeal, VerifiedPoolAuthority,
    VerifiedProvisioningReceipt, VolumeBudget,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct FixedExt4Backend {
    root: PathBuf,
    pool_id: String,
    run_uid: u32,
    run_gid: u32,
    initial_authority: PoolAuthority,
}
pub(super) struct LockedAllocation {
    directory: PathBuf,
    _lock: File,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ownership {
    pool_authority: PoolAuthority,
    request: crate::AllocationRequest,
}

const MANAGEMENT_TIMEOUT_SECONDS: u32 = 120;
const MANAGEMENT_OUTPUT_BYTES: u64 = 1024 * 1024;

fn bounded_output(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MANAGEMENT_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MANAGEMENT_OUTPUT_BYTES,
        "workspace management output exceeds bound"
    );
    Ok(bytes)
}
fn command(program: &'static str, args: &[String], lock: &File) -> Result<Output> {
    command_with_timeout(program, args, lock, MANAGEMENT_TIMEOUT_SECONDS)
}
fn command_with_timeout(
    program: &'static str,
    args: &[String],
    lock: &File,
    seconds: u32,
) -> Result<Output> {
    ensure!(seconds > 0, "workspace management timeout must be positive");
    // The guardian keeps the allocation's open-file-description lock while the
    // fixed management utility runs, even if its Rust parent is killed. The
    // utility may close inherited FDs without releasing the guardian's copy.
    // The watchdog signals only its directly spawned fixed utility and waits
    // for actual child exit: no kill-after may kill the watchdog itself and
    // drop the lock while a kernel operation remains uninterruptible.
    // Program and arguments are derived solely from administrator configuration
    // and typed budgets; no RPC accepts a command, script or arbitrary path.
    let descriptor = lock.as_raw_fd();
    let mut child = Command::new("/bin/sh");
    child
        .args([
            "-c",
            "\"$@\" & wait \"$!\"",
            "warpin-workspace-management-guardian",
            "/usr/bin/timeout",
            "--foreground",
            "--signal=KILL",
        ])
        .arg(format!("{seconds}s"))
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    // SAFETY: after fork the hook performs only async-signal-safe fcntl; it
    // changes the descriptor flags in the child, not in the parent's table.
    unsafe {
        child.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = child.spawn()?;
    let stdout = child
        .stdout
        .take()
        .context("workspace stdout pipe absent")?;
    let stderr = child
        .stderr
        .take()
        .context("workspace stderr pipe absent")?;
    // Each reader stores at most the declared bound plus one rejection byte;
    // dropping an overflowing pipe also prevents unbounded helper output.
    // The guardian owns its timeout and lock even after this parent dies.
    let output = std::thread::scope(|scope| -> Result<Output> {
        let stdout = scope.spawn(move || bounded_output(stdout));
        let stderr = scope.spawn(move || bounded_output(stderr));
        let status = child.wait()?;
        let stdout = stdout
            .join()
            .map_err(|_| anyhow::anyhow!("workspace stdout reader failed"))??;
        let stderr = stderr
            .join()
            .map_err(|_| anyhow::anyhow!("workspace stderr reader failed"))??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })?;
    ensure!(
        output.status.success(),
        "workspace management operation failed: {program}"
    );
    Ok(output)
}
fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o777 == 0o700,
        "workspace management directory ownership invalid"
    );
    Ok(())
}
fn string(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("workspace path is not UTF-8")?
        .to_owned())
}
fn role_uuid(id: Uuid, role: &str) -> Uuid {
    Uuid::new_v5(&id, role.as_bytes())
}
fn volume_roles(record: &AllocationRecord) -> [(&str, &VolumeBudget); 3] {
    [
        ("inputs", &record.request.policy.inputs),
        ("scratch", &record.request.policy.scratch),
        ("outputs", &record.request.policy.outputs),
    ]
}

impl FixedExt4Backend {
    /// The root is administrator configuration, not a per-request path. It must
    /// already be root-owned 0700 and contain only this manager's allocations.
    pub fn new(root: &Path, pool_id: &str, run_uid: u32, run_gid: u32) -> Result<Self> {
        ensure!(
            run_uid > 0 && run_gid > 0,
            "workspace task identity must be non-root"
        );
        ensure!(
            !pool_id.is_empty()
                && pool_id.len() <= 128
                && pool_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "invalid workspace backend pool identity"
        );
        private_directory(root)?;
        let canonical = fs::canonicalize(root)?;
        ensure!(canonical == root, "workspace pool root must be canonical");
        Ok(Self {
            root: canonical.clone(),
            pool_id: pool_id.to_owned(),
            run_uid,
            run_gid,
            initial_authority: observe_pool_root(&canonical, pool_id, run_uid, run_gid)?,
        })
    }
    pub(super) fn pool_authority(&self) -> Result<VerifiedPoolAuthority> {
        let observed = observe_pool_root(&self.root, &self.pool_id, self.run_uid, self.run_gid)?;
        ensure!(
            observed == self.initial_authority,
            "workspace bootstrap physical pool changed"
        );
        Ok(VerifiedPoolAuthority {
            authority: observed,
        })
    }
    pub(super) fn lock(&self, record: &AllocationRecord) -> Result<LockedAllocation> {
        let authority = self.pool_authority()?.authority;
        ensure!(
            record.request.pool_id == self.pool_id,
            "workspace backend belongs to another pool"
        );
        record.request.identity.validate()?;
        record.request.policy.validate()?;
        ensure!(
            record.request.policy.digest()?.as_str() == record.request.policy_digest,
            "workspace policy digest mismatch"
        );
        let directory = self.root.join(record.request.allocation_id.to_string());
        if record.state == AllocationState::Reserved {
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        } else {
            ensure!(
                directory.exists()
                    && directory.join("ownership.json").exists()
                    && directory.join("manager.lock").exists(),
                "workspace non-reserved physical ownership missing"
            );
        }
        private_directory(&directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(record.state == AllocationState::Reserved)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("manager.lock"))?;
        ensure!(
            lock.metadata()?.uid() == 0 && lock.metadata()?.nlink() == 1,
            "workspace lock ownership invalid"
        );
        lock.lock()?;
        let ownership = directory.join("ownership.json");
        let bytes = serde_json::to_vec(&Ownership {
            pool_authority: authority.clone(),
            request: record.request.clone(),
        })?;
        let creation = if record.state == AllocationState::Reserved {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&ownership)
        } else {
            // Read existing ownership only: even a disappearance while waiting
            // for the physical lock must never mint a new non-RESERVED owner.
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        };
        match creation {
            Ok(mut f) => {
                f.write_all(&bytes)?;
                f.sync_all()?;
                File::open(&directory)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut f = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&ownership)?;
                ensure!(
                    f.metadata()?.uid() == 0
                        && f.metadata()?.nlink() == 1
                        && f.metadata()?.len() <= 64 * 1024,
                    "workspace ownership record invalid"
                );
                let mut observed = Vec::new();
                f.read_to_end(&mut observed)?;
                let stored: Ownership = serde_json::from_slice(&observed)?;
                ensure!(
                    stored.request == record.request && stored.pool_authority == authority,
                    "workspace backing allocation scope/fence mismatch"
                );
            }
            Err(e) => return Err(e.into()),
        }
        Ok(LockedAllocation {
            directory,
            _lock: lock,
        })
    }
    pub(super) fn provision_locked(
        &self,
        record: &AllocationRecord,
        allocation: &LockedAllocation,
    ) -> Result<VerifiedProvisioningReceipt> {
        ensure!(
            matches!(
                record.state,
                AllocationState::Reserved | AllocationState::Provisioned
            ),
            "workspace cannot reprovision active allocation"
        );
        ensure!(
            !allocation.directory.join("retirement.json").exists(),
            "workspace allocation is permanently retired"
        );
        let mut receipts = Vec::new();
        for (role, budget) in volume_roles(record) {
            let image = allocation.directory.join(format!("{role}.img"));
            let target = allocation.directory.join(role);
            let uuid = role_uuid(record.request.allocation_id, role);
            let exists = image.exists();
            if exists {
                verify_image(&image, budget.capacity_bytes)?;
            }
            let fresh_or_unattached = !exists
                || (record.state == AllocationState::Reserved
                    && loops_for_image(&image, &allocation._lock)?.is_empty()
                    && !mount_exists(&target)?);
            if fresh_or_unattached {
                // Acquiring the inherited physical lock proves previous fixed
                // utilities finished. No execution can be admitted in RESERVED.
                // An unattached partial image may therefore be rebuilt safely;
                // attached/active filesystems are never formatted on replay.
                let f = OpenOptions::new()
                    .write(true)
                    .create_new(!exists)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&image)?;
                f.set_len(budget.capacity_bytes)?;
                f.sync_all()?;
                command(
                    "/usr/bin/fallocate",
                    &[
                        "--length".into(),
                        budget.capacity_bytes.to_string(),
                        string(&image)?,
                    ],
                    &allocation._lock,
                )?;
                let groups = (budget.capacity_bytes / 4096).div_ceil(32768);
                let alignment = groups
                    .checked_mul(16)
                    .context("workspace inode alignment overflow")?;
                let inodes = budget.maximum_inodes / alignment * alignment;
                ensure!(
                    inodes >= 128,
                    "workspace inode budget cannot represent filesystem groups"
                );
                command(
                    "/usr/sbin/mkfs.ext4",
                    &[
                        "-F".into(),
                        "-q".into(),
                        "-b".into(),
                        "4096".into(),
                        "-g".into(),
                        "32768".into(),
                        "-I".into(),
                        "256".into(),
                        "-m".into(),
                        "0".into(),
                        "-N".into(),
                        inodes.to_string(),
                        "-U".into(),
                        uuid.to_string(),
                        "-O".into(),
                        "^resize_inode".into(),
                        "-E".into(),
                        "lazy_itable_init=0,lazy_journal_init=0".into(),
                        string(&image)?,
                    ],
                    &allocation._lock,
                )?;
            }
            verify_image(&image, budget.capacity_bytes)?;
            let output = command(
                "/usr/sbin/losetup",
                &[
                    "--find".into(),
                    "--show".into(),
                    "--nooverlap".into(),
                    "--sizelimit".into(),
                    budget.capacity_bytes.to_string(),
                    string(&image)?,
                ],
                &allocation._lock,
            )?;
            let device = String::from_utf8(output.stdout)?.trim().to_owned();
            verify_loop(&device, &image, budget.capacity_bytes, &allocation._lock)?;
            let receipt = inspect_filesystem(&device, uuid, budget, &allocation._lock)?;
            if !target.exists() {
                fs::DirBuilder::new().mode(0o700).create(&target)?;
            }
            ensure!(
                fs::symlink_metadata(&target)?.is_dir()
                    && !fs::symlink_metadata(&target)?.file_type().is_symlink(),
                "workspace mount target invalid"
            );
            if !verify_mount(&target, &receipt)? {
                command(
                    "/usr/bin/mount",
                    &[
                        "--no-canonicalize".into(),
                        "-t".into(),
                        "ext4".into(),
                        "-o".into(),
                        "rw,nosuid,nodev,noexec".into(),
                        device,
                        "--target".into(),
                        string(&target)?,
                    ],
                    &allocation._lock,
                )?;
                ensure!(
                    verify_mount(&target, &receipt)?,
                    "workspace hard mount readback failed"
                );
            }
            // A crash between mount and chown leaves a valid mounted image but
            // not a usable task root. Replay validates/repairs this only while
            // unstarted, never by making a sealed filesystem writable.
            let metadata = fs::symlink_metadata(&target)?;
            if metadata.uid() != self.run_uid
                || metadata.gid() != self.run_gid
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                ensure!(
                    !mount_is_read_only(&target)?,
                    "workspace read-only task root ownership drift"
                );
                command(
                    "/usr/bin/chown",
                    &[
                        format!("{}:{}", self.run_uid, self.run_gid),
                        string(&target)?,
                    ],
                    &allocation._lock,
                )?;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
            }
            verify_task_root(&target, self.run_uid, self.run_gid)?;
            receipts.push(receipt);
        }
        let mut receipts = receipts.into_iter();
        let token = record.token()?;
        let result = ProvisioningReceipt {
            allocation_id: token.allocation_id,
            identity_digest: token.identity_digest,
            policy_digest: token.policy_digest,
            inputs: receipts
                .next()
                .context("input filesystem receipt missing")?,
            scratch: receipts
                .next()
                .context("scratch filesystem receipt missing")?,
            outputs: receipts
                .next()
                .context("output filesystem receipt missing")?,
        };
        result.validate(record)?;
        Ok(VerifiedProvisioningReceipt {
            pool_authority: self.pool_authority()?.authority,
            receipt: result,
        })
    }
    pub(super) fn seal_inputs_locked(
        &self,
        record: &AllocationRecord,
        allocation: &LockedAllocation,
    ) -> Result<VerifiedInputSeal> {
        ensure!(
            record.state == AllocationState::Provisioned,
            "workspace input sealing requires unstarted provisioning"
        );
        let receipt = record
            .provisioning
            .as_ref()
            .context("workspace provisioning absent")?;
        receipt.validate(record)?;
        let path = allocation.directory.join("inputs");
        ensure!(
            verify_mount(&path, &receipt.inputs)?,
            "workspace input mount absent"
        );
        if !mount_is_read_only(&path)? {
            command(
                "/usr/bin/mount",
                &[
                    "--no-canonicalize".into(),
                    "-t".into(),
                    "ext4".into(),
                    "-o".into(),
                    "remount,ro,nosuid,nodev,noexec".into(),
                    "--target".into(),
                    string(&path)?,
                ],
                &allocation._lock,
            )?;
        }
        ensure!(
            verify_mount(&path, &receipt.inputs)? && mount_is_read_only(&path)?,
            "workspace input read-only seal unconfirmed"
        );
        Ok(VerifiedInputSeal {
            pool_authority: self.pool_authority()?.authority,
            token: record.token()?,
            filesystem_uuid: receipt.inputs.filesystem_uuid,
        })
    }

    /// Fixed role paths are returned only from an exact verified allocation.
    pub(super) fn verified_paths_locked(
        &self,
        record: &AllocationRecord,
        allocation: &LockedAllocation,
    ) -> Result<[PathBuf; 3]> {
        let receipt = record
            .provisioning
            .as_ref()
            .context("workspace provisioning absent")?;
        receipt.validate(record)?;
        let paths = [
            allocation.directory.join("inputs"),
            allocation.directory.join("scratch"),
            allocation.directory.join("outputs"),
        ];
        for (path, volume) in
            paths
                .iter()
                .zip([&receipt.inputs, &receipt.scratch, &receipt.outputs])
        {
            ensure!(
                verify_mount(path, volume)?,
                "workspace allocation mount lost"
            );
            verify_task_root(path, self.run_uid, self.run_gid)?;
        }
        ensure!(
            !record.inputs_sealed || mount_is_read_only(&paths[0])?,
            "workspace sealed input became writable"
        );
        Ok(paths)
    }
    /// Caller supplies a ledger readback, never deserialized RPC state. Active,
    /// retained and launch-uncertain allocations cannot be physically removed.
    pub(super) fn teardown_locked(
        &self,
        record: &AllocationRecord,
        allocation: &LockedAllocation,
    ) -> Result<VerifiedFilesystemTeardown> {
        ensure!(
            record.state == AllocationState::Quiescent
                || (matches!(
                    record.state,
                    AllocationState::Reserved
                        | AllocationState::Provisioned
                        | AllocationState::Released
                ) && record.execution.is_none()),
            "workspace teardown requires actual namespace death"
        );
        let marker = allocation.directory.join("retirement.json");
        let token = record.token()?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&marker)
        {
            Ok(mut file) => {
                file.write_all(&serde_json::to_vec(&token)?)?;
                file.sync_all()?;
                File::open(&allocation.directory)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&marker)?;
                ensure!(
                    file.metadata()?.uid() == 0
                        && file.metadata()?.nlink() == 1
                        && file.metadata()?.len() <= 4096,
                    "workspace retirement marker ownership invalid"
                );
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                let observed: crate::ReservationToken = serde_json::from_slice(&bytes)?;
                ensure!(
                    observed == token,
                    "workspace retirement marker scope differs"
                );
            }
            Err(error) => return Err(error.into()),
        }
        for (role, budget) in volume_roles(record) {
            let image = allocation.directory.join(format!("{role}.img"));
            let target = allocation.directory.join(role);
            if !image.exists() {
                ensure!(
                    !mount_exists(&target)?,
                    "workspace mounted without owned backing image"
                );
                continue;
            }
            verify_image(&image, budget.capacity_bytes)?;
            let loops = loops_for_image(&image, &allocation._lock)?;
            for device in loops {
                verify_loop(&device, &image, budget.capacity_bytes, &allocation._lock)?;
                let receipt = inspect_filesystem(
                    &device,
                    role_uuid(record.request.allocation_id, role),
                    budget,
                    &allocation._lock,
                )?;
                if mount_exists(&target)? {
                    ensure!(
                        verify_mount(&target, &receipt)?,
                        "workspace foreign mount blocks cleanup"
                    );
                    command(
                        "/usr/bin/umount",
                        &["--no-canonicalize".into(), string(&target)?],
                        &allocation._lock,
                    )?;
                    ensure!(
                        !mount_exists(&target)?,
                        "workspace mount cleanup unconfirmed"
                    );
                }
                command(
                    "/usr/sbin/losetup",
                    &["--detach".into(), device],
                    &allocation._lock,
                )?;
            }
            ensure!(
                loops_for_image(&image, &allocation._lock)?.is_empty(),
                "workspace loop detach unconfirmed"
            );
            ensure!(!mount_exists(&target)?, "workspace mount remains");
            fs::remove_file(&image)?;
        }
        File::open(&allocation.directory)?.sync_all()?;
        Ok(VerifiedFilesystemTeardown {
            pool_authority: self.pool_authority()?.authority,
            token: record.token()?,
        })
    }
}

fn verify_task_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && metadata.gid() == gid
            && metadata.permissions().mode() & 0o777 == 0o700,
        "workspace task root ownership drift"
    );
    Ok(())
}
fn verify_image(image: &Path, bytes: u64) -> Result<()> {
    let m = fs::symlink_metadata(image)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.uid() == 0
            && m.nlink() == 1
            && m.len() == bytes
            && m.permissions().mode() & 0o777 == 0o600,
        "workspace image ownership or capacity drift"
    );
    Ok(())
}
#[derive(Deserialize)]
struct LoopList {
    loopdevices: Vec<LoopRow>,
}
#[derive(Deserialize)]
struct LoopRow {
    name: String,
    #[serde(rename = "back-file")]
    back_file: String,
    sizelimit: u64,
    offset: u64,
}
fn loops_for_image(image: &Path, lock: &File) -> Result<Vec<String>> {
    let output = command(
        "/usr/sbin/losetup",
        &[
            "--json".into(),
            "--list".into(),
            "--output".into(),
            "NAME,BACK-FILE,SIZELIMIT,OFFSET".into(),
            "--associated".into(),
            string(image)?,
        ],
        lock,
    )?;
    let list: LoopList = serde_json::from_slice(&output.stdout)?;
    Ok(list.loopdevices.into_iter().map(|row| row.name).collect())
}
fn verify_loop(device: &str, image: &Path, bytes: u64, lock: &File) -> Result<()> {
    let suffix = device
        .strip_prefix("/dev/loop")
        .context("workspace loop device name invalid")?;
    ensure!(
        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()),
        "workspace loop device name invalid"
    );
    let m = fs::metadata(device)?;
    ensure!(
        m.file_type().is_block_device() && libc::major(m.rdev()) == 7,
        "workspace device is not a loop block device"
    );
    let output = command(
        "/usr/sbin/losetup",
        &[
            "--json".into(),
            "--list".into(),
            "--output".into(),
            "NAME,BACK-FILE,SIZELIMIT,OFFSET".into(),
            device.into(),
        ],
        lock,
    )?;
    let list: LoopList = serde_json::from_slice(&output.stdout)?;
    ensure!(
        list.loopdevices.len() == 1,
        "workspace loop identity ambiguous"
    );
    let row = &list.loopdevices[0];
    ensure!(
        row.name == device
            && Path::new(&row.back_file) == image
            && row.sizelimit == bytes
            && row.offset == 0,
        "workspace loop backing identity drift"
    );
    Ok(())
}
fn inspect_filesystem(
    device: &str,
    uuid: Uuid,
    budget: &VolumeBudget,
    lock: &File,
) -> Result<FilesystemReceipt> {
    let out = command("/usr/sbin/dumpe2fs", &["-h".into(), device.into()], lock)?;
    let text = String::from_utf8(out.stdout)?;
    let field = |key: &str| -> Result<&str> {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
            .context("workspace filesystem metadata missing")
    };
    ensure!(
        field("Filesystem UUID:")?.parse::<Uuid>()? == uuid,
        "workspace filesystem UUID mismatch"
    );
    let blocks = field("Block count:")?.parse::<u64>()?;
    let size = field("Block size:")?.parse::<u64>()?;
    let bytes = blocks
        .checked_mul(size)
        .context("workspace filesystem capacity overflow")?;
    let inodes = field("Inode count:")?.parse::<u64>()?;
    ensure!(
        bytes == budget.capacity_bytes && inodes <= budget.maximum_inodes && inodes > 0,
        "workspace filesystem hard capacity mismatch"
    );
    let m = fs::metadata(device)?;
    Ok(FilesystemReceipt {
        filesystem_uuid: uuid,
        filesystem_bytes: bytes,
        filesystem_inodes: inodes,
        backing_device_major: libc::major(m.rdev()),
        backing_device_minor: libc::minor(m.rdev()),
    })
}
fn decode_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
fn mount_rows(target: &Path) -> Result<Vec<String>> {
    let expected = string(target)?;
    Ok(fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(4)
                .is_some_and(|value| decode_mount(value) == expected)
        })
        .map(str::to_owned)
        .collect())
}
fn mount_exists(target: &Path) -> Result<bool> {
    Ok(!mount_rows(target)?.is_empty())
}
fn mount_is_read_only(target: &Path) -> Result<bool> {
    let rows = mount_rows(target)?;
    ensure!(rows.len() == 1, "workspace input mount absent or ambiguous");
    let flags = rows[0]
        .split_whitespace()
        .nth(5)
        .context("workspace mount flags absent")?;
    Ok(flags.split(',').any(|flag| flag == "ro"))
}
fn verify_mount(target: &Path, receipt: &FilesystemReceipt) -> Result<bool> {
    let rows = mount_rows(target)?;
    if rows.is_empty() {
        return Ok(false);
    }
    ensure!(rows.len() == 1, "workspace overlapping mounts ambiguous");
    let fields: Vec<_> = rows[0].split_whitespace().collect();
    let separator = fields
        .iter()
        .position(|value| *value == "-")
        .context("workspace mountinfo malformed")?;
    ensure!(
        fields.get(2).copied()
            == Some(
                format!(
                    "{}:{}",
                    receipt.backing_device_major, receipt.backing_device_minor
                )
                .as_str()
            )
            && fields.get(separator + 1) == Some(&"ext4")
            && fields
                .get(5)
                .is_some_and(|flags| ["nosuid", "nodev", "noexec"]
                    .iter()
                    .all(|required| flags.split(',').any(|value| value == *required))),
        "workspace mount authority or flags drift"
    );
    Ok(true)
}

fn observe_pool_root(
    root: &Path,
    pool_id: &str,
    run_uid: u32,
    run_gid: u32,
) -> Result<PoolAuthority> {
    private_directory(root)?;
    ensure!(
        fs::canonicalize(root)? == root,
        "workspace pool root changed canonical identity"
    );
    let metadata = fs::symlink_metadata(root)?;
    let authority = PoolAuthority {
        schema_version: "warpin.workspace-pool-authority/v1".into(),
        backend: "fixed-ext4-image/v1".into(),
        pool_id: pool_id.into(),
        kernel_boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .parse()?,
        canonical_root: string(root)?,
        root_device_major: libc::major(metadata.dev()),
        root_device_minor: libc::minor(metadata.dev()),
        root_inode: metadata.ino().to_string(),
        run_uid,
        run_gid,
    };
    authority.validate()?;
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn management_output_is_bounded_before_return() {
        assert_eq!(
            bounded_output(std::io::Cursor::new(b"bounded")).unwrap(),
            b"bounded"
        );
        let bytes = vec![b'x'; MANAGEMENT_OUTPUT_BYTES as usize + 1];
        assert!(bounded_output(std::io::Cursor::new(bytes)).is_err());
    }

    #[test]
    #[ignore = "Requires an explicit self-owned isolated Linux fixture"]
    fn guardian_timeout_settles_real_command_without_releasing_early() {
        let parent = PathBuf::from(
            std::env::var("WARPIN_WORKSPACE_CRASH_TEST_ROOT").expect("owned isolated root"),
        );
        let root = parent.join(format!("timeout-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("guard.lock"))
            .unwrap();
        lock.lock().unwrap();
        let start = Instant::now();
        assert!(command_with_timeout("/usr/bin/sleep", &["30".into()], &lock, 1).is_err());
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(start.elapsed() < Duration::from_secs(6));
        lock.unlock().unwrap();
        let second = File::open(root.join("guard.lock")).unwrap();
        second.try_lock().unwrap();
        fs::remove_file(root.join("guard.lock")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    #[ignore = "Only launched by the explicitly isolated crash fixture parent"]
    fn guardian_child_fixture() {
        let path = PathBuf::from(
            std::env::var("WARPIN_WORKSPACE_CRASH_HELPER_ROOT").expect("owned test root"),
        );
        private_directory(&path).expect("private owned fixture");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("guard.lock"))
            .unwrap();
        lock.lock().unwrap();
        command("/usr/bin/sleep", &["3".into()], &lock).unwrap();
    }

    #[test]
    #[ignore = "Requires an explicit self-owned isolated Linux fixture"]
    fn guardian_keeps_lock_until_real_command_exit_after_parent_sigkill() {
        let parent = PathBuf::from(
            std::env::var("WARPIN_WORKSPACE_CRASH_TEST_ROOT").expect("owned isolated root"),
        );
        let root = parent.join(format!("crash-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        private_directory(&root).unwrap();
        let mut helper = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "linux::filesystem::tests::guardian_child_fixture",
                "--nocapture",
            ])
            .env("WARPIN_WORKSPACE_CRASH_HELPER_ROOT", &root)
            .spawn()
            .unwrap();
        let started = Instant::now();
        let guardian = loop {
            let mut children = String::new();
            for task in fs::read_dir(format!("/proc/{}/task", helper.id())).unwrap() {
                let path = task.unwrap().path().join("children");
                if let Ok(value) = fs::read_to_string(path) {
                    children.push_str(&value);
                    children.push(' ');
                }
            }
            if let Some(pid) = children.split_whitespace().next() {
                break pid.parse::<u32>().unwrap();
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("guard.lock"))
            .unwrap();
        assert!(lock.try_lock().is_err());
        // SAFETY: the helper PID was returned by our own spawn and is still a
        // live child. No caller-selected PID or arbitrary command is accepted.
        assert_eq!(unsafe { libc::kill(helper.id() as i32, libc::SIGKILL) }, 0);
        helper.wait().unwrap();
        assert!(PathBuf::from(format!("/proc/{guardian}")).exists());
        assert!(
            lock.try_lock().is_err(),
            "crashed parent released live command's lock"
        );
        let start = Instant::now();
        loop {
            if lock.try_lock().is_ok() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(6),
                "guardian did not settle"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        fs::remove_file(root.join("guard.lock")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
