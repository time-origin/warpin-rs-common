//! Explicitly constructed Linux management test, never a production daemon.
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use chrono::Utc;
    use sea_orm::{ConnectionTrait, Database, TransactionTrait};
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::Path,
        process::Command,
        sync::Arc,
        time::{Duration, Instant},
    };
    use uuid::Uuid;
    use warpin_workspace::{
        AllocationIdentity, AllocationRequest, AllocationState, VolumeBudget, WorkspacePolicy,
        ledger::PostgresAllocationLedger,
        linux::{FixedExt4AllocationManager, FixedExt4Backend},
    };
    let root = Path::new("/work/manager-root");
    let mode = std::env::args().nth(1).unwrap_or_else(|| "normal".into());
    if mode == "recover" || mode == "recover-reject-foreign-view" {
        let token: warpin_workspace::ReservationToken =
            serde_json::from_slice(&fs::read("/work/recovery-token.json")?)?;
        let db = Arc::new(
            Database::connect(std::env::var("WARPIN_WORKSPACE_TEST_DATABASE_URL")?).await?,
        );
        let ledger = PostgresAllocationLedger::new(
            db.clone(),
            warpin_workspace::schema::WorkspaceSchema::parse(&std::env::var(
                "WARPIN_WORKSPACE_TEST_SCHEMA",
            )?)?,
        );
        let backend = FixedExt4Backend::new(root, &token.pool_id, 65534, 65534)?;
        let manager = FixedExt4AllocationManager::new(
            ledger.clone(),
            backend,
            std::num::NonZeroUsize::new(2).unwrap(),
        )?;
        if mode == "recover-reject-foreign-view" {
            ensure!(
                manager.recover_and_release(&token).await.is_err(),
                "different real PID namespace view authorized release"
            );
            ensure!(
                ledger.read(&token).await?.state == AllocationState::Retained,
                "wrong observer view released retained capacity"
            );
            println!(
                "{}",
                serde_json::json!({"allocationId":token.allocation_id,
                "foreignObserverRejected":true,"retained":true,"constructedOnly":true})
            );
            return Ok(());
        }
        let released = manager.recover_and_release(&token).await?;
        ensure!(
            released.state == AllocationState::Released,
            "cross-process recovery did not release"
        );
        ensure!(
            manager.recover_and_release(&token).await? == released,
            "cross-process release replay differs"
        );
        println!(
            "{}",
            serde_json::json!({"allocationId":token.allocation_id,"state":released.state,"crossProcessRecovery":true,"exactReplay":true,"constructedOnly":true})
        );
        return Ok(());
    }
    ensure!(
        mode == "normal"
            || mode == "prepare-recovery"
            || mode == "foreign-root-negative"
            || mode == "foreign-root-race-negative",
        "unknown constructed probe mode"
    );
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let pool = format!("isolated-{}", Uuid::new_v4());
    let budget = VolumeBudget {
        capacity_bytes: 32 * 1024 * 1024,
        maximum_inodes: 128,
    };
    let policy = WorkspacePolicy {
        schema_version: "warpin.workspace-policy/v1".into(),
        backend: "fixed-ext4-image/v1".into(),
        inputs: budget.clone(),
        scratch: budget.clone(),
        outputs: budget,
    };
    let mut request = AllocationRequest {
        allocation_id: Uuid::new_v4(),
        pool_id: pool.clone(),
        identity: AllocationIdentity {
            tenant_id: "constructed-tenant".into(),
            scope_id: "constructed-scope".into(),
            job_id: Uuid::new_v4().to_string(),
            attempt_id: "constructed-attempt".into(),
            fence: "19".into(),
            release_ref: "constructed-resource".into(),
            release_digest: format!("sha256:{}", "d".repeat(64)),
        },
        policy_digest: policy.digest()?.to_string(),
        policy,
        deadline: Utc::now() + chrono::Duration::minutes(10),
    };
    request.allocation_id = request.expected_allocation_id()?;
    let db =
        Arc::new(Database::connect(std::env::var("WARPIN_WORKSPACE_TEST_DATABASE_URL")?).await?);
    let ledger = PostgresAllocationLedger::new(
        db.clone(),
        warpin_workspace::schema::WorkspaceSchema::parse(&std::env::var(
            "WARPIN_WORKSPACE_TEST_SCHEMA",
        )?)?,
    );
    ledger.install_schema().await?;
    ledger
        .configure_pool(
            &pool,
            request.policy.total_bytes()?,
            request.policy.total_inodes()?,
        )
        .await?;
    let backend = FixedExt4Backend::new(root, &pool, 65534, 65534)?;
    let manager = FixedExt4AllocationManager::new(
        ledger.clone(),
        backend,
        std::num::NonZeroUsize::new(2).unwrap(),
    )?;
    if mode == "foreign-root-race-negative" {
        let foreign = Path::new("/work/foreign-manager-root");
        fs::DirBuilder::new().mode(0o700).create(foreign)?;
        let wrong = FixedExt4AllocationManager::new(
            ledger.clone(),
            FixedExt4Backend::new(foreign, &pool, 65534, 65534)?,
            std::num::NonZeroUsize::new(2).unwrap(),
        )?;
        // Both roots observe the same pre-existing RESERVED request before the
        // first provision. The durable pool binding must elect exactly one.
        ledger.reserve(request.clone()).await?;
        let (a, b) = tokio::join!(
            manager.provision(request.clone()),
            wrong.provision(request.clone())
        );
        ensure!(
            a.is_ok() != b.is_ok(),
            "concurrent different roots both provisioned or neither won"
        );
        let (record, winner, loser, losing_root) = match (a, b) {
            (Ok(record), Err(_)) => (record, &manager, &wrong, foreign),
            (Err(_), Ok(record)) => (record, &wrong, &manager, root),
            _ => unreachable!(),
        };
        ensure!(
            loser.recover_and_release(&record.token()?).await.is_err(),
            "losing root reclaimed winner"
        );
        ensure!(
            !losing_root
                .join(record.request.allocation_id.to_string())
                .exists(),
            "losing root minted allocation ownership"
        );
        ensure!(
            ledger.read(&record.token()?).await?.state == AllocationState::Provisioned,
            "losing root altered durable phase"
        );
        winner.release_unstarted(&record.token()?).await?;
        println!(
            "{}",
            serde_json::json!({"allocationId":record.request.allocation_id,
            "reservedConcurrentRootsExactlyOneWinner":true,"loserDidNotMintOwnership":true,
            "foreignRootRecoveryRejected":true,"winnerOwnCleanup":true,"constructedOnly":true})
        );
        return Ok(());
    }
    // Construct the exact self-owned RESERVED image interrupted before mkfs.
    // It has no loop/mount and may be rebuilt under the inherited guard.
    let reserved = ledger.reserve(request.clone()).await?;
    let directory = root.join(reserved.request.allocation_id.to_string());
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut partial = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("inputs.img"))?;
    partial.set_len(reserved.request.policy.inputs.capacity_bytes)?;
    partial.write_all(b"constructed interrupted pre-mkfs bytes")?;
    partial.sync_all()?;
    drop(partial);
    let record = manager.provision(request.clone()).await?;
    if mode == "foreign-root-negative" {
        let foreign = Path::new("/work/foreign-manager-root");
        fs::DirBuilder::new().mode(0o700).create(foreign)?;
        let wrong = FixedExt4AllocationManager::new(
            ledger.clone(),
            FixedExt4Backend::new(foreign, &pool, 65534, 65534)?,
            std::num::NonZeroUsize::new(2).unwrap(),
        )?;
        ensure!(
            wrong.recover_and_release(&record.token()?).await.is_err(),
            "empty foreign root falsely released A"
        );
        ensure!(
            !foreign
                .join(record.request.allocation_id.to_string())
                .exists(),
            "foreign root minted ownership directory"
        );
        let current = ledger.read(&record.token()?).await?;
        ensure!(
            current == record
                && fs::read_dir(&directory)?
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry
                        .path()
                        .extension()
                        .is_some_and(|suffix| suffix == "img"))
                    .count()
                    == 3,
            "foreign attempt changed A record or images"
        );
        // Exact same-root missing ownership must not be silently re-created.
        let owner = directory.join("ownership.json");
        let saved = directory.join("ownership.saved");
        fs::rename(&owner, &saved)?;
        let rejected = manager.recover_and_release(&record.token()?).await.is_err();
        let reminted = owner.exists();
        fs::rename(&saved, &owner)?;
        ensure!(
            rejected && !reminted,
            "non-reserved missing ownership was minted/released"
        );
        ensure!(
            ledger.read(&record.token()?).await? == record,
            "missing ownership changed durable record"
        );
        manager.release_unstarted(&record.token()?).await?;
        println!(
            "{}",
            serde_json::json!({"allocationId":record.request.allocation_id,
            "samePoolEmptyForeignRootRejected":true,"aImagesRemain":3,
            "nonReservedMissingOwnershipRejectedWithoutMint":true,"aOwnCleanupCompleted":true,
            "constructedOnly":true})
        );
        return Ok(());
    }

    let receipt = record
        .provisioning
        .clone()
        .context("verified provisioning missing")?;
    // Construct the exact owned post-mount/pre-chown crash boundary, without
    // changing filesystem contents or touching another allocation.
    ensure!(
        Command::new("/usr/bin/chown")
            .arg("0:0")
            .arg(directory.join("inputs"))
            .status()?
            .success(),
        "constructed own post-mount metadata drift failed"
    );
    let replay = manager.provision(request).await?;
    ensure!(replay == record, "provisioning replay drift");
    let paths = manager.verified_paths(&record.token()?).await?;
    ensure!(
        fs::metadata(&paths[0])?.uid() == 65534,
        "post-mount interrupted ownership was not restored"
    );
    ensure!(
        manager.begin_launch(&record.token()?).await.is_err(),
        "unsealed inputs admitted execution"
    );
    fs::write(
        paths[0].join("constructed-input"),
        b"constructed input bytes",
    )?;
    // Block the real durable seal commit after its actual physical remount,
    // then cancel only the request future. The owned settlement must retain
    // its file guard and operation permit until the PostgreSQL commit resumes.
    let held = db.begin().await?;
    held.query_one_raw(warpin_storage::postgres_statement(
        "SELECT pool_id FROM warpin_workspace_pools_v1 WHERE pool_id=$1 FOR UPDATE",
        [pool.clone().into()],
    ))
    .await?
    .context("constructed own pool missing")?;
    let sealing = manager.clone();
    let sealing_token = record.token()?;
    let caller = tokio::spawn(async move { sealing.seal_inputs(&sealing_token).await });
    let observed = Instant::now();
    loop {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let readonly = mountinfo.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.get(4).copied() == paths[0].to_str()
                && fields
                    .get(5)
                    .is_some_and(|flags| flags.split(',').any(|flag| flag == "ro"))
        });
        if readonly {
            break;
        }
        ensure!(
            observed.elapsed() < Duration::from_secs(15),
            "constructed seal physical timeout"
        );
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    caller.abort();
    ensure!(
        caller.await.unwrap_err().is_cancelled(),
        "constructed requester was not cancelled"
    );
    let competing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.join("manager.lock"))?;
    ensure!(
        competing.try_lock().is_err(),
        "caller cancellation released pre-commit physical guard"
    );
    ensure!(
        !ledger.read(&record.token()?).await?.inputs_sealed,
        "real PG seal commit was not held by fixture transaction"
    );
    let mut heartbeat = tokio::time::interval(Duration::from_millis(5));
    for _ in 0..5 {
        tokio::time::timeout(Duration::from_millis(30), heartbeat.tick())
            .await
            .context("single-worker heartbeat starved during physical/PG settlement")?;
    }
    ensure!(
        competing.try_lock().is_err(),
        "physical guard dropped while commit remained pending"
    );
    held.commit().await?;
    let start = Instant::now();
    let sealed = loop {
        let settled = ledger.read(&record.token()?).await?;
        if settled.inputs_sealed && competing.try_lock().is_ok() {
            competing.unlock()?;
            break settled;
        }
        ensure!(
            start.elapsed() < Duration::from_secs(15),
            "detached seal did not durably settle"
        );
        tokio::time::sleep(Duration::from_millis(3)).await;
    };
    drop(competing);
    ensure!(sealed.inputs_sealed, "input seal was not persisted");
    ensure!(
        manager.seal_inputs(&record.token()?).await? == sealed,
        "input seal replay differs"
    );
    let write_error = fs::write(paths[0].join("forbidden-write"), b"forbidden").unwrap_err();
    ensure!(
        write_error.raw_os_error() == Some(libc::EROFS),
        "inputs not protected by actual read-only filesystem"
    );
    // An external administrator drift in this isolated owned fixture cannot
    // silently make previously sealed inputs writable at launch admission.
    ensure!(
        manager.provision(record.request.clone()).await? == sealed,
        "provision replay changed sealed authority"
    );
    ensure!(
        Command::new("/usr/bin/mount")
            .args([
                "--no-canonicalize",
                "-t",
                "ext4",
                "-o",
                "remount,rw,nosuid,nodev,noexec",
                "--target"
            ])
            .arg(&paths[0])
            .status()?
            .success(),
        "constructed own mount drift failed"
    );
    ensure!(
        manager.verified_paths(&record.token()?).await.is_err(),
        "writable sealed input returned verified paths"
    );
    ensure!(
        manager.begin_launch(&record.token()?).await.is_err(),
        "writable sealed input admitted launch"
    );
    ensure!(
        ledger.read(&record.token()?).await?.inputs_sealed,
        "mount drift erased durable seal"
    );
    manager.seal_inputs(&record.token()?).await?;
    ensure!(
        fs::write(paths[0].join("still-forbidden"), b"forbidden")
            .unwrap_err()
            .raw_os_error()
            == Some(libc::EROFS),
        "input seal restoration not physically read-only"
    );
    let mut bytes_written = 0_u64;
    let file = paths[1].join("constructed-capacity.data");
    let mut f = File::create(&file)?;
    let chunk = vec![0x5a; 64 * 1024];
    let disk_error = loop {
        match f.write(&chunk) {
            Ok(0) => anyhow::bail!("zero write before capacity error"),
            Ok(n) => {
                bytes_written += n as u64;
                ensure!(
                    bytes_written <= record.request.policy.scratch.capacity_bytes,
                    "disk capacity exceeded"
                );
            }
            Err(e) => break e,
        }
    };
    ensure!(
        disk_error.raw_os_error() == Some(libc::ENOSPC),
        "expected actual hard filesystem capacity error"
    );
    drop(f);
    fs::remove_file(&file)?;
    let mut created = Vec::new();
    let inode_error = loop {
        let path = paths[2].join(format!("inode-{}", created.len()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => {
                drop(f);
                created.push(path);
                ensure!(
                    created.len() <= record.request.policy.outputs.maximum_inodes as usize,
                    "inode capacity exceeded"
                );
            }
            Err(e) => break e,
        }
    };
    ensure!(
        inode_error.raw_os_error() == Some(libc::ENOSPC),
        "expected actual hard inode capacity error"
    );
    let files_created = created.len();
    for path in created {
        fs::remove_file(path)?;
    }
    let launching = manager.begin_launch(&record.token()?).await?;
    ensure!(
        manager
            .recover_and_release(&launching.token()?)
            .await
            .is_err(),
        "uncertain launch was reclaimed without namespace identity"
    );
    ensure!(
        ledger.read(&launching.token()?).await?.state == AllocationState::Launching,
        "uncertain launch lost its reservation"
    );
    let mut child = Command::new("/usr/bin/unshare")
        .args([
            "--mount",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "/usr/bin/sleep",
            "30",
        ])
        .spawn()?;
    let start = Instant::now();
    let init_pid = loop {
        let descendants =
            fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))?;
        if let Some(pid) = descendants.split_whitespace().next() {
            break pid.parse::<u32>()?;
        }
        ensure!(
            start.elapsed() < Duration::from_secs(5),
            "constructed namespace launch timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let namespace = manager.capture_namespace(init_pid).await?;
    let active = manager
        .bind_execution(&launching.token()?, namespace.verified_binding())
        .await?;
    ensure!(
        manager
            .observe_namespace_death(namespace.clone())
            .await?
            .is_none(),
        "live namespace reported dead"
    );
    ensure!(
        manager.release_unstarted(&active.token()?).await.is_err(),
        "live namespace filesystem was torn down"
    );
    ensure!(
        manager.recover_and_release(&active.token()?).await.is_err(),
        "live prior namespace was reclaimed"
    );
    let retained = manager.retain(&active.token()?).await?;
    ensure!(
        manager
            .recover_and_release(&retained.token()?)
            .await
            .is_err(),
        "retained live prior namespace was reclaimed"
    );
    ensure!(
        manager.release_unstarted(&retained.token()?).await.is_err(),
        "retained namespace filesystem was torn down"
    );
    // SAFETY: this PID is pinned by our pidfd and belongs to the namespace init
    // just launched by this constructed fixture; no caller PID is accepted.
    ensure!(
        unsafe { libc::kill(init_pid as i32, libc::SIGKILL) } == 0,
        "constructed namespace kill failed"
    );
    let _status = child.wait()?;
    let death = manager
        .observe_namespace_death(namespace.clone())
        .await?
        .context("actual namespace death unconfirmed")?;
    if mode == "prepare-recovery" {
        fs::write(
            "/work/recovery-token.json",
            serde_json::to_vec(&retained.token()?)?,
        )?;
        println!(
            "{}",
            serde_json::json!({"allocationId":retained.request.allocation_id,"state":retained.state,"namespaceKnownDead":true,"leftForSecondProcess":true,"constructedOnly":true})
        );
        return Ok(());
    }
    let released = manager
        .quiescent_release(&retained.token()?, &death)
        .await?;
    ensure!(
        released.state == AllocationState::Released,
        "capacity not released"
    );
    ensure!(
        ledger.read(&released.token()?).await? == released,
        "release readback drift"
    );
    println!(
        "{}",
        serde_json::json!({"allocationId":released.request.allocation_id,"pool":pool,"hardCapacityBytes":released.request.policy.scratch.capacity_bytes,"bytesWrittenBeforeEnospc":bytes_written,"filesCreatedBeforeInodeEnospc":files_created,"hardInodeMaximum":released.request.policy.outputs.maximum_inodes,"provisioning":&receipt,"namespace":death.binding(),"releaseState":released.state,"exactReplay":true,"constructedOnly":true})
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("constructed fixed-filesystem probe requires Linux");
    std::process::exit(1)
}
