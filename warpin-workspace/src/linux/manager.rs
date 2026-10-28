//! Atomic management facade: bounded per-manager/process operations settle
//! independently of requester cancellation. Physical guards span I/O and the
//! durable phase result; database failure never returns reserved capacity.
use super::{FixedExt4Backend, LinuxNamespaceHandle, filesystem::LockedAllocation};
use crate::{
    AllocationRecord, AllocationRequest, AllocationState, ReservationToken,
    VerifiedExecutionBinding, VerifiedNamespaceDeath, VerifiedPoolAuthority,
    ledger::PostgresAllocationLedger,
};
use anyhow::{Context, Result, ensure};
use std::{future::Future, num::NonZeroUsize, path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Clone)]
struct SettlementDomain {
    admission: Arc<Semaphore>,
}
impl SettlementDomain {
    fn new(maximum_in_flight: NonZeroUsize) -> Result<Self> {
        ensure!(
            maximum_in_flight.get() <= Semaphore::MAX_PERMITS,
            "workspace management concurrency is not representable"
        );
        Ok(Self {
            admission: Arc::new(Semaphore::new(maximum_in_flight.get())),
        })
    }
    async fn execute<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
    {
        // Admit before spawning: overloaded/cancelled callers cannot create an
        // unbounded detached queue. All clones share this same local domain.
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .context("workspace management operation capacity occupied")?;
        // Dropping the request's JoinHandle detaches this settlement task; it
        // does not abort a live helper or the following durable phase write.
        tokio::spawn(async move {
            let result = operation.await;
            drop(permit);
            result
        })
        .await
        .context("workspace management settlement task failed")?
    }
    async fn blocking<T, F>(operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        tokio::task::spawn_blocking(operation)
            .await
            .context("workspace management physical operation failed")?
    }
}

#[derive(Clone)]
pub struct FixedExt4AllocationManager {
    ledger: PostgresAllocationLedger,
    backend: FixedExt4Backend,
    operations: SettlementDomain,
}
impl FixedExt4AllocationManager {
    /// Explicit administrator concurrency, shared by clones of this manager.
    /// This is local admission, not a cross-node global concurrency limit.
    pub fn new(
        ledger: PostgresAllocationLedger,
        backend: FixedExt4Backend,
        maximum_in_flight: NonZeroUsize,
    ) -> Result<Self> {
        Ok(Self {
            ledger,
            backend,
            operations: SettlementDomain::new(maximum_in_flight)?,
        })
    }
    async fn observed_pool_authority(&self) -> Result<VerifiedPoolAuthority> {
        let backend = self.backend.clone();
        SettlementDomain::blocking(move || backend.pool_authority()).await
    }
    async fn lock_record(
        &self,
        token: &ReservationToken,
    ) -> Result<(AllocationRecord, LockedAllocation)> {
        let authority = self.observed_pool_authority().await?;
        ensure!(
            authority.authority.pool_id == token.pool_id,
            "workspace manager token belongs to another pool"
        );
        self.ledger.verify_pool_authority(&authority).await?;
        let before = self.ledger.read(token).await?;
        let backend = self.backend.clone();
        let locking_record = before.clone();
        let lock = SettlementDomain::blocking(move || backend.lock(&locking_record)).await?;
        let current = self.ledger.read(token).await?;
        ensure!(
            current.request == before.request,
            "workspace authority changed across physical lock"
        );
        Ok((current, lock))
    }
    async fn physical<T, F>(
        &self,
        record: AllocationRecord,
        lock: LockedAllocation,
        operation: F,
    ) -> Result<(T, LockedAllocation)>
    where
        T: Send + 'static,
        F: FnOnce(&FixedExt4Backend, &AllocationRecord, &LockedAllocation) -> Result<T>
            + Send
            + 'static,
    {
        let backend = self.backend.clone();
        SettlementDomain::blocking(move || {
            let output = operation(&backend, &record, &lock)?;
            Ok((output, lock))
        })
        .await
    }
    pub async fn provision(&self, request: AllocationRequest) -> Result<AllocationRecord> {
        let manager = self.clone();
        self.operations
            .execute(async move {
                let authority = manager.observed_pool_authority().await?;
                ensure!(
                    authority.authority.pool_id == request.pool_id,
                    "workspace provision pool differs"
                );
                manager.ledger.bind_pool_authority(&authority).await?;
                let reserved = manager.ledger.reserve(request).await?;
                let token = reserved.token()?;
                let (record, lock) = manager.lock_record(&token).await?;
                if record.state == AllocationState::Reserved {
                    record.request.validate(chrono::Utc::now())?;
                }
                let (proof, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.provision_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.provisioned(&token, &proof).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn verified_paths(&self, token: &ReservationToken) -> Result<[PathBuf; 3]> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (record, lock) = manager.lock_record(&token).await?;
                ensure!(
                    matches!(
                        record.state,
                        AllocationState::Provisioned
                            | AllocationState::Launching
                            | AllocationState::Active
                    ),
                    "workspace paths are not active authority"
                );
                let (paths, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.verified_paths_locked(record, lock)
                    })
                    .await?;
                drop(guard);
                Ok(paths)
            })
            .await
    }
    pub async fn seal_inputs(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (record, lock) = manager.lock_record(&token).await?;
                let (proof, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.seal_inputs_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.seal_inputs(&token, &proof).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn begin_launch(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (record, lock) = manager.lock_record(&token).await?;
                let (_paths, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.verified_paths_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.begin_launch(&token).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn bind_execution(
        &self,
        token: &ReservationToken,
        process: &VerifiedExecutionBinding,
    ) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        let process = process.clone();
        self.operations
            .execute(async move {
                let (_record, guard) = manager.lock_record(&token).await?;
                let result = manager.ledger.bind_execution(&token, &process).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn retain(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (_record, guard) = manager.lock_record(&token).await?;
                let result = manager.ledger.retain(&token).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn release_unstarted(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (record, lock) = manager.lock_record(&token).await?;
                let (proof, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.teardown_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.release(&token, &proof).await;
                drop(guard);
                result
            })
            .await
    }
    pub async fn quiescent_release(
        &self,
        token: &ReservationToken,
        death: &VerifiedNamespaceDeath,
    ) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        let death = death.clone();
        self.operations
            .execute(async move {
                let (_record, lock) = manager.lock_record(&token).await?;
                let record = manager.ledger.quiescent(&token, &death).await?;
                let (proof, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.teardown_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.release(&token, &proof).await;
                drop(guard);
                result
            })
            .await
    }
    /// Only exact prior namespace-init death permits crash cleanup. Lost
    /// LAUNCHING identity or changed proc view retains capacity.
    pub async fn recover_and_release(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let manager = self.clone();
        let token = token.clone();
        self.operations
            .execute(async move {
                let (record, lock) = manager.lock_record(&token).await?;
                if record.state == AllocationState::Released {
                    return Ok(record);
                }
                if record.execution.is_none() {
                    ensure!(
                        matches!(
                            record.state,
                            AllocationState::Reserved | AllocationState::Provisioned
                        ),
                        "workspace uncertain launch has no verified namespace identity"
                    );
                    let (proof, guard) = manager
                        .physical(record, lock, |backend, record, lock| {
                            backend.teardown_locked(record, lock)
                        })
                        .await?;
                    let result = manager.ledger.release(&token, &proof).await;
                    drop(guard);
                    return result;
                }
                let (death, lock) = manager
                    .physical(record, lock, |backend, record, _lock| {
                        let binding = record
                            .execution
                            .as_ref()
                            .context("workspace prior execution identity missing")?;
                        let mut death = super::namespace::observe_previous_death(binding)?
                            .context("workspace prior namespace remains live")?;
                        death.pool_authority = Some(backend.pool_authority()?.authority);
                        Ok(death)
                    })
                    .await?;
                let record = manager.ledger.quiescent(&token, &death).await?;
                let (proof, guard) = manager
                    .physical(record, lock, |backend, record, lock| {
                        backend.teardown_locked(record, lock)
                    })
                    .await?;
                let result = manager.ledger.release(&token, &proof).await;
                drop(guard);
                result
            })
            .await
    }
    /// The trusted launcher supplies its own captured child PID, never an RPC
    /// caller PID. Synchronous proc/pidfd observation runs off Tokio workers.
    pub async fn capture_namespace(&self, pid: u32) -> Result<Arc<LinuxNamespaceHandle>> {
        let manager = self.clone();
        self.operations
            .execute(async move {
                let authority = manager.observed_pool_authority().await?;
                manager.ledger.verify_pool_authority(&authority).await?;
                SettlementDomain::blocking(move || {
                    Ok(Arc::new(
                        LinuxNamespaceHandle::capture(pid)?.associate(&authority)?,
                    ))
                })
                .await
            })
            .await
    }
    pub async fn observe_namespace_death(
        &self,
        namespace: Arc<LinuxNamespaceHandle>,
    ) -> Result<Option<VerifiedNamespaceDeath>> {
        let manager = self.clone();
        self.operations
            .execute(async move {
                let authority = manager.observed_pool_authority().await?;
                ensure!(
                    namespace.pool_authority() == Some(&authority.authority),
                    "workspace namespace physical pool association differs"
                );
                manager.ledger.verify_pool_authority(&authority).await?;
                SettlementDomain::blocking(move || namespace.observe_death()).await
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use tokio::sync::oneshot;

    #[tokio::test(flavor = "current_thread")]
    async fn single_worker_heartbeat_survives_blocking_and_admission_is_shared() {
        let domain = SettlementDomain::new(NonZeroUsize::new(1).unwrap()).unwrap();
        let other = domain.clone();
        let finish = Arc::new(AtomicBool::new(false));
        let work_finish = finish.clone();
        let (started, ready) = oneshot::channel();
        let request = tokio::spawn(async move {
            other
                .execute(async move {
                    SettlementDomain::blocking(move || {
                        started.send(()).unwrap();
                        while !work_finish.load(Ordering::Acquire) {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Ok(())
                    })
                    .await
                })
                .await
        });
        ready.await.unwrap();
        assert!(domain.execute(async { Ok(()) }).await.is_err());
        let mut heartbeat = tokio::time::interval(Duration::from_millis(5));
        for _ in 0..5 {
            tokio::time::timeout(Duration::from_millis(20), heartbeat.tick())
                .await
                .unwrap();
        }
        finish.store(true, Ordering::Release);
        request.await.unwrap().unwrap();
        domain.execute(async { Ok(()) }).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_request_keeps_os_lock_until_physical_and_commit_settle() {
        let root = std::env::temp_dir().join(format!("workspace-cancel-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("owned.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let competing = File::open(&path).unwrap();
        let domain = SettlementDomain::new(NonZeroUsize::new(1).unwrap()).unwrap();
        let other = domain.clone();
        let finish = Arc::new(AtomicBool::new(false));
        let work_finish = finish.clone();
        let settled = Arc::new(AtomicBool::new(false));
        let work_settled = settled.clone();
        let (started, ready) = oneshot::channel();
        let (commit_ready, commit_observed) = oneshot::channel();
        let (commit, commit_wait) = oneshot::channel();
        let request = tokio::spawn(async move {
            other
                .execute(async move {
                    let guard = SettlementDomain::blocking(move || {
                        lock.lock()?;
                        started.send(()).unwrap();
                        while !work_finish.load(Ordering::Acquire) {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Ok(lock)
                    })
                    .await?;
                    commit_ready.send(()).unwrap();
                    commit_wait.await?;
                    drop(guard);
                    work_settled.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        ready.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(competing.try_lock().is_err());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(competing.try_lock().is_err());
        finish.store(true, Ordering::Release);
        commit_observed.await.unwrap();
        assert!(
            competing.try_lock().is_err(),
            "guard dropped before durable phase result"
        );
        assert!(!settled.load(Ordering::Acquire));
        assert!(domain.execute(async { Ok(()) }).await.is_err());
        commit.send(()).unwrap();
        while !settled.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        competing.try_lock().unwrap();
        competing.unlock().unwrap();
        domain.execute(async { Ok(()) }).await.unwrap();
        drop(competing);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
