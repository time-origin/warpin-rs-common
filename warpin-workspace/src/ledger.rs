//! Durable pool accounting. DDL installation is an explicit operator action.
use crate::schema::{WorkspaceSchema, statement as workspace_statement};
use crate::state::{
    VerifiedExecutionBinding, VerifiedFilesystemTeardown, VerifiedInputSeal,
    VerifiedProvisioningReceipt,
};
use crate::{
    AllocationRecord, AllocationRequest, AllocationState, PoolAuthority, ReservationToken,
    VerifiedNamespaceDeath, VerifiedPoolAuthority,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction};
use serde_json::Value;
use std::sync::Arc;
use warpin_storage::run_in_transaction;

pub const SCHEMA_SQL: &str = include_str!("ledger.sql");

#[derive(Clone)]
pub struct PostgresAllocationLedger {
    database: Arc<DatabaseConnection>,
    schema: WorkspaceSchema,
}

impl PostgresAllocationLedger {
    pub fn new(database: Arc<DatabaseConnection>, schema: WorkspaceSchema) -> Self {
        Self { database, schema }
    }
    pub async fn install_schema(&self) -> Result<()> {
        crate::schema::install(&self.database, &self.schema).await
    }
    pub async fn verify_schema(&self) -> Result<()> {
        crate::schema::verify(&self.database, &self.schema).await
    }
    pub async fn configure_pool(&self, pool_id: &str, bytes: u64, inodes: u64) -> Result<()> {
        ensure!(
            !pool_id.is_empty()
                && pool_id.len() <= 128
                && pool_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                && bytes > 0
                && bytes <= i64::MAX as u64
                && inodes > 0
                && inodes <= i64::MAX as u64,
            "invalid workspace pool capacity"
        );
        let pool_id = pool_id.to_owned();
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| Box::pin(async move {
            crate::schema::check_transaction(tx, &schema).await?;
            tx.execute_raw(workspace_statement(&schema, "INSERT INTO warpin_workspace_pools_v1(pool_id,maximum_bytes,maximum_inodes) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                [pool_id.clone().into(),(bytes as i64).into(),(inodes as i64).into()])).await?;
            let row=tx.query_one_raw(workspace_statement(&schema, "SELECT maximum_bytes,maximum_inodes FROM warpin_workspace_pools_v1 WHERE pool_id=$1 FOR UPDATE",[pool_id.into()])).await?.context("workspace pool missing")?;
            ensure!(row.try_get::<i64>("","maximum_bytes")? == bytes as i64
                && row.try_get::<i64>("","maximum_inodes")? == inodes as i64, "workspace pool capacity drift");
            Ok(())
        })).await
    }
    /// Bind before any physical provisioning. Pool row locking serializes
    /// concurrent roots even when reservations already exist in RESERVED.
    pub async fn bind_pool_authority(&self, verified: &VerifiedPoolAuthority) -> Result<()> {
        let authority = verified.authority.clone();
        authority.validate()?;
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| Box::pin(async move {
            crate::schema::check_transaction(tx, &schema).await?;
            lock_pool(tx, &schema, &authority.pool_id).await?;
            if let Some(bound) = read_pool_authority(tx, &schema, &authority.pool_id).await? {
                ensure!(bound == authority, "workspace pool physical authority differs");
                return Ok(());
            }
            let row = tx.query_one_raw(workspace_statement(&schema,
                "SELECT COUNT(*)::bigint AS started FROM warpin_workspace_allocations_v1 WHERE pool_id=$1 AND state<>'RESERVED'",
                [authority.pool_id.clone().into()],
            )).await?.context("workspace pool adoption count absent")?;
            ensure!(row.try_get::<i64>("", "started")? == 0,
                "workspace unbound non-reserved history cannot be adopted");
            tx.execute_raw(workspace_statement(&schema,
                "INSERT INTO warpin_workspace_pool_authorities_v1(pool_id,authority_json,authority_digest) VALUES($1,$2,$3)",
                [authority.pool_id.clone().into(), serde_json::to_value(&authority)?.into(), authority.digest()?.into()],
            )).await?;
            Ok(())
        })).await
    }
    pub async fn verify_pool_authority(&self, verified: &VerifiedPoolAuthority) -> Result<()> {
        let authority = verified.authority.clone();
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| {
            Box::pin(async move {
                crate::schema::check_transaction(tx, &schema).await?;
                // The authority is immutable once bound. Read its committed
                // row without taking the capacity row lock; phase mutation
                // still verifies it under lock_pool in the same transaction.
                require_pool_authority(tx, &schema, &authority).await
            })
        })
        .await
    }
    pub async fn reserve(&self, request: AllocationRequest) -> Result<AllocationRecord> {
        request.identity.validate()?;
        ensure!(
            request.policy.digest()?.as_str() == request.policy_digest,
            "workspace policy digest mismatch"
        );
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| Box::pin(async move {
            crate::schema::check_transaction(tx, &schema).await?;
            let (maximum_bytes,maximum_inodes,used_bytes,used_inodes)=lock_pool(tx, &schema,&request.pool_id).await?;
            if let Some(record)=read_locked(tx, &schema,request.allocation_id).await? {
                ensure!(record.request==request,"workspace reservation replay differs");
                return Ok(record);
            }
            request.validate(Utc::now())?;
            let bytes=request.policy.total_bytes()?;
            let inodes=request.policy.total_inodes()?;
            let next_bytes=used_bytes.checked_add(bytes).context("workspace pool byte overflow")?;
            let next_inodes=used_inodes.checked_add(inodes).context("workspace pool inode overflow")?;
            ensure!(next_bytes<=maximum_bytes && next_inodes<=maximum_inodes,"workspace pool capacity exhausted");
            let record=AllocationRecord { request,state:AllocationState::Reserved,provisioning:None,inputs_sealed:false,execution:None };
            tx.execute_raw(workspace_statement(&schema, "INSERT INTO warpin_workspace_allocations_v1(allocation_id,pool_id,reserved_bytes,reserved_inodes,state,record_json,record_digest) VALUES($1,$2,$3,$4,$5,$6,$7)",
                [record.request.allocation_id.into(),record.request.pool_id.clone().into(),(bytes as i64).into(),(inodes as i64).into(),state_name(record.state).into(),serde_json::to_value(&record)?.into(),record.record_digest()?.into()])).await?;
            tx.execute_raw(workspace_statement(&schema, "UPDATE warpin_workspace_pools_v1 SET reserved_bytes=$2,reserved_inodes=$3 WHERE pool_id=$1",
                [record.request.pool_id.clone().into(),(next_bytes as i64).into(),(next_inodes as i64).into()])).await?;
            Ok(record)
        })).await
    }
    pub async fn read(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        let token = token.clone();
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| {
            Box::pin(async move {
                crate::schema::check_transaction(tx, &schema).await?;
                let record = read_locked(tx, &schema, token.allocation_id)
                    .await?
                    .context("workspace reservation missing")?;
                record.verify_token(&token)?;
                Ok(record)
            })
        })
        .await
    }
    pub async fn provisioned(
        &self,
        token: &ReservationToken,
        verified: &VerifiedProvisioningReceipt,
    ) -> Result<AllocationRecord> {
        let receipt = verified.receipt.clone();
        self.change_verified(
            token,
            Some(verified.pool_authority.clone()),
            None,
            move |record| {
                receipt.validate(record)?;
                if record.state == AllocationState::Provisioned {
                    ensure!(
                        record.provisioning.as_ref() == Some(&receipt),
                        "workspace provisioning replay differs"
                    );
                } else {
                    ensure!(
                        record.state == AllocationState::Reserved,
                        "workspace provisioning state invalid"
                    );
                    record.provisioning = Some(receipt);
                    record.state = AllocationState::Provisioned;
                }
                Ok(())
            },
        )
        .await
    }
    pub async fn seal_inputs(
        &self,
        token: &ReservationToken,
        proof: &VerifiedInputSeal,
    ) -> Result<AllocationRecord> {
        ensure!(
            proof.token == *token,
            "workspace input seal authority differs"
        );
        let uuid = proof.filesystem_uuid;
        self.change_verified(
            token,
            Some(proof.pool_authority.clone()),
            None,
            move |record| {
                ensure!(
                    record.state == AllocationState::Provisioned,
                    "workspace input seal state invalid"
                );
                ensure!(
                    record
                        .provisioning
                        .as_ref()
                        .map(|receipt| receipt.inputs.filesystem_uuid)
                        == Some(uuid),
                    "workspace input seal filesystem differs"
                );
                record.inputs_sealed = true;
                Ok(())
            },
        )
        .await
    }

    /// Persist launch intent before creating a namespace. A crash in this state
    /// retains capacity until management reconciliation; no expiry auto-release.
    pub async fn begin_launch(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        self.change(token, |record| {
            ensure!(
                record.request.deadline > Utc::now(),
                "workspace launch deadline expired"
            );
            ensure!(
                matches!(
                    record.state,
                    AllocationState::Provisioned | AllocationState::Launching
                ),
                "workspace launch state invalid"
            );
            ensure!(
                record.inputs_sealed,
                "workspace inputs must be sealed before launch"
            );
            record.state = AllocationState::Launching;
            Ok(())
        })
        .await
    }
    pub async fn bind_execution(
        &self,
        token: &ReservationToken,
        verified: &VerifiedExecutionBinding,
    ) -> Result<AllocationRecord> {
        let binding = verified.binding.clone();
        let authority = verified
            .pool_authority
            .clone()
            .context("workspace namespace lacks physical pool association")?;
        self.change_verified(
            token,
            Some(authority),
            Some(binding.boot_id),
            move |record| {
                if record.state == AllocationState::Active {
                    ensure!(
                        record.execution.as_ref() == Some(&binding),
                        "workspace namespace replay differs"
                    );
                } else {
                    ensure!(
                        record.state == AllocationState::Launching && record.execution.is_none(),
                        "workspace namespace state invalid"
                    );
                    record.execution = Some(binding);
                    record.state = AllocationState::Active;
                }
                Ok(())
            },
        )
        .await
    }
    pub async fn retain(&self, token: &ReservationToken) -> Result<AllocationRecord> {
        self.change(token, |record| {
            ensure!(
                !matches!(
                    record.state,
                    AllocationState::Quiescent | AllocationState::Released
                ),
                "workspace cannot retain released capacity"
            );
            record.state = AllocationState::Retained;
            Ok(())
        })
        .await
    }
    pub async fn quiescent(
        &self,
        token: &ReservationToken,
        death: &VerifiedNamespaceDeath,
    ) -> Result<AllocationRecord> {
        let binding = death.binding.clone();
        ensure!(
            death.observed_boot_id == binding.boot_id,
            "workspace foreign boot cannot prove namespace death"
        );
        let authority = death
            .pool_authority
            .clone()
            .context("workspace death lacks physical pool association")?;
        self.change_verified(
            token,
            Some(authority),
            Some(death.observed_boot_id),
            move |record| {
                ensure!(
                    record.execution.as_ref() == Some(&binding),
                    "workspace death receipt namespace mismatch"
                );
                ensure!(
                    matches!(
                        record.state,
                        AllocationState::Active
                            | AllocationState::Retained
                            | AllocationState::Quiescent
                    ),
                    "workspace quiescence state invalid"
                );
                record.state = AllocationState::Quiescent;
                Ok(())
            },
        )
        .await
    }
    pub async fn release(
        &self,
        token: &ReservationToken,
        teardown: &VerifiedFilesystemTeardown,
    ) -> Result<AllocationRecord> {
        ensure!(
            teardown.token == *token,
            "workspace teardown scope mismatch"
        );
        let token = token.clone();
        let authority = teardown.pool_authority.clone();
        let schema = self.schema.clone();
        run_in_transaction(&self.database,move |tx| Box::pin(async move {
            crate::schema::check_transaction(tx, &schema).await?;
            let (_,_,bytes,inodes)=lock_pool(tx, &schema,&token.pool_id).await?;
            ensure!(authority.pool_id == token.pool_id, "workspace teardown pool differs");
            require_pool_authority(tx, &schema, &authority).await?;
            let mut record=read_locked(tx, &schema,token.allocation_id).await?.context("workspace reservation missing")?;
            record.verify_token(&token)?;
            if record.state==AllocationState::Released{return Ok(record)}
            ensure!(record.state==AllocationState::Quiescent ||
                (matches!(record.state,AllocationState::Reserved|AllocationState::Provisioned) && record.execution.is_none()),
                "workspace release requires actual namespace death");
            let next_bytes=bytes.checked_sub(record.request.policy.total_bytes()?).context("workspace pool byte underflow")?;
            let next_inodes=inodes.checked_sub(record.request.policy.total_inodes()?).context("workspace pool inode underflow")?;
            record.state=AllocationState::Released;
            save(tx, &schema,&record).await?;
            tx.execute_raw(workspace_statement(&schema, "UPDATE warpin_workspace_pools_v1 SET reserved_bytes=$2,reserved_inodes=$3 WHERE pool_id=$1",
                [token.pool_id.into(),(next_bytes as i64).into(),(next_inodes as i64).into()])).await?;
            Ok(record)
        })).await
    }
    async fn change<F>(&self, token: &ReservationToken, change: F) -> Result<AllocationRecord>
    where
        F: FnOnce(&mut AllocationRecord) -> Result<()> + Send + 'static,
    {
        self.change_verified(token, None, None, change).await
    }
    async fn change_verified<F>(
        &self,
        token: &ReservationToken,
        authority: Option<PoolAuthority>,
        expected_boot: Option<uuid::Uuid>,
        change: F,
    ) -> Result<AllocationRecord>
    where
        F: FnOnce(&mut AllocationRecord) -> Result<()> + Send + 'static,
    {
        let token = token.clone();
        let schema = self.schema.clone();
        run_in_transaction(&self.database, move |tx| {
            Box::pin(async move {
                crate::schema::check_transaction(tx, &schema).await?;
                lock_pool(tx, &schema, &token.pool_id).await?;
                if let Some(authority) = authority {
                    ensure!(
                        authority.pool_id == token.pool_id,
                        "workspace receipt pool differs"
                    );
                    require_pool_authority(tx, &schema, &authority).await?;
                }
                if let Some(boot) = expected_boot {
                    let bound = read_pool_authority(tx, &schema, &token.pool_id)
                        .await?
                        .context("workspace physical pool authority missing")?;
                    ensure!(
                        bound.kernel_boot_id == boot,
                        "workspace namespace belongs to another boot"
                    );
                }
                let mut record = read_locked(tx, &schema, token.allocation_id)
                    .await?
                    .context("workspace reservation missing")?;
                record.verify_token(&token)?;
                change(&mut record)?;
                save(tx, &schema, &record).await?;
                Ok(record)
            })
        })
        .await
    }
}

fn state_name(state: AllocationState) -> &'static str {
    match state {
        AllocationState::Reserved => "RESERVED",
        AllocationState::Provisioned => "PROVISIONED",
        AllocationState::Launching => "LAUNCHING",
        AllocationState::Active => "ACTIVE",
        AllocationState::Retained => "RETAINED",
        AllocationState::Quiescent => "QUIESCENT",
        AllocationState::Released => "RELEASED",
    }
}

async fn lock_pool(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    id: &str,
) -> Result<(u64, u64, u64, u64)> {
    let row=tx.query_one_raw(workspace_statement(schema, "SELECT maximum_bytes,maximum_inodes,reserved_bytes,reserved_inodes FROM warpin_workspace_pools_v1 WHERE pool_id=$1 FOR UPDATE",[id.into()])).await?.context("workspace pool missing")?;
    let used=tx.query_one_raw(workspace_statement(schema, "SELECT COALESCE(SUM(reserved_bytes),0)::bigint AS bytes,COALESCE(SUM(reserved_inodes),0)::bigint AS inodes FROM warpin_workspace_allocations_v1 WHERE pool_id=$1 AND state<>'RELEASED'",[id.into()])).await?.context("workspace pool accounting absent")?;
    let bytes = row.try_get::<i64>("", "reserved_bytes")?;
    let inodes = row.try_get::<i64>("", "reserved_inodes")?;
    ensure!(
        bytes == used.try_get::<i64>("", "bytes")?
            && inodes == used.try_get::<i64>("", "inodes")?,
        "workspace durable capacity accounting drift"
    );
    Ok((
        row.try_get::<i64>("", "maximum_bytes")?.try_into()?,
        row.try_get::<i64>("", "maximum_inodes")?.try_into()?,
        bytes.try_into()?,
        inodes.try_into()?,
    ))
}
async fn read_locked(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    id: uuid::Uuid,
) -> Result<Option<AllocationRecord>> {
    let Some(row)=tx.query_one_raw(workspace_statement(schema, "SELECT pool_id,reserved_bytes,reserved_inodes,record_json,record_digest,state FROM warpin_workspace_allocations_v1 WHERE allocation_id=$1 FOR UPDATE",[id.into()])).await? else{return Ok(None)};
    let record: AllocationRecord =
        serde_json::from_value(row.try_get::<Value>("", "record_json")?)?;
    ensure!(
        record.request.allocation_id == id
            && record.request.expected_allocation_id()? == id
            && record.request.pool_id == row.try_get::<String>("", "pool_id")?
            && record.request.policy.total_bytes()?
                == u64::try_from(row.try_get::<i64>("", "reserved_bytes")?)?
            && record.request.policy.total_inodes()?
                == u64::try_from(row.try_get::<i64>("", "reserved_inodes")?)?
            && record.request.policy.digest()?.as_str() == record.request.policy_digest
            && record.record_digest()? == row.try_get::<String>("", "record_digest")?
            && state_name(record.state) == row.try_get::<String>("", "state")?,
        "workspace persisted identity/digest drift"
    );
    Ok(Some(record))
}
async fn save(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    record: &AllocationRecord,
) -> Result<()> {
    let result=tx.execute_raw(workspace_statement(schema, "UPDATE warpin_workspace_allocations_v1 SET state=$2,record_json=$3,record_digest=$4 WHERE allocation_id=$1",[record.request.allocation_id.into(),state_name(record.state).into(),serde_json::to_value(record)?.into(),record.record_digest()?.into()])).await?;
    ensure!(
        result.rows_affected() == 1,
        "workspace persisted record missing"
    );
    Ok(())
}

async fn read_pool_authority(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    pool: &str,
) -> Result<Option<PoolAuthority>> {
    let Some(row) = tx.query_one_raw(workspace_statement(schema,
        "SELECT authority_json,authority_digest FROM warpin_workspace_pool_authorities_v1 WHERE pool_id=$1", [pool.into()],
    )).await? else { return Ok(None) };
    let authority: PoolAuthority =
        serde_json::from_value(row.try_get::<Value>("", "authority_json")?)?;
    ensure!(
        authority.pool_id == pool
            && authority.digest()? == row.try_get::<String>("", "authority_digest")?,
        "workspace persisted physical pool authority drift"
    );
    Ok(Some(authority))
}
async fn require_pool_authority(
    tx: &DatabaseTransaction,
    schema: &WorkspaceSchema,
    expected: &PoolAuthority,
) -> Result<()> {
    expected.validate()?;
    let bound = read_pool_authority(tx, schema, &expected.pool_id)
        .await?
        .context("workspace physical pool authority missing")?;
    ensure!(
        bound == *expected,
        "workspace physical pool authority differs"
    );
    Ok(())
}

#[cfg(test)]
mod pool_identity_tests {
    use super::*;
    use crate::{AllocationIdentity, VolumeBudget, WorkspacePolicy};
    use sea_orm::{ConnectOptions, Database};
    use uuid::Uuid;
    use warpin_storage::postgres_statement;

    // Synthetic trusted-test metadata exercises the database contract only;
    // these tests do not mint a runtime/kernel attestation or touch devices.
    fn authority(pool: &str, root: &str, inode: &str) -> VerifiedPoolAuthority {
        VerifiedPoolAuthority {
            authority: PoolAuthority {
                schema_version: "warpin.workspace-pool-authority/v1".into(),
                backend: "fixed-ext4-image/v1".into(),
                pool_id: pool.into(),
                kernel_boot_id: Uuid::from_u128(0x11111111111111111111111111111111),
                canonical_root: root.into(),
                root_device_major: 8,
                root_device_minor: 1,
                root_inode: inode.into(),
                run_uid: 65534,
                run_gid: 65534,
            },
        }
    }
    fn request(pool: &str) -> AllocationRequest {
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
        let mut value = AllocationRequest {
            allocation_id: Uuid::new_v4(),
            pool_id: pool.into(),
            identity: AllocationIdentity {
                tenant_id: "synthetic-tenant".into(),
                scope_id: "synthetic-scope".into(),
                job_id: Uuid::new_v4().to_string(),
                attempt_id: "synthetic-attempt".into(),
                fence: "3".into(),
                release_ref: "synthetic-neutral-resource".into(),
                release_digest: format!("sha256:{}", "e".repeat(64)),
            },
            policy_digest: policy.digest().unwrap().to_string(),
            policy,
            deadline: Utc::now() + chrono::Duration::minutes(5),
        };
        value.allocation_id = value.expected_allocation_id().unwrap();
        value
    }
    #[tokio::test]
    #[ignore = "Requires explicitly owned isolated PostgreSQL fixture; no filesystem/device operations"]
    async fn real_pg_pool_authority_atomic_reserved_race_foreign_proofs_and_unknown_retention() {
        let url =
            std::env::var("WARPIN_WORKSPACE_TEST_DATABASE_URL").expect("owned development DB");
        let admin = Database::connect(url.clone()).await.unwrap();
        let schema = format!("workspace_identity_{}", Uuid::new_v4().simple());
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options
            .max_connections(8)
            .set_schema_search_path(schema.clone());
        let db = Arc::new(Database::connect(options).await.unwrap());
        let ledger =
            PostgresAllocationLedger::new(db.clone(), WorkspaceSchema::parse(&schema).unwrap());
        ledger.install_schema().await.unwrap();
        let pool = format!("pool-{}", Uuid::new_v4());
        let req = request(&pool);
        ledger
            .configure_pool(
                &pool,
                req.policy.total_bytes().unwrap(),
                req.policy.total_inodes().unwrap(),
            )
            .await
            .unwrap();
        let reserved = ledger.reserve(req).await.unwrap();
        let a = authority(&pool, "/synthetic/root-a", "101");
        let b = authority(&pool, "/synthetic/root-b", "202");
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let left = {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            let a = a.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                ledger.bind_pool_authority(&a).await
            })
        };
        let right = {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            let b = b.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                ledger.bind_pool_authority(&b).await
            })
        };
        let left = left.await.unwrap();
        let right = right.await.unwrap();
        assert_ne!(
            left.is_ok(),
            right.is_ok(),
            "two physical roots claimed same reserved pool"
        );
        let (winner, loser) = if left.is_ok() { (a, b) } else { (b, a) };
        ledger.bind_pool_authority(&winner).await.unwrap();
        assert!(ledger.verify_pool_authority(&loser).await.is_err());
        assert_eq!(
            ledger.read(&reserved.token().unwrap()).await.unwrap(),
            reserved
        );
        let foreign = VerifiedFilesystemTeardown {
            token: reserved.token().unwrap(),
            pool_authority: loser.authority,
        };
        assert!(
            ledger
                .release(&reserved.token().unwrap(), &foreign)
                .await
                .is_err()
        );
        assert_eq!(
            ledger.read(&reserved.token().unwrap()).await.unwrap().state,
            AllocationState::Reserved
        );
        for changed in [
            {
                let mut v = winner.clone();
                v.authority.kernel_boot_id = Uuid::new_v4();
                v
            },
            {
                let mut v = winner.clone();
                v.authority.root_inode = "303".into();
                v
            },
            {
                let mut v = winner.clone();
                v.authority.run_uid = 65533;
                v
            },
        ] {
            assert!(ledger.verify_pool_authority(&changed).await.is_err());
        }
        let retained = ledger.retain(&reserved.token().unwrap()).await.unwrap();
        assert_eq!(retained.state, AllocationState::Retained);
        let own = VerifiedFilesystemTeardown {
            token: reserved.token().unwrap(),
            pool_authority: winner.authority,
        };
        assert!(
            ledger
                .release(&reserved.token().unwrap(), &own)
                .await
                .is_err(),
            "unknown retained phase was released"
        );
        assert!(
            ledger.reserve(request(&pool)).await.is_err(),
            "retained reservation no longer occupied capacity"
        );
        let row = db.query_one_raw(postgres_statement(
            "SELECT reserved_bytes,reserved_inodes FROM warpin_workspace_pools_v1 WHERE pool_id=$1", [pool.clone().into()]
        )).await.unwrap().unwrap();
        assert_eq!(
            row.try_get::<i64>("", "reserved_bytes").unwrap() as u64,
            reserved.request.policy.total_bytes().unwrap()
        );
        assert_eq!(
            row.try_get::<i64>("", "reserved_inodes").unwrap() as u64,
            reserved.request.policy.total_inodes().unwrap()
        );
        // Unbound legacy/uncertain phases cannot be adopted by any new root.
        let legacy = format!("legacy-{}", Uuid::new_v4());
        let req = request(&legacy);
        ledger
            .configure_pool(
                &legacy,
                req.policy.total_bytes().unwrap(),
                req.policy.total_inodes().unwrap(),
            )
            .await
            .unwrap();
        let legacy_record = ledger.reserve(req).await.unwrap();
        ledger
            .retain(&legacy_record.token().unwrap())
            .await
            .unwrap();
        assert!(
            ledger
                .bind_pool_authority(&authority(&legacy, "/synthetic/new-root", "404"))
                .await
                .is_err()
        );
        // A historical RELEASED label alone cannot prove physical provenance
        // for an unbound legacy pool. Inject only an owned synthetic DB row.
        let mut historical = ledger.read(&legacy_record.token().unwrap()).await.unwrap();
        historical.state = AllocationState::Released;
        db.execute_raw(postgres_statement(
            "UPDATE warpin_workspace_allocations_v1 SET state='RELEASED',record_json=$2,record_digest=$3 WHERE allocation_id=$1",
            [historical.request.allocation_id.into(), serde_json::to_value(&historical).unwrap().into(), historical.record_digest().unwrap().into()],
        )).await.unwrap();
        db.execute_raw(postgres_statement(
            "UPDATE warpin_workspace_pools_v1 SET reserved_bytes=0,reserved_inodes=0 WHERE pool_id=$1", [legacy.clone().into()],
        )).await.unwrap();
        assert!(
            ledger
                .bind_pool_authority(&authority(&legacy, "/synthetic/another-root", "505"))
                .await
                .is_err()
        );

        admin
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
