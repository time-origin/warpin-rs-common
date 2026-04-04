# warpin-transaction 设计文档

> **版本**: 0.1.0 (Draft)
> **作者**: Warpin Engineering
> **日期**: 2026-04-03
> **状态**: Architecture Design

## 目录

1. [设计哲学](#1-设计哲学)
2. [问题域分析](#2-问题域分析)
3. [架构总览](#3-架构总览)
4. [一致性模型分层](#4-一致性模型分层)
5. [Layer 1: Local Transaction Engine](#5-layer-1-local-transaction-engine)
6. [Layer 2: Transactional Outbox + CDC](#6-layer-2-transactional-outbox--cdc)
7. [Layer 3: 2PC Coordinator](#7-layer-3-2pc-coordinator)
8. [Layer 4: TCC Coordinator](#8-layer-4-tcc-coordinator)
9. [Layer 5: Saga Orchestrator](#9-layer-5-saga-orchestrator)
10. [Cross-Cutting: Distributed Lock](#10-cross-cutting-distributed-lock)
11. [Cross-Cutting: Idempotency Guard](#11-cross-cutting-idempotency-guard)
12. [Cross-Cutting: Transaction Tracing](#12-cross-cutting-transaction-tracing)
13. [数据库 Schema](#13-数据库-schema)
14. [Feature Gate 设计](#14-feature-gate-设计)
15. [公开 API 总览](#15-公开-api-总览)
16. [场景决策矩阵](#16-场景决策矩阵)
17. [与 warpin 生态集成](#17-与-warpin-生态集成)

---

## 1. 设计哲学

### 1.1 第一铁律

**永远选择最优解，而非低成本方案。**

warpin-transaction 不是"能跑就行"的事务工具包。它是一套面向生产级分布式系统的完整事务基础设施，覆盖从单库 ACID 到跨服务最终一致的全部一致性级别。

### 1.2 核心原则

| 原则 | 说明 |
|------|------|
| **一致性优先** | 在一致性和性能之间，优先保证一致性。绝不用弱一致模型"凑合"强一致场景 |
| **按需选择** | 提供 5 个一致性层级，业务按场景精确选择。不存在万能方案 |
| **不耦合业务** | 框架提供 trait 抽象和基础设施，业务项目仅实现 trait 并调用 API |
| **崩溃可恢复** | 所有分布式事务的每个决策点都持久化。进程崩溃后可从断点恢复 |
| **可观测** | 每个事务的生命周期都有 tracing span，支持 OpenTelemetry 集成 |
| **遵循 warpin 惯例** | trait → enum union → feature gate → helper functions |

### 1.3 为什么不只用 Saga

很多框架只提供 Saga 作为分布式事务方案。这是错误的。

Saga 本质是**最终一致**——执行过程中数据处于中间状态，其他事务可以读到未完成的数据。对于"跨库转账"这类不容忍中间状态的场景，Saga 无法满足要求。

warpin-transaction 的设计理念是：**该用什么一致性级别就用什么级别，不降级。**

### 1.4 为什么纳入 2PC

2PC（Two-Phase Commit）常因"性能差、阻塞"而被微服务社区回避。但在以下场景中，2PC 是唯一正确的选择：

- 跨数据库的财务结算（不容忍任何不一致）
- 跨服务的库存扣减（超卖 = 业务灾难）
- 审计要求强一致的合规场景

PostgreSQL 原生支持 `PREPARE TRANSACTION` / `COMMIT PREPARED`，这不是应用层模拟的 2PC，而是数据库引擎级别的原子保证。warpin-transaction 利用这一能力，配合持久化协调器和崩溃恢复机制，解决了传统 2PC 的单点故障问题。

---

## 2. 问题域分析

### 2.1 分布式系统中的事务挑战

在微服务架构下，数据分布在多个数据库中，服务间通过消息队列通信。以下是典型的事务问题：

**问题 1：单库多表操作的原子性**

```
Service A
├── Table: tasks        → UPDATE status = 'completed'
├── Table: arc_segments → UPDATE status = 'released'
└── 如果第二步失败，第一步的修改需要回滚
```

**问题 2：DB 写入 + 消息发送的原子性**

```
Service A
├── DB: UPDATE task status   → 成功
├── Kafka: publish event     → 失败（网络/Kafka 宕机）
└── 结果：DB 已更新，但下游服务永远不知道
```

**问题 3：跨服务操作的原子性**

```
Service A (scheduler DB): 创建任务        → 成功
Service B (customer DB):  生成账单        → 失败
└── 结果：任务已创建，但没有账单 → 数据不一致
```

**问题 4：长流程的失败补偿**

```
Step 1: 创建任务          → 成功
Step 2: 分配弧段          → 成功
Step 3: 预留设备          → 成功
Step 4: 生成计费单        → 失败
└── 需要逆序补偿：释放设备 → 释放弧段 → 取消任务
```

### 2.2 每个问题对应的解决方案

| 问题 | 解决方案 | warpin-transaction 层级 |
|------|---------|----------------------|
| 单库多表原子性 | 数据库本地事务（ACID） | Layer 1: Local Transaction |
| DB + 消息原子性 | Transactional Outbox + CDC | Layer 2: Outbox |
| 跨库原子提交（不容忍不一致） | 2PC（PostgreSQL PREPARE TX） | Layer 3: 2PC |
| 跨服务资源预留（可容忍短暂预留态） | TCC（Try-Confirm-Cancel） | Layer 4: TCC |
| 长流程失败补偿 | Saga + Semantic Lock | Layer 5: Saga |

---

## 3. 架构总览

### 3.1 分层架构图

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        warpin-transaction                                │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 1: Local Transaction Engine                                  │  │
│  │ ┌─────────────┐ ┌──────────────┐ ┌─────────────────────────────┐  │  │
│  │ │ ACID TX     │ │ Savepoints   │ │ TX Hooks                    │  │  │
│  │ │ (SeaORM)    │ │ (Nested TX)  │ │ (after-commit/on-rollback)  │  │  │
│  │ └─────────────┘ └──────────────┘ └─────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 2: Transactional Outbox + CDC                                │  │
│  │ ┌──────────────────┐ ┌────────────────┐ ┌──────────────────────┐  │  │
│  │ │ Outbox Writer    │ │ CDC Relay      │ │ Polling Relay        │  │  │
│  │ │ (same-TX write)  │ │ (WAL-based,   │ │ (fallback mode)      │  │  │
│  │ │                  │ │  primary)      │ │                      │  │  │
│  │ └──────────────────┘ └────────────────┘ └──────────────────────┘  │  │
│  │ ┌──────────────────────────────────────────────────────────────┐  │  │
│  │ │ Idempotent Consumer (consumer-side dedup, exactly-once)      │  │  │
│  │ └──────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 3: 2PC Coordinator (跨库原子提交)                             │  │
│  │ ┌──────────────────┐ ┌────────────────┐ ┌──────────────────────┐  │  │
│  │ │ Coordinator      │ │ Participant    │ │ Recovery Manager     │  │  │
│  │ │ (persistent FSM) │ │ (PREPARE TX)   │ │ (crash recovery)     │  │  │
│  │ └──────────────────┘ └────────────────┘ └──────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 4: TCC Coordinator (跨服务资源预留)                           │  │
│  │ ┌──────────────────┐ ┌────────────────┐ ┌──────────────────────┐  │  │
│  │ │ TCC Engine       │ │ Participant    │ │ Timeout + Fencing    │  │  │
│  │ │ (Try/Confirm/    │ │ (business      │ │ (auto-cancel,        │  │  │
│  │ │  Cancel driver)  │ │  reservation)  │ │  token validation)   │  │  │
│  │ └──────────────────┘ └────────────────┘ └──────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Layer 5: Saga Orchestrator (跨服务长流程编排)                       │  │
│  │ ┌──────────────────┐ ┌────────────────┐ ┌──────────────────────┐  │  │
│  │ │ Orchestrator     │ │ Semantic Lock  │ │ Dead Letter +        │  │  │
│  │ │ (persistent FSM) │ │ (isolation)    │ │ Manual Intervention  │  │  │
│  │ └──────────────────┘ └────────────────┘ └──────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Cross-Cutting Infrastructure                                       │  │
│  │ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ ┌────────────┐ │  │
│  │ │ Distributed  │ │ Idempotency  │ │ Fencing     │ │ TX         │ │  │
│  │ │ Lock (PG)    │ │ Guard        │ │ Token       │ │ Tracing    │ │  │
│  │ └──────────────┘ └──────────────┘ └─────────────┘ └────────────┘ │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 模块目录结构

```
warpin-transaction/
├── Cargo.toml
└── src/
    ├── lib.rs                          # 统一导出

    ├── local.rs                        # Layer 1: 本地事务引擎
    ├── local/
    │   ├── context.rs                  #   TransactionContext
    │   ├── hooks.rs                    #   AfterCommitHook / OnRollbackHook
    │   └── savepoint.rs               #   Savepoint 嵌套事务

    ├── outbox.rs                       # Layer 2: Transactional Outbox
    ├── outbox/
    │   ├── event.rs                    #   OutboxEvent 实体
    │   ├── writer.rs                   #   TransactionalPublisher
    │   ├── cdc_relay.rs                #   CDC Relay（WAL）
    │   ├── polling_relay.rs            #   Polling Relay（降级）
    │   ├── relay.rs                    #   OutboxRelay trait + enum union
    │   ├── consumer.rs                 #   IdempotentConsumer
    │   └── repository.rs              #   OutboxRepository

    ├── twopc.rs                        # Layer 3: 2PC Coordinator
    ├── twopc/
    │   ├── coordinator.rs              #   TwoPcCoordinator
    │   ├── participant.rs              #   TwoPcParticipant trait
    │   ├── pg_participant.rs           #   PostgreSQL PREPARE TX 实现
    │   ├── grpc_participant.rs         #   gRPC 远程 Participant 代理
    │   ├── recovery.rs                 #   崩溃恢复管理器
    │   ├── state.rs                    #   TwoPcExecution 持久化实体
    │   └── repository.rs              #   TwoPcRepository

    ├── tcc.rs                          # Layer 4: TCC Coordinator
    ├── tcc/
    │   ├── coordinator.rs              #   TccCoordinator
    │   ├── participant.rs              #   TccParticipant trait
    │   ├── state.rs                    #   TccExecution 持久化实体
    │   ├── timeout.rs                  #   超时自动 Cancel + Fencing
    │   └── repository.rs              #   TccRepository

    ├── saga.rs                         # Layer 5: Saga Orchestrator
    ├── saga/
    │   ├── definition.rs               #   SagaStep trait + SagaDefinition
    │   ├── context.rs                  #   SagaContext
    │   ├── orchestrator.rs             #   SagaOrchestrator
    │   ├── state.rs                    #   SagaExecution 状态机
    │   ├── semantic_lock.rs            #   Semantic Locking
    │   ├── dead_letter.rs              #   Dead Letter + 人工干预
    │   └── repository.rs              #   SagaExecutionRepository

    ├── lock.rs                         # Cross-cutting: 分布式锁
    ├── lock/
    │   ├── advisory.rs                 #   PostgreSQL Advisory Lock
    │   ├── fencing.rs                  #   Fencing Token
    │   └── memory.rs                   #   InMemoryLock（测试）

    ├── idempotency.rs                  # Cross-cutting: 幂等性
    ├── idempotency/
    │   ├── guard.rs                    #   IdempotencyGuard
    │   └── repository.rs              #   IdempotencyRepository

    └── tracing.rs                      # Cross-cutting: 事务追踪
```

### 3.3 依赖关系图

```
                    warpin-storage
                    (DatabaseConnection, CrudRepository,
                     run_in_transaction, SchemaPlan)
                          │
              ┌───────────┼───────────────┐
              ▼           ▼               ▼
          lock.rs     local.rs      idempotency.rs
              │           │
              ▼           ▼
          outbox.rs ◄─────┤
              │           │
         ┌────┼────┐      │
         ▼    ▼    ▼      │
     cdc  polling  consumer
              │           │
         ┌────┴────┐      │
         ▼         ▼      │
     twopc.rs   tcc.rs    │
         │         │      │
         └────┬────┘      │
              ▼           │
          saga.rs ◄───────┘
              │
              ▼
        warpin-event-bus
        (EventBus, BusEvent)
```

---

## 4. 一致性模型分层

### 4.1 五级一致性

```
强 ─────────────────────────────────────────────────── 弱
  │                                                      │
  │  Level 5    Level 4    Level 3    Level 2    Level 1  │
  │  Local TX   2PC        TCC        Saga+Lock  Saga    │
  │  (ACID)     (Atomic)   (Reserved) (Eventual  (Eventual)
  │                                    +Isolated)         │
  └──────────────────────────────────────────────────────┘
```

### 4.2 详细对比

| 维度 | Layer 1: Local TX | Layer 3: 2PC | Layer 4: TCC | Layer 5: Saga |
|------|-------------------|--------------|--------------|---------------|
| **一致性** | 强一致（ACID） | 原子提交（最强跨库） | 最终一致（资源隔离） | 最终一致 |
| **隔离性** | DB 隔离级别 | DB 隔离级别 | 业务层隔离（reserved 状态） | Semantic Lock（可选） |
| **持久性** | DB WAL | PREPARE TX 持久化 | 状态持久化到 DB | 状态持久化到 DB |
| **性能** | 毫秒级 | 秒级（阻塞） | 秒级（非阻塞） | 秒~分钟级 |
| **并发影响** | DB 行锁 | DB 行锁（PREPARE 期间） | 无 DB 锁（业务锁） | Semantic Lock |
| **适用范围** | 单数据库 | 跨 PostgreSQL 数据库 | 任意服务 | 任意服务 |
| **失败处理** | 自动回滚 | 自动回滚 | 自动 Cancel | 补偿操作 |
| **崩溃恢复** | DB 自动恢复 | Coordinator 恢复 | 超时自动 Cancel | Orchestrator 恢复 |

### 4.3 选择原则

```
是否跨数据库？
├── 否 → Layer 1: Local Transaction
└── 是 → 是否要求原子提交（绝不容忍中间状态）？
    ├── 是 → Layer 3: 2PC Coordinator
    └── 否 → 是否涉及资源预留（弧段/设备/余额冻结）？
        ├── 是 → Layer 4: TCC Coordinator
        └── 否 → Layer 5: Saga Orchestrator
            └── 是否需要隔离性？
                ├── 是 → Saga + Semantic Lock
                └── 否 → Saga（基础模式）

是否涉及 DB 写入 + 消息发送？
├── 是 → 必须使用 Layer 2: Outbox（与上述任何层组合使用）
└── 否 → 不需要 Outbox
```

---

## 5. Layer 1: Local Transaction Engine

### 5.1 概述

Local Transaction Engine 是整个框架的基石。它增强了 SeaORM 原生事务，增加了三项关键能力：

1. **TransactionContext** —— 携带事务元数据和钩子的上下文对象
2. **Savepoints** —— 嵌套事务，内层失败不影响外层
3. **Transaction Hooks** —— after-commit / on-rollback 回调

### 5.2 核心类型

```rust
/// 事务上下文 —— 是所有事务操作的入口
pub struct TransactionContext<'txn> {
    txn: &'txn DatabaseTransaction,
    hooks: TransactionHooks,
    savepoint_counter: AtomicU32,
}

impl<'txn> TransactionContext<'txn> {
    /// 获取底层 SeaORM 事务引用
    /// 所有 repository 操作通过此引用在事务内执行
    pub fn txn(&self) -> &'txn DatabaseTransaction;

    /// 注册 after-commit 钩子
    /// 事务成功提交后异步执行，失败不影响事务结果
    pub fn after_commit<F>(&mut self, hook: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static;

    /// 注册 on-rollback 钩子
    /// 事务回滚后异步执行
    pub fn on_rollback<F>(&mut self, hook: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static;

    /// 创建 savepoint（嵌套事务点）
    pub async fn savepoint<T, F>(&mut self, name: &str, op: F) -> Result<T>
    where
        F: FnOnce(&DatabaseTransaction) -> BoxFuture<'_, Result<T>> + Send;
}
```

```rust
/// 事务执行器 —— 增强版，支持 TransactionContext
pub async fn execute<T, F>(db: &DatabaseConnection, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: for<'txn> FnOnce(&mut TransactionContext<'txn>)
        -> BoxFuture<'txn, Result<T>> + Send + 'static;
```

### 5.3 使用方式

#### 5.3.1 基础用法：单库多表事务

```rust
use warpin_transaction::local;

// 场景：更新任务状态 + 释放弧段（同一个数据库）
let task = local::execute(&db, |ctx| Box::pin(async move {
    // 两个操作在同一个事务中，要么全成功，要么全回滚
    let task = task_repo.update_status(ctx.txn(), task_id, "completed").await?;
    arc_segment_repo.release(ctx.txn(), task.arc_segment_id).await?;
    Ok(task)
})).await?;
```

#### 5.3.2 使用事务钩子：提交后发通知

```rust
use warpin_transaction::local;

let task = local::execute(&db, |ctx| Box::pin(async move {
    let task = task_repo.update_status(ctx.txn(), task_id, "completed").await?;
    arc_segment_repo.release(ctx.txn(), task.arc_segment_id).await?;

    // 注册 after-commit 钩子
    // 只有事务成功提交后才会执行，不会在回滚时触发
    let task_clone = task.clone();
    let bus = event_bus.clone();
    ctx.after_commit(move || Box::pin(async move {
        let event = BusEvent::new(
            "ttc.task.status",
            &task_clone.trace_id,
            &task_clone.tenant_id,
            serde_json::to_string(&task_clone).unwrap(),
        );
        if let Err(e) = bus.publish(event).await {
            tracing::error!(error = %e, "after-commit hook: failed to publish event");
        }
    }));

    // 注册 on-rollback 钩子（可选）
    ctx.on_rollback(|| Box::pin(async {
        tracing::warn!("task completion rolled back, no notification sent");
    }));

    Ok(task)
})).await?;
```

#### 5.3.3 使用 Savepoint：批量操作部分失败

```rust
use warpin_transaction::local;

// 场景：批量导入遥测记录，单条失败不影响整批
let result = local::execute(&db, |ctx| Box::pin(async move {
    let mut imported = Vec::new();
    let mut failed = Vec::new();

    for record in &records {
        let sp_result = ctx.savepoint(
            &format!("import_{}", record.id),
            |txn| Box::pin(async move {
                telemetry_repo.insert(txn, record.clone()).await
            })
        ).await;

        match sp_result {
            Ok(saved) => imported.push(saved),
            Err(e) => {
                // savepoint 回滚，外层事务不受影响
                tracing::warn!(
                    record_id = %record.id,
                    error = %e,
                    "import failed, savepoint rolled back"
                );
                failed.push((record.id, e.to_string()));
            }
        }
    }

    Ok(ImportResult { imported, failed })
})).await?;
```

#### 5.3.4 兼容旧 API

```rust
// 如果不需要 hooks 和 savepoint，可以继续使用原始 API
use warpin_storage::run_in_transaction;

let task = run_in_transaction(&db, |txn| Box::pin(async move {
    task_repo.update_status(txn, task_id, "completed").await
})).await?;
```

---

## 6. Layer 2: Transactional Outbox + CDC

### 6.1 概述

Transactional Outbox 解决的核心问题是：**如何保证 "DB 写入" 和 "消息发送" 的原子性？**

传统方式（先写 DB，再发 Kafka）在 Kafka 不可用时会导致数据不一致。Outbox 模式将事件写入与业务数据写入放在同一个数据库事务中，由后台进程（Relay）异步发布到消息队列。

warpin-transaction 提供两种 Relay 实现：

| Relay 类型 | 原理 | 延迟 | 可靠性 | 推荐场景 |
|-----------|------|------|--------|---------|
| **CDC Relay** | 基于 PostgreSQL WAL logical replication | < 100ms | 最高（WAL 持久化） | 生产环境主选 |
| **Polling Relay** | 定时扫描 outbox 表 | 秒级 | 高（依赖数据库） | 开发环境 / CDC 不可用时降级 |

### 6.2 核心类型

```rust
/// Outbox 事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub id: Uuid,
    pub aggregate_type: String,        // "task", "bill"
    pub aggregate_id: String,          // 业务聚合根 ID
    pub event_type: String,            // "task.completed"
    pub topic: String,                 // Kafka topic
    pub partition_key: String,         // Kafka partition key
    pub payload: serde_json::Value,    // 事件载荷
    pub metadata: EventMetadata,       // 追踪元数据
    pub status: OutboxStatus,
    pub retry_count: i32,
    pub max_retries: i32,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub trace_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub causation_id: Option<String>,   // 引发此事件的前序事件 ID
    pub correlation_id: Option<String>, // 业务流程关联 ID
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OutboxStatus {
    Pending,       // 待发布
    Published,     // 已发布
    Failed,        // 发布失败（将重试）
    DeadLetter,    // 超过最大重试次数
}

/// 创建 Outbox 事件的 DTO
#[derive(Debug, Clone)]
pub struct OutboxEventCreate {
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub topic: String,
    pub partition_key: String,
    pub payload: serde_json::Value,
    pub metadata: EventMetadata,
    pub max_retries: Option<i32>,       // 默认 5
}
```

```rust
/// 事务性发布者 —— 在数据库事务内写入 outbox 表
pub struct TransactionalPublisher {
    repo: OutboxRepository,
}

impl TransactionalPublisher {
    pub fn new(db: Arc<DatabaseConnection>) -> Self;

    /// 在事务内发布单个事件
    pub async fn publish_in_tx(
        &self,
        txn: &DatabaseTransaction,
        event: OutboxEventCreate,
    ) -> Result<Uuid>;

    /// 在事务内批量发布
    pub async fn publish_batch_in_tx(
        &self,
        txn: &DatabaseTransaction,
        events: Vec<OutboxEventCreate>,
    ) -> Result<Vec<Uuid>>;
}
```

```rust
/// Outbox Relay trait
#[async_trait]
pub trait OutboxRelay: Send + Sync {
    async fn start(&self, shutdown: CancellationToken) -> Result<()>;
    async fn poll_once(&self) -> Result<RelayResult>;
    async fn health(&self) -> RelayHealth;
}

/// Runtime-switchable Relay
pub enum OutboxRelayImpl {
    Cdc(CdcRelay),
    Polling(PollingRelay),
}

#[async_trait]
impl OutboxRelay for OutboxRelayImpl { /* delegate */ }

pub struct RelayResult {
    pub published: usize,
    pub failed: usize,
    pub remaining: usize,
}

pub struct RelayHealth {
    pub is_running: bool,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub events_behind: u64,
}
```

```rust
/// CDC Relay 配置
#[derive(Debug, Clone, Deserialize)]
pub struct CdcConfig {
    pub slot_name: String,              // 默认 "warpin_outbox_slot"
    pub publication_name: String,       // 默认 "warpin_outbox_pub"
    pub poll_interval: Duration,        // WAL 消费间隔，默认 100ms
    pub max_batch_size: u32,            // 默认 500
    pub status_update_interval: Duration, // LSN 确认间隔，默认 10s
}

/// Polling Relay 配置
#[derive(Debug, Clone, Deserialize)]
pub struct PollingRelayConfig {
    pub poll_interval: Duration,        // 轮询间隔，默认 1s
    pub batch_size: u32,                // 每次拉取数量，默认 100
    pub max_retries: i32,               // 最大重试次数，默认 5
    pub retry_backoff_base: Duration,   // 退避基础间隔，默认 10s
    pub cleanup_after: Duration,        // 已发布事件保留时间，默认 7 天
}
```

```rust
/// 幂等消费者 —— 消费端去重
pub struct IdempotentConsumer<H: EventHandler> {
    consumer: EventConsumerImpl,
    handler: H,
    dedup_repo: ConsumedEventRepository,
    db: Arc<DatabaseConnection>,
    config: IdempotentConsumerConfig,
}

/// 事件处理器 trait —— 业务项目实现
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// 在本地事务内处理事件
    /// 事件去重 + 业务处理在同一个事务中完成
    async fn handle(
        &self,
        txn: &DatabaseTransaction,
        event: &ConsumedEvent,
    ) -> Result<()>;
}

pub struct ConsumedEvent {
    pub id: Uuid,
    pub topic: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub metadata: EventMetadata,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdempotentConsumerConfig {
    pub max_processing_time: Duration,  // 单条事件最大处理时间，默认 30s
    pub dead_letter_topic: Option<String>, // 死信 topic
}
```

### 6.3 使用方式

#### 6.3.1 生产者：事务内写 Outbox（替代直接发 Kafka）

```rust
use warpin_transaction::{local, outbox::*};

// 创建 TransactionalPublisher
let publisher = TransactionalPublisher::new(db.clone());

// 场景：完成任务 + 可靠发送事件
let task = local::execute(&db, |ctx| Box::pin(async move {
    // Step 1: 更新任务状态
    let task = task_repo.update_status(ctx.txn(), task_id, "completed").await?;

    // Step 2: 释放弧段
    arc_segment_repo.release(ctx.txn(), task.arc_segment_id).await?;

    // Step 3: 写入 Outbox（在同一个事务中！）
    //         不再直接调用 event_bus.publish()
    publisher.publish_in_tx(ctx.txn(), OutboxEventCreate {
        aggregate_type: "task".into(),
        aggregate_id: task_id.to_string(),
        event_type: "task.completed".into(),
        topic: "ttc.task.status".into(),
        partition_key: task.trace_id.clone(),
        payload: serde_json::to_value(&TaskCompletedPayload {
            task_id,
            completed_at: Utc::now(),
            result_summary: task.result_summary.clone(),
        })?,
        metadata: EventMetadata {
            trace_id: task.trace_id.clone(),
            tenant_id: task.tenant_id.clone(),
            actor_id: "system".into(),
            causation_id: None,
            correlation_id: Some(task.correlation_id.clone()),
        },
        max_retries: None, // 使用默认值 5
    }).await?;

    Ok(task)
    // 事务提交时：task 更新 + arc_segment 释放 + outbox 写入 全部原子提交
    // 事务回滚时：三个操作全部回滚，不会有脏事件
})).await?;
```

#### 6.3.2 启动 Relay（服务启动时配置）

```rust
use warpin_transaction::outbox::*;

// ── 方式 A: CDC Relay（生产环境推荐）──
let cdc_relay = CdcRelay::new(
    db.clone(),
    event_bus.clone(),
    CdcConfig {
        slot_name: "ttc_scheduler_outbox_slot".into(),
        publication_name: "ttc_scheduler_outbox_pub".into(),
        poll_interval: Duration::from_millis(100),
        max_batch_size: 500,
        status_update_interval: Duration::from_secs(10),
    },
)?;

// ── 方式 B: Polling Relay（开发环境 / 降级）──
let polling_relay = PollingRelay::new(
    db.clone(),
    event_bus.clone(),
    PollingRelayConfig {
        poll_interval: Duration::from_secs(1),
        batch_size: 100,
        max_retries: 5,
        retry_backoff_base: Duration::from_secs(10),
        cleanup_after: Duration::from_secs(7 * 24 * 3600),
    },
);

// ── 使用 enum union 进行运行时切换 ──
let relay: OutboxRelayImpl = if config.outbox.use_cdc {
    OutboxRelayImpl::Cdc(cdc_relay)
} else {
    OutboxRelayImpl::Polling(polling_relay)
};

// 启动 Relay 后台任务
let shutdown = CancellationToken::new();
tokio::spawn({
    let relay = relay.clone();
    let shutdown = shutdown.clone();
    async move {
        if let Err(e) = relay.start(shutdown).await {
            tracing::error!(error = %e, "outbox relay terminated with error");
        }
    }
});
```

#### 6.3.3 消费者：幂等消费（exactly-once 语义）

```rust
use warpin_transaction::outbox::*;

// Step 1: 实现 EventHandler trait
struct TaskEventHandler {
    telemetry_repo: TelemetryRepository,
}

#[async_trait]
impl EventHandler for TaskEventHandler {
    async fn handle(
        &self,
        txn: &DatabaseTransaction,
        event: &ConsumedEvent,
    ) -> Result<()> {
        match event.event_type.as_str() {
            "task.completed" => {
                let payload: TaskCompletedPayload =
                    serde_json::from_value(event.payload.clone())?;
                // 在事务内处理（去重记录也在这个事务中）
                self.telemetry_repo
                    .mark_task_completed(txn, payload.task_id)
                    .await?;
            }
            _ => {
                tracing::debug!(event_type = %event.event_type, "unhandled event");
            }
        }
        Ok(())
    }
}

// Step 2: 创建幂等消费者并启动
let handler = TaskEventHandler { telemetry_repo };
let consumer = IdempotentConsumer::new(
    event_consumer,    // warpin-event-bus 的 EventConsumerImpl
    handler,
    db.clone(),
    IdempotentConsumerConfig {
        max_processing_time: Duration::from_secs(30),
        dead_letter_topic: Some("ttc.dead-letter".into()),
    },
);

tokio::spawn({
    let shutdown = shutdown.clone();
    async move {
        if let Err(e) = consumer.start(shutdown).await {
            tracing::error!(error = %e, "idempotent consumer terminated");
        }
    }
});
```

#### 6.3.4 Exactly-Once 完整流程

```
Producer (scheduler-service)              Consumer (dataflow-service)
──────────────────────────                ────────────────────────────
BEGIN TX
  UPDATE tasks SET status='completed'
  INSERT outbox_events (id=E1, ...)
COMMIT
        │
   [CDC Relay reads WAL]
        │
   Kafka ─── ttc.task.status ──────────►  IdempotentConsumer.recv()
                                          BEGIN TX
                                            SELECT id FROM consumed_events
                                              WHERE event_id = 'E1'
                                              → NOT FOUND (首次)
                                            INSERT consumed_events (E1)
                                            handler.handle(txn, event)
                                              → telemetry_repo.mark_completed(txn, ...)
                                          COMMIT
                                          consumer.ack()

                                          // Kafka 重投递（网络抖动）
                                          IdempotentConsumer.recv() again
                                          BEGIN TX
                                            SELECT id FROM consumed_events
                                              WHERE event_id = 'E1'
                                              → FOUND (重复!)
                                            SKIP processing
                                          COMMIT
                                          consumer.ack()
```

#### 6.3.5 CDC Relay 的 PostgreSQL 前置配置

```sql
-- DBA 需要执行以下配置（每个数据库一次）

-- 1. 启用 logical replication（需要重启 PostgreSQL）
ALTER SYSTEM SET wal_level = 'logical';
ALTER SYSTEM SET max_replication_slots = 10;
ALTER SYSTEM SET max_wal_senders = 10;

-- 2. 创建 publication（每个服务数据库一次）
CREATE PUBLICATION warpin_outbox_pub FOR TABLE outbox_events;

-- 3. 验证
SELECT * FROM pg_publication WHERE pubname = 'warpin_outbox_pub';
```

Polling Relay 不需要额外 PostgreSQL 配置，开箱即用。

---

## 7. Layer 3: 2PC Coordinator

### 7.1 概述

2PC（Two-Phase Commit）协调器提供跨数据库的原子提交能力。这是所有跨库事务方案中一致性最强的。

**关键实现**：利用 PostgreSQL 原生的 `PREPARE TRANSACTION` / `COMMIT PREPARED` 机制，不是应用层模拟。

**状态机**：

```
Init ──► Preparing ──► Prepared ──► Committing ──► Committed
                  │                         │
                  └──► Aborting ──► Aborted ◄┘ (commit 失败 → 不可能，
                                                prepared TX 的 commit 必须成功)
```

### 7.2 核心类型

```rust
/// 2PC 参与者 trait —— 业务项目或远程服务实现
#[async_trait]
pub trait TwoPcParticipant: Send + Sync {
    /// 参与者名称
    fn name(&self) -> &str;

    /// Phase 1: Prepare
    /// 执行业务操作并进入 prepared 状态
    async fn prepare(&self, ctx: &TwoPcContext) -> Result<PrepareResult>;

    /// Phase 2a: Commit
    /// 提交 prepared transaction
    async fn commit(&self, ctx: &TwoPcContext) -> Result<()>;

    /// Phase 2b: Rollback
    /// 回滚 prepared transaction
    async fn rollback(&self, ctx: &TwoPcContext) -> Result<()>;

    /// Recovery: 查询 prepared transaction 状态
    async fn recover(&self, xid: &str) -> Result<ParticipantRecoveryStatus>;
}

#[derive(Debug, Clone)]
pub struct TwoPcContext {
    pub xid: String,                  // 全局事务 ID
    pub tenant_id: String,
    pub trace_id: String,
    pub timeout: Duration,
    pub payload: serde_json::Value,   // 业务参数
}

#[derive(Debug)]
pub enum PrepareResult {
    Ready,                  // 准备就绪
    ReadOnly,               // 只读参与者
    Refused(String),        // 拒绝（业务校验失败）
}

#[derive(Debug)]
pub enum ParticipantRecoveryStatus {
    Prepared,     // 仍在 prepared 状态
    Committed,    // 已提交
    RolledBack,   // 已回滚
    Unknown,      // 未找到
}
```

```rust
/// PostgreSQL 原生 2PC 参与者
pub struct PgTwoPcParticipant<F> {
    name: String,
    db: Arc<DatabaseConnection>,
    operation: F,    // 业务操作闭包
}

impl<F> PgTwoPcParticipant<F> {
    pub fn new(
        name: impl Into<String>,
        db: Arc<DatabaseConnection>,
        operation: F,
    ) -> Self;
}
```

```rust
/// gRPC 远程参与者代理
/// 当参与者是远程微服务时使用
pub struct GrpcTwoPcParticipant {
    name: String,
    endpoint: String,
    timeout: Duration,
}
```

```rust
/// 2PC 协调器
pub struct TwoPcCoordinator {
    repo: TwoPcRepository,
    lock_manager: Arc<dyn DistributedLock>,
    config: TwoPcConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwoPcConfig {
    pub prepare_timeout: Duration,           // 默认 10s
    pub commit_retry_interval: Duration,     // 默认 1s
    pub commit_max_retries: u32,             // 默认 u32::MAX（无限）
    pub abort_timeout: Duration,             // 默认 30s
    pub recovery_scan_interval: Duration,    // 默认 60s
}

#[derive(Debug)]
pub enum TwoPcOutcome {
    Committed,
    Aborted { reason: String },
}

/// 管理员手动决议
#[derive(Debug)]
pub enum ForceDecision {
    ForceCommit,
    ForceRollback,
}

impl TwoPcCoordinator {
    pub fn new(
        db: Arc<DatabaseConnection>,
        lock_manager: Arc<dyn DistributedLock>,
        config: TwoPcConfig,
    ) -> Self;

    /// 执行 2PC 分布式事务
    pub async fn execute(
        &self,
        xid: impl Into<String>,
        participants: Vec<Arc<dyn TwoPcParticipant>>,
        payload: serde_json::Value,
        tenant_id: String,
        trace_id: String,
    ) -> Result<TwoPcOutcome>;

    /// 启动崩溃恢复后台任务
    pub async fn start_recovery(
        &self,
        shutdown: CancellationToken,
    ) -> Result<()>;

    /// 手动解决 in-doubt 事务（管理员 API）
    pub async fn force_resolve(
        &self,
        xid: &str,
        decision: ForceDecision,
    ) -> Result<()>;

    /// 列出所有 in-doubt 事务（管理员 API）
    pub async fn list_in_doubt(&self) -> Result<Vec<TwoPcExecution>>;
}
```

### 7.3 使用方式

#### 7.3.1 跨库原子提交（本地多数据库）

```rust
use warpin_transaction::twopc::*;

// 场景：scheduler DB 更新任务状态 + customer DB 生成账单
// 两个操作必须原子完成，不容忍任何不一致

// Step 1: 定义参与者
let scheduler_participant = PgTwoPcParticipant::new(
    "scheduler",
    scheduler_db.clone(),
    |txn: &DatabaseTransaction, payload: &serde_json::Value| {
        Box::pin(async move {
            let task_id: Uuid = serde_json::from_value(payload["task_id"].clone())?;
            task_repo.update_status(txn, task_id, "billed").await?;
            Ok(())
        })
    },
);

let customer_participant = PgTwoPcParticipant::new(
    "customer",
    customer_db.clone(),
    |txn: &DatabaseTransaction, payload: &serde_json::Value| {
        Box::pin(async move {
            let bill: CreateBillDto = serde_json::from_value(payload["bill"].clone())?;
            bill_repo.create(txn, bill).await?;
            Ok(())
        })
    },
);

// Step 2: 通过协调器执行 2PC
let coordinator = TwoPcCoordinator::new(
    coordinator_db.clone(),    // 协调器自己的数据库连接
    lock_manager.clone(),
    TwoPcConfig::default(),
);

let outcome = coordinator.execute(
    format!("task_billing_{}", task_id),    // 全局事务 ID
    vec![
        Arc::new(scheduler_participant),
        Arc::new(customer_participant),
    ],
    serde_json::json!({
        "task_id": task_id,
        "bill": {
            "tenant_id": tenant_id,
            "task_id": task_id,
            "amount": 1500.00,
            "currency": "CNY",
        }
    }),
    tenant_id.to_string(),
    trace_id.to_string(),
).await?;

match outcome {
    TwoPcOutcome::Committed => {
        tracing::info!("2PC committed: task billed successfully");
    }
    TwoPcOutcome::Aborted { reason } => {
        tracing::warn!(reason = %reason, "2PC aborted");
    }
}
```

#### 7.3.2 跨服务原子提交（通过 gRPC）

```rust
use warpin_transaction::twopc::*;

// 场景：本地 DB 操作 + 远程服务 DB 操作的原子提交
// 远程服务需要实现 TwoPcService gRPC 接口

let local_participant = PgTwoPcParticipant::new(
    "local_scheduler",
    scheduler_db.clone(),
    |txn, payload| Box::pin(async move {
        // 本地业务操作
        Ok(())
    }),
);

let remote_participant = GrpcTwoPcParticipant::new(
    "remote_customer",
    "http://customer-service:7401",
    Duration::from_secs(10),
);

let outcome = coordinator.execute(
    format!("cross_svc_{}", Uuid::new_v4()),
    vec![
        Arc::new(local_participant),
        Arc::new(remote_participant),
    ],
    payload,
    tenant_id,
    trace_id,
).await?;
```

#### 7.3.3 崩溃恢复

```rust
// 在服务启动时，启动 2PC Recovery Manager
// 它会扫描所有未完成的 2PC 事务，驱动到终态
tokio::spawn({
    let coordinator = coordinator.clone();
    let shutdown = shutdown.clone();
    async move {
        if let Err(e) = coordinator.start_recovery(shutdown).await {
            tracing::error!(error = %e, "2PC recovery manager terminated");
        }
    }
});
```

#### 7.3.4 管理员手动干预

```rust
// 查看所有 in-doubt 事务
let in_doubt = coordinator.list_in_doubt().await?;
for tx in &in_doubt {
    tracing::warn!(
        xid = %tx.xid,
        status = ?tx.status,
        started_at = %tx.started_at,
        "in-doubt transaction found"
    );
}

// 手动强制提交或回滚
coordinator.force_resolve(
    "task_billing_xxx",
    ForceDecision::ForceCommit,
).await?;
```

#### 7.3.5 PostgreSQL 前置配置

```sql
-- 必须：启用 prepared transactions
-- 默认值为 0（禁用），需要设置为 > 0
ALTER SYSTEM SET max_prepared_transactions = 100;
-- 需要重启 PostgreSQL 生效

-- 验证
SHOW max_prepared_transactions;  -- 应该 > 0

-- 查看当前 prepared transactions
SELECT * FROM pg_prepared_xacts;

-- 手动清理悬挂的 prepared transaction（紧急情况）
-- ROLLBACK PREPARED 'xid_name';
```

### 7.4 2PC 协调时序

```
时间 →
─────────────────────────────────────────────────────────────────────────

Coordinator:  [persist PREPARING] ──► [prepare A] ──► [prepare B]
                                          │               │
Participant A:                    BEGIN ──► SQL ──► PREPARE TX 'xid_a'
                                                        │
Participant B:                                   BEGIN ──► SQL ──► PREPARE TX 'xid_b'
                                                                      │
Coordinator:  ◄── Ready ◄── Ready ──► [persist COMMITTING (决议!)]     │
                                          │                            │
              │ (即使此刻 Coordinator 崩溃，重启后也能从这个状态恢复)      │
                                          │                            │
Coordinator:  ──► [commit A] ──► [commit B] ──► [persist COMMITTED]
                      │               │
Participant A:  COMMIT PREPARED 'xid_a'
                                      │
Participant B:              COMMIT PREPARED 'xid_b'
```

**关键保证**：一旦 Coordinator 持久化了 `COMMITTING` 状态（决议），即使任何参与者暂时不可达，Coordinator 也会无限重试 commit，因为 PostgreSQL 的 `PREPARE TRANSACTION` 是持久化的，不会因为 session 断开而丢失。

---

## 8. Layer 4: TCC Coordinator

### 8.1 概述

TCC（Try-Confirm-Cancel）是一种基于业务层资源预留的分布式事务模式。与 2PC 相比：

| 维度 | 2PC | TCC |
|------|-----|-----|
| 锁的位置 | 数据库行锁（`PREPARE TRANSACTION` 持有） | 业务层状态标记（`reserved`） |
| 阻塞 | 是（DB 行锁阻塞其他事务） | 否（只修改状态字段） |
| 适用范围 | 仅 PostgreSQL | 任意服务（HTTP/gRPC/本地） |
| 一致性 | 原子（最强） | 最终一致（Try 和 Confirm 之间有窗口） |
| 典型场景 | 跨库转账 | 弧段预留 + 设备分配 |

**TCC 核心思想**：将一个大操作拆为三步：
1. **Try**：预留资源（冻结余额、标记弧段为 "reserved"）
2. **Confirm**：确认预留（扣减余额、标记弧段为 "allocated"）
3. **Cancel**：取消预留（解冻余额、恢复弧段为 "available"）

### 8.2 核心类型

```rust
/// TCC 参与者 trait
#[async_trait]
pub trait TccParticipant: Send + Sync {
    fn name(&self) -> &str;

    /// Try: 资源预留
    ///
    /// 要求：
    /// - 业务校验（资源是否可用、额度是否充足）
    /// - 将资源状态标记为 "reserved"（预留，非最终确认）
    /// - 不可产生不可逆副作用
    /// - 返回 ReservationToken 供后续 Confirm/Cancel 使用
    async fn try_reserve(&self, ctx: &TccContext) -> Result<ReservationToken>;

    /// Confirm: 确认提交
    ///
    /// 要求：
    /// - 必须幂等（重复调用结果相同）
    /// - 不允许因业务原因失败（Try 成功则 Confirm 必须成功）
    /// - 将 "reserved" 转为 "confirmed/allocated"
    async fn confirm(
        &self,
        ctx: &TccContext,
        token: &ReservationToken,
    ) -> Result<()>;

    /// Cancel: 取消预留
    ///
    /// 要求：
    /// - 必须幂等
    /// - 将 "reserved" 恢复为 "available"
    /// - 释放所有冻结的资源
    async fn cancel(
        &self,
        ctx: &TccContext,
        token: &ReservationToken,
    ) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccContext {
    pub tx_id: Uuid,
    pub tenant_id: String,
    pub trace_id: String,
    pub payload: serde_json::Value,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationToken {
    pub participant_name: String,
    pub resource_id: String,
    pub reservation_data: serde_json::Value,
    pub reserved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub fencing_token: u64,
}
```

```rust
/// TCC 协调器
pub struct TccCoordinator {
    repo: TccRepository,
    lock_manager: Arc<dyn DistributedLock>,
    fencing: FencingTokenIssuer,
    config: TccConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TccConfig {
    pub try_timeout: Duration,            // 单个 Try 超时，默认 5s
    pub global_timeout: Duration,         // 全局超时，默认 30s
    pub confirm_cancel_retry_interval: Duration, // 默认 1s
    pub confirm_cancel_max_retries: u32,  // 默认 u32::MAX
    pub reservation_ttl: Duration,        // 预留有效期，默认 5min
}

#[derive(Debug)]
pub enum TccOutcome {
    Confirmed { tokens: Vec<ReservationToken> },
    Cancelled { reason: String },
    TimedOut { reason: String },
}

impl TccCoordinator {
    pub fn new(
        db: Arc<DatabaseConnection>,
        lock_manager: Arc<dyn DistributedLock>,
        config: TccConfig,
    ) -> Self;

    /// 执行 TCC 分布式事务
    pub async fn execute(
        &self,
        participants: Vec<Arc<dyn TccParticipant>>,
        context: TccContext,
    ) -> Result<TccOutcome>;

    /// 启动超时扫描后台任务
    pub async fn start_timeout_scanner(
        &self,
        shutdown: CancellationToken,
    ) -> Result<()>;

    /// 列出所有超时未决的 TCC 事务
    pub async fn list_timed_out(&self) -> Result<Vec<TccExecution>>;
}
```

### 8.3 使用方式

#### 8.3.1 资源预留场景：弧段 + 设备

```rust
use warpin_transaction::tcc::*;

// Step 1: 实现 TCC 参与者

/// 弧段预留参与者
struct ArcSegmentReservation {
    repo: ArcSegmentRepository,
}

#[async_trait]
impl TccParticipant for ArcSegmentReservation {
    fn name(&self) -> &str { "arc_segment" }

    async fn try_reserve(&self, ctx: &TccContext) -> Result<ReservationToken> {
        let segment_id: Uuid = serde_json::from_value(
            ctx.payload["segment_id"].clone()
        )?;

        // 检查弧段是否空闲
        let segment = self.repo.find_by_id(segment_id).await?
            .ok_or_else(|| anyhow!("arc segment not found"))?;

        if segment.status != "available" {
            return Err(anyhow!("arc segment not available: {}", segment.status));
        }

        // 标记为 reserved（不是 allocated！）
        self.repo.update_status(segment_id, "reserved").await?;

        Ok(ReservationToken {
            participant_name: "arc_segment".into(),
            resource_id: segment_id.to_string(),
            reservation_data: serde_json::json!({
                "previous_status": segment.status,
            }),
            reserved_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            fencing_token: ctx.payload["fencing_token"].as_u64().unwrap_or(0),
        })
    }

    async fn confirm(&self, _ctx: &TccContext, token: &ReservationToken) -> Result<()> {
        let segment_id: Uuid = token.resource_id.parse()?;
        // reserved → allocated（幂等：如果已经是 allocated，直接返回 Ok）
        self.repo.confirm_reservation(segment_id).await
    }

    async fn cancel(&self, _ctx: &TccContext, token: &ReservationToken) -> Result<()> {
        let segment_id: Uuid = token.resource_id.parse()?;
        let previous: String = serde_json::from_value(
            token.reservation_data["previous_status"].clone()
        )?;
        // reserved → 恢复原状态（幂等）
        self.repo.cancel_reservation(segment_id, &previous).await
    }
}

/// 设备分配参与者
struct DeviceAllocation {
    repo: DeviceRepository,
}

#[async_trait]
impl TccParticipant for DeviceAllocation {
    fn name(&self) -> &str { "device" }

    async fn try_reserve(&self, ctx: &TccContext) -> Result<ReservationToken> {
        let device_id: Uuid = serde_json::from_value(
            ctx.payload["device_id"].clone()
        )?;
        // 检查设备是否空闲 → 标记为 reserved
        self.repo.reserve_device(device_id).await?;
        Ok(ReservationToken {
            participant_name: "device".into(),
            resource_id: device_id.to_string(),
            reservation_data: serde_json::json!({}),
            reserved_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            fencing_token: 0,
        })
    }

    async fn confirm(&self, _ctx: &TccContext, token: &ReservationToken) -> Result<()> {
        let device_id: Uuid = token.resource_id.parse()?;
        self.repo.confirm_device_allocation(device_id).await
    }

    async fn cancel(&self, _ctx: &TccContext, token: &ReservationToken) -> Result<()> {
        let device_id: Uuid = token.resource_id.parse()?;
        self.repo.release_device(device_id).await
    }
}

// Step 2: 通过协调器执行 TCC
let coordinator = TccCoordinator::new(
    coordinator_db.clone(),
    lock_manager.clone(),
    TccConfig::default(),
);

let outcome = coordinator.execute(
    vec![
        Arc::new(ArcSegmentReservation { repo: arc_repo }),
        Arc::new(DeviceAllocation { repo: device_repo }),
    ],
    TccContext {
        tx_id: Uuid::new_v4(),
        tenant_id: tenant_id.to_string(),
        trace_id: trace_id.to_string(),
        payload: serde_json::json!({
            "segment_id": segment_id,
            "device_id": device_id,
        }),
        timeout: Duration::from_secs(30),
    },
).await?;

match outcome {
    TccOutcome::Confirmed { tokens } => {
        tracing::info!(
            tokens = ?tokens.iter().map(|t| &t.resource_id).collect::<Vec<_>>(),
            "TCC confirmed: resources allocated"
        );
    }
    TccOutcome::Cancelled { reason } => {
        tracing::warn!(reason = %reason, "TCC cancelled");
    }
    TccOutcome::TimedOut { reason } => {
        tracing::error!(reason = %reason, "TCC timed out");
    }
}
```

#### 8.3.2 TCC + Outbox 组合使用

```rust
// TCC 确认后，通过 Outbox 可靠发送事件
match outcome {
    TccOutcome::Confirmed { tokens } => {
        // TCC 成功后，在本地事务中写 Outbox
        local::execute(&db, |ctx| Box::pin(async move {
            publisher.publish_in_tx(ctx.txn(), OutboxEventCreate {
                aggregate_type: "task".into(),
                aggregate_id: task_id.to_string(),
                event_type: "task.resources_allocated".into(),
                topic: "ttc.task.status".into(),
                partition_key: trace_id.clone(),
                payload: serde_json::json!({
                    "task_id": task_id,
                    "segment_id": segment_id,
                    "device_id": device_id,
                }),
                metadata: EventMetadata { /* ... */ },
                max_retries: None,
            }).await?;
            Ok(())
        })).await?;
    }
    _ => { /* handle failure */ }
}
```

### 8.4 TCC 时序图

```
Coordinator                    Participant A (弧段)          Participant B (设备)
     │                              │                            │
     ├─── persist(Trying) ─────────►│                            │
     │                              │                            │
     ├─── try_reserve() ──────────►│                            │
     │                    Check available                        │
     │                    UPDATE status='reserved'               │
     │◄── ReservationToken ────────┤                            │
     │                              │                            │
     ├─── try_reserve() ───────────────────────────────────────►│
     │                                              Check available
     │                                              UPDATE status='reserved'
     │◄── ReservationToken ────────────────────────────────────┤
     │                              │                            │
     ├─── persist(Confirming) ─────►│                            │
     │                              │                            │
     ├─── confirm(token) ─────────►│                            │
     │                    UPDATE status='allocated'              │
     │◄── Ok ──────────────────────┤                            │
     │                              │                            │
     ├─── confirm(token) ──────────────────────────────────────►│
     │                                              UPDATE status='allocated'
     │◄── Ok ──────────────────────────────────────────────────┤
     │                              │                            │
     ├─── persist(Confirmed) ──────►│                            │

--- 如果 Participant B try_reserve 失败: ---

     │◄── Error ───────────────────────────────────────────────┤
     │                              │                            │
     ├─── persist(Cancelling) ─────►│                            │
     │                              │                            │
     ├─── cancel(token_a) ────────►│                            │
     │                    UPDATE status='available' (恢复)       │
     │◄── Ok ──────────────────────┤                            │
     │                              │                            │
     ├─── persist(Cancelled) ──────►│                            │
```

### 8.5 Fencing Token 防护

```
问题场景：
1. TCC Coordinator 发送 confirm(token) 到 Participant
2. 网络超时，Coordinator 认为失败
3. 超时 → Coordinator 发送 cancel(token)
4. 但 confirm 实际已经到达并执行了！
→ confirm 和 cancel 都执行了，数据不一致

Fencing Token 解决方案：
1. Try 阶段：Coordinator 获取 fencing_token（单调递增）
2. Confirm/Cancel 时携带 fencing_token
3. Participant 检查：
   if incoming_token < last_confirmed_token:
       reject (stale operation)
4. 这样，迟到的 confirm 会被拒绝
```

---

## 9. Layer 5: Saga Orchestrator

### 9.1 概述

Saga 是跨服务长流程编排的最终一致性方案。与 2PC/TCC 相比，Saga 适用于：

- 流程跨越多个服务、耗时较长（秒~分钟级）
- 不需要资源锁定
- 可以接受最终一致性

warpin-transaction 的 Saga 实现包含两项关键增强：

1. **Semantic Locking** —— 解决 Saga 的隔离性问题
2. **Dead Letter + Manual Intervention** —— 补偿失败时的人工干预机制

### 9.2 核心类型

```rust
/// Saga 步骤 trait
#[async_trait]
pub trait SagaStep: Send + Sync {
    /// 步骤名称
    fn name(&self) -> &str;

    /// 声明此步骤需要的 semantic locks
    fn required_locks(&self, input: &serde_json::Value) -> Vec<SemanticLockSpec> {
        vec![]  // 默认不需要
    }

    /// 正向执行
    async fn execute(&self, ctx: &mut SagaContext) -> Result<StepOutput>;

    /// 补偿（逆向操作）
    async fn compensate(&self, ctx: &mut SagaContext) -> Result<()>;

    /// 是否可重试（execute 失败后）
    fn is_retryable(&self) -> bool { true }

    /// 最大重试次数
    fn max_retries(&self) -> u32 { 3 }

    /// 重试间隔
    fn retry_interval(&self) -> Duration { Duration::from_secs(1) }
}

/// Saga 上下文
pub struct SagaContext {
    pub saga_id: Uuid,
    pub tenant_id: String,
    pub trace_id: String,
    pub input: serde_json::Value,
    /// 前序步骤的执行结果
    pub step_results: HashMap<String, serde_json::Value>,
}

impl SagaContext {
    /// 获取前序步骤的结果（类型安全）
    pub fn get_step_result<T: DeserializeOwned>(
        &self,
        step_name: &str,
    ) -> Result<T>;

    /// 获取业务输入（类型安全）
    pub fn input<T: DeserializeOwned>(&self) -> Result<T>;
}

/// 步骤输出
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutput {
    /// 步骤结果数据（传递给后续步骤）
    pub data: serde_json::Value,
    /// 可选：通过 Outbox 可靠发布的事件
    pub events: Vec<OutboxEventCreate>,
}

/// Semantic Lock 规格
#[derive(Debug, Clone)]
pub struct SemanticLockSpec {
    pub resource_type: String,
    pub resource_id: String,
    pub lock_type: SemanticLockType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SemanticLockType {
    Creating,       // 资源正在被创建
    Updating,       // 资源正在被修改
    Deleting,       // 资源正在被删除
}
```

```rust
/// Saga 定义（Builder 模式）
pub struct SagaDefinition {
    name: String,
    steps: Vec<Arc<dyn SagaStep>>,
}

impl SagaDefinition {
    pub fn builder(name: impl Into<String>) -> SagaDefinitionBuilder;
    pub fn name(&self) -> &str;
    pub fn steps(&self) -> &[Arc<dyn SagaStep>];
}

pub struct SagaDefinitionBuilder {
    name: String,
    steps: Vec<Arc<dyn SagaStep>>,
}

impl SagaDefinitionBuilder {
    pub fn step(mut self, step: impl SagaStep + 'static) -> Self;
    pub fn build(self) -> SagaDefinition;
}
```

```rust
/// Saga 执行状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SagaStatus {
    Pending,        // 未开始
    Running,        // 正向执行中
    Compensating,   // 补偿回滚中
    Completed,      // 全部成功
    Failed,         // 补偿完成（业务失败）
    Aborted,        // 补偿也失败（需人工干预）
}

/// Saga 执行记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaExecution {
    pub id: Uuid,
    pub saga_name: String,
    pub status: SagaStatus,
    pub current_step: i32,
    pub total_steps: i32,
    pub input: serde_json::Value,
    pub step_results: HashMap<String, serde_json::Value>,
    pub error_message: Option<String>,
    pub tenant_id: String,
    pub trace_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
```

```rust
/// Dead Letter 钩子
#[async_trait]
pub trait DeadLetterHook: Send + Sync {
    async fn on_saga_aborted(
        &self,
        execution: &SagaExecution,
        error: &str,
    );
}

/// Saga 编排器
pub struct SagaOrchestrator {
    repo: SagaExecutionRepository,
    lock_repo: SemanticLockRepository,
    outbox_writer: Option<TransactionalPublisher>,
    lock_manager: Arc<dyn DistributedLock>,
    config: SagaConfig,
    dead_letter_hook: Option<Arc<dyn DeadLetterHook>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SagaConfig {
    pub step_timeout: Duration,              // 默认 30s
    pub compensation_timeout: Duration,      // 默认 60s
    pub compensation_max_retries: u32,       // 默认 u32::MAX
    pub semantic_lock_ttl: Duration,         // 默认 10min
    pub recovery_scan_interval: Duration,    // 默认 30s
}

impl SagaOrchestrator {
    pub fn new(
        db: Arc<DatabaseConnection>,
        lock_manager: Arc<dyn DistributedLock>,
        config: SagaConfig,
    ) -> Self;

    /// 设置 Outbox 集成
    pub fn with_outbox(self, publisher: TransactionalPublisher) -> Self;

    /// 设置 Dead Letter 钩子
    pub fn with_dead_letter_hook(
        self,
        hook: Arc<dyn DeadLetterHook>,
    ) -> Self;

    /// 启动 Saga
    pub async fn start(
        &self,
        definition: &SagaDefinition,
        input: serde_json::Value,
        tenant_id: String,
        trace_id: String,
    ) -> Result<SagaExecution>;

    /// 恢复中断的 Saga
    pub async fn resume(
        &self,
        saga_id: Uuid,
        definition: &SagaDefinition,
    ) -> Result<SagaExecution>;

    /// 启动恢复后台任务
    pub async fn start_recovery(
        &self,
        shutdown: CancellationToken,
    ) -> Result<()>;

    /// 查询 Saga 状态
    pub async fn get_status(
        &self,
        saga_id: Uuid,
    ) -> Result<Option<SagaExecution>>;

    /// 列出 Dead Letter Saga
    pub async fn list_dead_letters(&self) -> Result<Vec<SagaExecution>>;

    /// 手动重试 Dead Letter Saga
    pub async fn retry_dead_letter(
        &self,
        saga_id: Uuid,
        definition: &SagaDefinition,
    ) -> Result<SagaExecution>;
}
```

### 9.3 使用方式

#### 9.3.1 定义 Saga 步骤

```rust
use warpin_transaction::saga::*;

// ── Step 1: 创建任务 ──
struct CreateTaskStep {
    task_repo: TaskRepository,
}

#[async_trait]
impl SagaStep for CreateTaskStep {
    fn name(&self) -> &str { "create_task" }

    fn required_locks(&self, input: &serde_json::Value) -> Vec<SemanticLockSpec> {
        // 声明：此步骤将创建一个 task 资源
        // Semantic Lock 防止其他 Saga 在此期间修改该资源
        if let Some(task_id) = input.get("task_id").and_then(|v| v.as_str()) {
            vec![SemanticLockSpec {
                resource_type: "task".into(),
                resource_id: task_id.into(),
                lock_type: SemanticLockType::Creating,
            }]
        } else {
            vec![]
        }
    }

    async fn execute(&self, ctx: &mut SagaContext) -> Result<StepOutput> {
        let input: CreateTaskInput = ctx.input()?;

        let task = self.task_repo.create(CreateTaskDto {
            name: input.task_name,
            tenant_id: ctx.tenant_id.clone(),
            status: "saga_pending".into(),  // Semantic: 标记为 saga 处理中
            // ...
        }).await?;

        Ok(StepOutput {
            data: serde_json::to_value(&task)?,
            events: vec![],  // 此步骤不发事件
        })
    }

    async fn compensate(&self, ctx: &mut SagaContext) -> Result<()> {
        let task: Task = ctx.get_step_result("create_task")?;
        self.task_repo.cancel(task.id).await?;
        Ok(())
    }
}

// ── Step 2: 分配弧段 ──
struct AllocateSegmentStep {
    segment_repo: ArcSegmentRepository,
}

#[async_trait]
impl SagaStep for AllocateSegmentStep {
    fn name(&self) -> &str { "allocate_segment" }

    fn required_locks(&self, _input: &serde_json::Value) -> Vec<SemanticLockSpec> {
        // 弧段 ID 要从前序步骤结果中获取，此处无法提前声明
        // 将在 execute 中动态获取
        vec![]
    }

    async fn execute(&self, ctx: &mut SagaContext) -> Result<StepOutput> {
        let task: Task = ctx.get_step_result("create_task")?;

        let segment = self.segment_repo
            .find_available(task.start_time, task.end_time, task.station_id)
            .await?
            .ok_or_else(|| anyhow!("no available arc segment"))?;

        self.segment_repo
            .allocate(segment.id, task.id)
            .await?;

        Ok(StepOutput {
            data: serde_json::to_value(&segment)?,
            events: vec![],
        })
    }

    async fn compensate(&self, ctx: &mut SagaContext) -> Result<()> {
        let segment: ArcSegment = ctx.get_step_result("allocate_segment")?;
        self.segment_repo.release(segment.id).await?;
        Ok(())
    }

    fn max_retries(&self) -> u32 { 0 }  // 弧段分配不重试（可能被别人占用）
}

// ── Step 3: 生成账单 ──
struct CreateBillStep {
    bill_service: BillServiceClient,
}

#[async_trait]
impl SagaStep for CreateBillStep {
    fn name(&self) -> &str { "create_bill" }

    async fn execute(&self, ctx: &mut SagaContext) -> Result<StepOutput> {
        let task: Task = ctx.get_step_result("create_task")?;
        let segment: ArcSegment = ctx.get_step_result("allocate_segment")?;

        let bill = self.bill_service
            .create_bill(task.tenant_id, task.id, segment.duration_minutes)
            .await?;

        Ok(StepOutput {
            data: serde_json::to_value(&bill)?,
            events: vec![
                // Saga 最后一步成功后，通过 Outbox 发布事件
                OutboxEventCreate {
                    aggregate_type: "task".into(),
                    aggregate_id: task.id.to_string(),
                    event_type: "task.fully_scheduled".into(),
                    topic: "ttc.task.status".into(),
                    partition_key: ctx.trace_id.clone(),
                    payload: serde_json::json!({
                        "task_id": task.id,
                        "segment_id": segment.id,
                        "bill_id": bill.id,
                    }),
                    metadata: EventMetadata {
                        trace_id: ctx.trace_id.clone(),
                        tenant_id: ctx.tenant_id.clone(),
                        actor_id: "saga".into(),
                        causation_id: None,
                        correlation_id: Some(ctx.saga_id.to_string()),
                    },
                    max_retries: None,
                },
            ],
        })
    }

    async fn compensate(&self, ctx: &mut SagaContext) -> Result<()> {
        let bill: Bill = ctx.get_step_result("create_bill")?;
        self.bill_service.cancel_bill(bill.id).await?;
        Ok(())
    }
}
```

#### 9.3.2 组装并执行 Saga

```rust
use warpin_transaction::saga::*;

// 定义 Saga
let definition = SagaDefinition::builder("task_scheduling")
    .step(CreateTaskStep { task_repo: task_repo.clone() })
    .step(AllocateSegmentStep { segment_repo: segment_repo.clone() })
    .step(CreateBillStep { bill_service: bill_client.clone() })
    .build();

// 创建编排器
let orchestrator = SagaOrchestrator::new(
    db.clone(),
    lock_manager.clone(),
    SagaConfig::default(),
)
.with_outbox(publisher)
.with_dead_letter_hook(Arc::new(AlertDeadLetterHook { alert_service }));

// 执行 Saga
let execution = orchestrator.start(
    &definition,
    serde_json::json!({
        "task_name": "TTC-2026-001",
        "station_id": station_id,
        "start_time": "2026-04-03T10:00:00Z",
        "end_time": "2026-04-03T10:15:00Z",
    }),
    tenant_id.to_string(),
    trace_id.to_string(),
).await?;

match execution.status {
    SagaStatus::Completed => {
        tracing::info!(saga_id = %execution.id, "saga completed successfully");
    }
    SagaStatus::Failed => {
        tracing::warn!(
            saga_id = %execution.id,
            error = execution.error_message.as_deref().unwrap_or("unknown"),
            "saga failed, compensation completed"
        );
    }
    SagaStatus::Aborted => {
        tracing::error!(
            saga_id = %execution.id,
            "saga aborted: compensation also failed, manual intervention required"
        );
    }
    _ => unreachable!("start() should return a terminal state"),
}
```

#### 9.3.3 Dead Letter 处理

```rust
use warpin_transaction::saga::*;

// 实现 Dead Letter 钩子
struct AlertDeadLetterHook {
    alert_service: AlertServiceClient,
}

#[async_trait]
impl DeadLetterHook for AlertDeadLetterHook {
    async fn on_saga_aborted(
        &self,
        execution: &SagaExecution,
        error: &str,
    ) {
        // 发送告警（企业微信/钉钉/邮件）
        self.alert_service.send_alert(Alert {
            level: AlertLevel::Critical,
            title: format!(
                "Saga '{}' 补偿失败，需要人工干预",
                execution.saga_name
            ),
            message: format!(
                "Saga ID: {}\n当前步骤: {}/{}\n错误: {}\n租户: {}",
                execution.id,
                execution.current_step,
                execution.total_steps,
                error,
                execution.tenant_id,
            ),
        }).await;
    }
}
```

#### 9.3.4 管理员查看和重试

```rust
// 列出所有 Dead Letter Saga
let dead_letters = orchestrator.list_dead_letters().await?;
for saga in &dead_letters {
    println!(
        "Saga: {} | Name: {} | Step: {}/{} | Error: {}",
        saga.id,
        saga.saga_name,
        saga.current_step,
        saga.total_steps,
        saga.error_message.as_deref().unwrap_or("N/A"),
    );
}

// 管理员修复数据后，手动重试
let retried = orchestrator.retry_dead_letter(
    saga_id,
    &definition,
).await?;
```

#### 9.3.5 服务启动时恢复中断的 Saga

```rust
// 在服务启动时，自动恢复因服务宕机而中断的 Saga
tokio::spawn({
    let orchestrator = orchestrator.clone();
    let shutdown = shutdown.clone();
    async move {
        if let Err(e) = orchestrator.start_recovery(shutdown).await {
            tracing::error!(error = %e, "saga recovery manager terminated");
        }
    }
});
```

### 9.4 Saga 执行流程

```
正常流程（全部成功）：
──────────────────────
start() → acquire semantic locks
        → [Step1.execute()] → persist result
        → [Step2.execute()] → persist result
        → [Step3.execute()] → persist result + publish outbox events
        → release semantic locks
        → status = Completed ✓

补偿流程（Step3 失败）：
──────────────────────────
start() → acquire semantic locks
        → [Step1.execute()] → persist result
        → [Step2.execute()] → persist result
        → [Step3.execute()] → ERROR!
        → status = Compensating
        → [Step2.compensate()] → OK
        → [Step1.compensate()] → OK
        → release semantic locks
        → status = Failed ✗ (业务失败，但数据一致)

异常流程（补偿也失败）：
──────────────────────────
start() → [Step1.execute()] → OK
        → [Step2.execute()] → OK
        → [Step3.execute()] → ERROR!
        → status = Compensating
        → [Step2.compensate()] → OK
        → [Step1.compensate()] → ERROR! (重试 N 次仍失败)
        → status = Aborted ✗✗
        → trigger dead_letter_hook (告警)
        → 等待人工干预
```

### 9.5 Semantic Lock 原理

```
问题：
  Saga A: Step1 创建 Task-001 (status = "pending")
  Saga B: 读取 Task-001，修改其属性
  Saga A: Step2 失败 → compensate → 取消 Task-001
  但 Saga B 已经基于 Task-001 做了操作 → 数据不一致！

Semantic Lock 解决方案：
  Saga A: Step1 创建 Task-001
          → 同时在 semantic_locks 表插入:
            (resource_type='task', resource_id='Task-001',
             lock_type='creating', saga_id=A)
  Saga B: 想修改 Task-001
          → 查询 semantic_locks 发现被 Saga A 锁定
          → 拒绝操作 / 等待 Saga A 完成
  Saga A: 完成或补偿后 → 释放 semantic lock
  Saga B: 现在可以安全操作 Task-001

业务代码中的集成：
  // 在 repository 层检查 semantic lock
  pub async fn update_task(&self, id: Uuid, dto: UpdateTaskDto) -> Result<Task> {
      // 检查是否被 Saga 锁定
      if self.semantic_lock_repo.is_locked("task", &id.to_string()).await? {
          return Err(ServiceError::conflict(
              "task is being modified by an active saga, please retry later"
          ));
      }
      // ... 正常更新逻辑
  }
```

---

## 10. Cross-Cutting: Distributed Lock

### 10.1 概述

分布式锁是 2PC、TCC、Saga 的共同依赖。warpin-transaction 提供基于 PostgreSQL Advisory Lock 的实现，不需要额外的 Redis 组件。

### 10.2 核心类型

```rust
/// 分布式锁 trait
#[async_trait]
pub trait DistributedLock: Send + Sync {
    /// 获取锁（阻塞等待）
    async fn acquire(
        &self,
        key: &str,
        ttl: Duration,
        wait_timeout: Duration,
    ) -> Result<LockGuard>;

    /// 尝试获取锁（非阻塞）
    async fn try_acquire(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Result<Option<LockGuard>>;

    /// 续期
    async fn extend(
        &self,
        guard: &LockGuard,
        ttl: Duration,
    ) -> Result<()>;

    /// 释放
    async fn release(&self, guard: LockGuard) -> Result<()>;
}

#[derive(Debug)]
pub struct LockGuard {
    pub key: String,
    pub fencing_token: u64,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Runtime-switchable
pub enum DistributedLockImpl {
    PgAdvisory(PgAdvisoryLock),
    InMemory(InMemoryLock),
}

#[async_trait]
impl DistributedLock for DistributedLockImpl { /* delegate */ }
```

### 10.3 使用方式

```rust
use warpin_transaction::lock::*;

// 创建锁管理器
let lock_manager: DistributedLockImpl = DistributedLockImpl::PgAdvisory(
    PgAdvisoryLock::new(db.clone()),
);

// 获取锁（阻塞等待）
let guard = lock_manager.acquire(
    "task_scheduling_segment_123",
    Duration::from_secs(30),     // TTL
    Duration::from_secs(10),     // 等待超时
).await?;

// 执行受保护的操作
let result = do_something().await;

// 释放锁
lock_manager.release(guard).await?;

// 或者使用 try_acquire（非阻塞）
if let Some(guard) = lock_manager.try_acquire(
    "task_scheduling_segment_123",
    Duration::from_secs(30),
).await? {
    // 获取成功
    let result = do_something().await;
    lock_manager.release(guard).await?;
} else {
    // 锁被其他进程持有
    return Err(ServiceError::conflict("resource is locked"));
}
```

### 10.4 Fencing Token

```rust
use warpin_transaction::lock::FencingTokenIssuer;

let fencing = FencingTokenIssuer::new(db.clone());

// 获取锁时同时获取 fencing token
let token = fencing.issue().await?;  // 单调递增

// 执行操作时验证 token
if fencing.validate("segment_123", token).await? {
    // token 有效，执行操作
    do_something().await?;
    // 确认 token
    fencing.confirm("segment_123", token).await?;
} else {
    // token 过期（有更新的操作已确认）
    return Err(anyhow!("stale fencing token"));
}
```

---

## 11. Cross-Cutting: Idempotency Guard

### 11.1 概述

幂等性守卫防止因网络重试、消息重投递导致的重复操作。

### 11.2 核心类型

```rust
pub struct IdempotencyGuard {
    repo: IdempotencyRepository,
    default_ttl: Duration,
}

#[derive(Debug)]
pub enum IdempotencyResult<T> {
    Executed(T),    // 首次执行
    Cached(T),      // 返回缓存结果（幂等命中）
}

impl IdempotencyGuard {
    pub fn new(db: Arc<DatabaseConnection>, default_ttl: Duration) -> Self;

    /// 幂等执行
    pub async fn execute<T, F>(
        &self,
        key: &str,
        operation: F,
    ) -> Result<IdempotencyResult<T>>
    where
        T: Serialize + DeserializeOwned + Send,
        F: FnOnce() -> BoxFuture<'static, Result<T>> + Send;

    /// 手动检查
    pub async fn check(
        &self,
        key: &str,
    ) -> Result<Option<serde_json::Value>>;

    /// 清理过期键
    pub async fn cleanup_expired(&self) -> Result<u64>;
}
```

### 11.3 使用方式

#### 11.3.1 API 层幂等（防止重复创建）

```rust
use warpin_transaction::idempotency::*;

let guard = IdempotencyGuard::new(db.clone(), Duration::from_hours(24));

// 在 API handler 中使用
pub async fn create_task(
    State(state): State<AppState>,
    Json(dto): Json<CreateTaskDto>,
) -> Result<Json<ResultEnvelope<Task>>> {
    // 用 request_id 作为幂等键
    let idempotency_key = format!("create_task:{}", dto.request_id);

    let result = state.idempotency_guard.execute(
        &idempotency_key,
        || Box::pin(async move {
            // 实际创建逻辑（只在首次执行）
            state.task_service.create_task(dto).await
        }),
    ).await?;

    match result {
        IdempotencyResult::Executed(task) => {
            Ok(Json(ResultEnvelope::success(task)))
        }
        IdempotencyResult::Cached(task) => {
            // 重复请求，返回缓存结果
            tracing::debug!(key = %idempotency_key, "idempotent hit");
            Ok(Json(ResultEnvelope::success(task)))
        }
    }
}
```

#### 11.3.2 消息消费幂等

```rust
// IdempotentConsumer 内部已经使用了幂等机制
// 但如果你需要在业务逻辑中额外使用：
let guard = IdempotencyGuard::new(db.clone(), Duration::from_hours(72));

async fn process_event(&self, event: &ConsumedEvent) -> Result<()> {
    let key = format!("event:{}:{}", event.topic, event.id);

    self.guard.execute(&key, || Box::pin(async move {
        // 幂等保护的业务逻辑
        self.handle_task_completed(event).await
    })).await?;

    Ok(())
}
```

---

## 12. Cross-Cutting: Transaction Tracing

### 12.1 概述

每个事务层级都内置 tracing span，与 warpin-observability 集成。

### 12.2 Span 层级

```
[service_name]
  └── [saga:task_scheduling] saga_id=xxx tenant_id=yyy
      ├── [saga_step:create_task] step=1/3
      │   └── [local_tx] db=scheduler savepoints=0
      │       ├── [sql] UPDATE tasks ...
      │       └── [sql] INSERT outbox_events ...
      ├── [saga_step:allocate_segment] step=2/3
      │   └── [tcc:resource_allocation] tx_id=zzz
      │       ├── [tcc_try:arc_segment] → Ready
      │       ├── [tcc_try:device] → Ready
      │       ├── [tcc_confirm:arc_segment] → Ok
      │       └── [tcc_confirm:device] → Ok
      └── [saga_step:create_bill] step=3/3
          └── [twopc:billing] xid=www
              ├── [twopc_prepare:scheduler] → Ready
              ├── [twopc_prepare:customer] → Ready
              ├── [twopc_commit:scheduler] → Ok
              └── [twopc_commit:customer] → Ok
```

### 12.3 使用方式

所有 tracing 自动生成，无需业务代码额外配置。只需确保服务已初始化 tracing：

```rust
use warpin_observability::init_tracing;

// 服务启动时
init_tracing("scheduler-service");
// 之后所有 warpin-transaction 操作自动产生 tracing span
```

---

## 13. 数据库 Schema

warpin-transaction 需要 7 张基础设施表 + 1 个序列。这些表通过 `warpin_transaction::schema_plan()` 自动注册到 warpin-storage 的 SchemaPlan 中。

### 13.1 自动创建（通过 SchemaPlan）

```rust
use warpin_storage::SchemaPlan;

// 在服务启动时，合并业务表和事务基础设施表
let plan = SchemaPlan::new()
    // 业务表
    .register::<task::Entity>()
    .register::<arc_segment::Entity>()
    // 事务基础设施表
    .merge(warpin_transaction::schema_plan());

// SchemaPlan 会在启动时自动创建所有表
let db_runtime = DatabaseRuntime::bootstrap(
    &config.database,
    &config.database_options,
    &plan,
).await;
```

### 13.2 完整 DDL 参考

以下 DDL 仅供参考，实际表由 SchemaPlan 自动管理。

```sql
-- ====================================================================
-- Layer 2: Transactional Outbox
-- ====================================================================

-- 事件暂存表（与业务数据在同一个数据库中）
CREATE TABLE IF NOT EXISTS outbox_events (
    id              UUID PRIMARY KEY,
    aggregate_type  VARCHAR(100) NOT NULL,
    aggregate_id    VARCHAR(200) NOT NULL,
    event_type      VARCHAR(200) NOT NULL,
    topic           VARCHAR(200) NOT NULL,
    partition_key   VARCHAR(200) NOT NULL,
    payload         JSONB NOT NULL,
    trace_id        VARCHAR(100) NOT NULL,
    tenant_id       VARCHAR(100) NOT NULL,
    actor_id        VARCHAR(100),
    causation_id    UUID,
    correlation_id  UUID,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    retry_count     INT NOT NULL DEFAULT 0,
    max_retries     INT NOT NULL DEFAULT 5,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at    TIMESTAMPTZ,
    next_retry_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbox_relay
    ON outbox_events(status, next_retry_at)
    WHERE status IN ('pending', 'failed');

-- 消费端去重表（消费者数据库中）
CREATE TABLE IF NOT EXISTS consumed_events (
    event_id        UUID PRIMARY KEY,
    topic           VARCHAR(200) NOT NULL,
    consumer_group  VARCHAR(200) NOT NULL,
    consumed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================================================
-- Layer 3: 2PC Coordinator
-- ====================================================================

-- 2PC 执行记录（协调器数据库中）
CREATE TABLE IF NOT EXISTS twopc_executions (
    xid             VARCHAR(200) PRIMARY KEY,
    status          VARCHAR(20) NOT NULL DEFAULT 'init',
    participants    JSONB NOT NULL,
    decision        VARCHAR(10),
    tenant_id       VARCHAR(100) NOT NULL,
    trace_id        VARCHAR(100) NOT NULL,
    payload         JSONB,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_twopc_recovery
    ON twopc_executions(status)
    WHERE status IN ('preparing', 'committing', 'aborting');

-- ====================================================================
-- Layer 4: TCC Coordinator
-- ====================================================================

-- TCC 执行记录
CREATE TABLE IF NOT EXISTS tcc_executions (
    id              UUID PRIMARY KEY,
    status          VARCHAR(20) NOT NULL DEFAULT 'init',
    participants    JSONB NOT NULL,
    tenant_id       VARCHAR(100) NOT NULL,
    trace_id        VARCHAR(100) NOT NULL,
    payload         JSONB,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_tcc_timeout
    ON tcc_executions(expires_at)
    WHERE status IN ('trying', 'all_reserved');

-- ====================================================================
-- Layer 5: Saga Orchestrator
-- ====================================================================

-- Saga 执行记录
CREATE TABLE IF NOT EXISTS saga_executions (
    id              UUID PRIMARY KEY,
    saga_name       VARCHAR(200) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    current_step    INT NOT NULL DEFAULT 0,
    total_steps     INT NOT NULL,
    input           JSONB NOT NULL,
    step_results    JSONB NOT NULL DEFAULT '{}',
    error_message   TEXT,
    tenant_id       VARCHAR(100) NOT NULL,
    trace_id        VARCHAR(100) NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_saga_recovery
    ON saga_executions(status)
    WHERE status IN ('running', 'compensating');

-- 语义锁
CREATE TABLE IF NOT EXISTS semantic_locks (
    saga_id         UUID NOT NULL REFERENCES saga_executions(id) ON DELETE CASCADE,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     VARCHAR(200) NOT NULL,
    lock_type       VARCHAR(20) NOT NULL,
    acquired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_semantic_lock_expiry
    ON semantic_locks(expires_at);

-- ====================================================================
-- Cross-Cutting: Idempotency
-- ====================================================================

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key             VARCHAR(500) PRIMARY KEY,
    response        JSONB,
    status          VARCHAR(20) NOT NULL DEFAULT 'in_progress',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_cleanup
    ON idempotency_keys(expires_at)
    WHERE status = 'completed';

-- ====================================================================
-- Cross-Cutting: Fencing Token
-- ====================================================================

CREATE SEQUENCE IF NOT EXISTS fencing_token_seq
    AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE;

CREATE TABLE IF NOT EXISTS fencing_confirmations (
    resource_key    VARCHAR(500) PRIMARY KEY,
    confirmed_token BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 14. Feature Gate 设计

### 14.1 Cargo Features

```toml
[features]
default = ["full"]
full = ["local", "outbox", "twopc", "tcc", "saga", "lock", "idempotency"]

# 核心层
local       = []                            # Layer 1
outbox      = ["local"]                     # Layer 2 (依赖 Layer 1)
twopc       = ["local", "lock"]             # Layer 3
tcc         = ["local", "lock"]             # Layer 4
saga        = ["local", "outbox", "lock"]   # Layer 5

# 基础设施
lock        = []
idempotency = []

# 扩展
grpc        = ["dep:tonic"]   # gRPC 远程 2PC/TCC 参与者
```

### 14.2 按需引用

```toml
# 单体项目：只需本地事务 + Outbox
[dependencies]
warpin-transaction = { version = "0.2.0", features = ["local", "outbox"] }

# 微服务项目：完整功能
[dependencies]
warpin-transaction = { version = "0.2.0" }  # default = full

# 微服务 + 跨服务 gRPC 2PC
[dependencies]
warpin-transaction = { version = "0.2.0", features = ["full", "grpc"] }

# 只需分布式锁和幂等
[dependencies]
warpin-transaction = { version = "0.2.0", default-features = false, features = ["lock", "idempotency"] }
```

---

## 15. 公开 API 总览

```rust
// ── Layer 1: Local Transaction ──
pub mod local {
    pub struct TransactionContext<'txn>;
    pub async fn execute<T, F>(db, operation) -> Result<T>;
}

// ── Layer 2: Transactional Outbox ──
pub mod outbox {
    // 生产者
    pub struct TransactionalPublisher;
    pub struct OutboxEventCreate;
    pub struct OutboxEvent;
    pub enum OutboxStatus;
    pub struct EventMetadata;

    // Relay
    pub trait OutboxRelay;
    pub enum OutboxRelayImpl { Cdc, Polling }
    pub struct CdcRelay;
    pub struct CdcConfig;
    pub struct PollingRelay;
    pub struct PollingRelayConfig;
    pub struct RelayResult;
    pub struct RelayHealth;

    // 消费者
    pub struct IdempotentConsumer<H>;
    pub trait EventHandler;
    pub struct ConsumedEvent;
    pub struct IdempotentConsumerConfig;
}

// ── Layer 3: 2PC ──
pub mod twopc {
    pub trait TwoPcParticipant;
    pub struct TwoPcContext;
    pub enum PrepareResult;
    pub enum ParticipantRecoveryStatus;
    pub struct PgTwoPcParticipant<F>;
    pub struct GrpcTwoPcParticipant;    // feature = "grpc"
    pub struct TwoPcCoordinator;
    pub struct TwoPcConfig;
    pub enum TwoPcOutcome;
    pub enum ForceDecision;
    pub struct TwoPcExecution;
}

// ── Layer 4: TCC ──
pub mod tcc {
    pub trait TccParticipant;
    pub struct TccContext;
    pub struct ReservationToken;
    pub struct TccCoordinator;
    pub struct TccConfig;
    pub enum TccOutcome;
    pub struct TccExecution;
}

// ── Layer 5: Saga ──
pub mod saga {
    pub trait SagaStep;
    pub struct SagaContext;
    pub struct StepOutput;
    pub struct SagaDefinition;
    pub struct SagaDefinitionBuilder;
    pub enum SagaStatus;
    pub struct SagaExecution;
    pub struct SemanticLockSpec;
    pub enum SemanticLockType;
    pub struct SagaOrchestrator;
    pub struct SagaConfig;
    pub trait DeadLetterHook;
}

// ── Cross-Cutting: Lock ──
pub mod lock {
    pub trait DistributedLock;
    pub enum DistributedLockImpl { PgAdvisory, InMemory }
    pub struct PgAdvisoryLock;
    pub struct InMemoryLock;
    pub struct LockGuard;
    pub struct FencingTokenIssuer;
}

// ── Cross-Cutting: Idempotency ──
pub mod idempotency {
    pub struct IdempotencyGuard;
    pub enum IdempotencyResult<T>;
}

// ── Schema Registration ──
pub fn schema_plan() -> SchemaPlan;
```

---

## 16. 场景决策矩阵

### 16.1 快速选择指南

```
Q1: 操作是否跨数据库？
    否 → Layer 1 (Local Transaction)
    是 → Q2

Q2: 是否要求原子提交（绝不容忍任何中间状态）？
    是 → Layer 3 (2PC)
    否 → Q3

Q3: 是否涉及资源预留（弧段/设备/余额冻结）？
    是 → Layer 4 (TCC)
    否 → Q4

Q4: 是否长流程（多步骤、可能耗时分钟级）？
    是 → Layer 5 (Saga)
    否 → Layer 4 (TCC)  // 短流程用 TCC 更简单

附加: 是否涉及 DB 写入后发消息？
    是 → 加上 Layer 2 (Outbox)
```

### 16.2 详细场景对照表

| 业务场景 | 推荐方案 | 层级组合 | 原因 |
|---------|---------|---------|------|
| 更新任务状态 + 释放弧段（同库） | Local TX | L1 | 同一数据库，ACID 足够 |
| 更新任务状态 + 发 Kafka 事件 | Local TX + Outbox | L1 + L2 | DB + 消息原子性 |
| 跨库：任务状态 + 生成账单（强一致） | 2PC | L3 | 不容忍不一致 |
| 弧段预留 + 设备分配（跨服务） | TCC | L4 | 资源预留模式 |
| 弧段预留 + 设备分配 + 发事件 | TCC + Outbox | L4 + L2 | 资源预留 + 可靠消息 |
| 任务全生命周期（创建→调度→执行→计费） | Saga | L5 | 长流程，需补偿 |
| 任务全生命周期 + 可靠消息 | Saga + Outbox | L5 + L2 | 长流程 + 可靠消息 |
| API 防重复提交 | Idempotency | Cross-cutting | 幂等性保护 |
| 并发调度同一弧段 | Distributed Lock | Cross-cutting | 防竞态 |
| 批量导入遥测数据（部分失败可接受） | Savepoint | L1 | 嵌套事务 |
| 消费 Kafka 事件（防重复处理） | Idempotent Consumer | L2 | exactly-once |

### 16.3 组合使用示例

**最复杂场景：任务调度全流程**

```
1. API 接收创建任务请求
   → IdempotencyGuard 去重（Cross-cutting）

2. Saga 编排开始
   → Semantic Lock 锁定涉及的资源（Layer 5）

3. Saga Step 1: 创建任务
   → Local TX: INSERT task + INSERT outbox_event（Layer 1 + 2）

4. Saga Step 2: 预留弧段 + 设备
   → TCC: try(弧段) + try(设备) → confirm/cancel（Layer 4）

5. Saga Step 3: 生成账单
   → 2PC: scheduler DB(task.status='billed') +
          customer DB(INSERT bill)（Layer 3）

6. Saga 完成
   → Outbox Relay 发布 "task.fully_scheduled" 事件（Layer 2）
   → 释放 Semantic Lock（Layer 5）

7. 下游消费者收到事件
   → IdempotentConsumer 去重处理（Layer 2）
```

---

## 17. 与 warpin 生态集成

### 17.1 依赖关系

```toml
[dependencies]
warpin-storage   = { workspace = true }   # DatabaseConnection, CrudRepository, SchemaPlan
warpin-event-bus = { workspace = true }   # EventBus, BusEvent, EventConsumerImpl
warpin-errors    = { workspace = true }   # ServiceError, ResultCode
```

### 17.2 与 warpin-storage 集成

```rust
// warpin-transaction 使用 warpin-storage 的:
// - DatabaseConnection / DatabaseTransaction (SeaORM)
// - run_in_transaction() (原始事务 API)
// - SchemaPlan (自动建表)
// - DatabaseRepository (连接管理)

// 业务项目启动时的集成方式:
let plan = SchemaPlan::new()
    .register::<task::Entity>()
    .register::<arc_segment::Entity>()
    .merge(warpin_transaction::schema_plan());  // 注册事务基础设施表

let db_runtime = DatabaseRuntime::bootstrap(
    &config.database,
    &config.database_options,
    &plan,
).await;
```

### 17.3 与 warpin-event-bus 集成

```rust
// Outbox Relay 使用 warpin-event-bus 的 EventBus trait 发布事件
// IdempotentConsumer 使用 warpin-event-bus 的 EventConsumerImpl 消费事件

// 创建 Relay 时传入 EventBus 实例
let relay = PollingRelay::new(
    db.clone(),
    event_bus.clone(),   // Arc<dyn EventBus> 来自 warpin-event-bus
    config,
);

// 创建 IdempotentConsumer 时传入 EventConsumerImpl
let consumer = IdempotentConsumer::new(
    event_consumer,      // EventConsumerImpl 来自 warpin-event-bus
    handler,
    db.clone(),
    config,
);
```

### 17.4 与 warpin-http 集成

```rust
// 在 Axum handler 中使用 IdempotencyGuard
use warpin_http::{ServiceState, ServiceResult};
use warpin_transaction::idempotency::*;

pub async fn create_task(
    State(state): State<ServiceState<AppState>>,
    Json(dto): Json<CreateTaskDto>,
) -> ServiceResult<Task> {
    let guard = &state.inner().idempotency_guard;
    let result = guard.execute(&dto.request_id, || {
        // ...
    }).await?;
    // ...
}
```

### 17.5 与 warpin-context 集成

```rust
// ExecutionContext 的 trace_id / tenant_id 传播到事务上下文
use warpin_context::ExecutionContext;

let exec_ctx = ExecutionContext::new(tenant_id, station_id, user_id);

// Saga 使用 ExecutionContext 的信息
orchestrator.start(
    &definition,
    input,
    exec_ctx.scope.tenant_id.clone(),   // tenant_id
    exec_ctx.request.request_id.to_string(), // trace_id
).await?;
```

### 17.6 完整服务启动模板

```rust
use warpin_storage::{DatabaseRuntime, SchemaPlan};
use warpin_event_bus::{EventBusImpl, KafkaEventBus};
use warpin_transaction::{
    lock::*,
    outbox::*,
    saga::*,
    idempotency::*,
};

pub async fn run() -> Result<()> {
    // 1. 初始化 tracing
    init_tracing("scheduler-service");

    // 2. 加载配置
    let config = load_config()?;

    // 3. 启动数据库（含事务基础设施表）
    let plan = SchemaPlan::new()
        .register::<task::Entity>()
        .register::<arc_segment::Entity>()
        .merge(warpin_transaction::schema_plan());

    let db_runtime = DatabaseRuntime::bootstrap(
        &config.database,
        &config.database_options,
        &plan,
    ).await;
    let db = db_runtime.connection_arc().unwrap();

    // 4. 初始化事件总线
    let event_bus = Arc::new(EventBusImpl::Kafka(
        KafkaEventBus::new(config.kafka.clone())?,
    ));

    // 5. 初始化事务基础设施
    let lock_manager = Arc::new(DistributedLockImpl::PgAdvisory(
        PgAdvisoryLock::new(db.clone()),
    ));

    let outbox_publisher = TransactionalPublisher::new(db.clone());

    let outbox_relay = OutboxRelayImpl::Polling(PollingRelay::new(
        db.clone(),
        event_bus.clone(),
        PollingRelayConfig::default(),
    ));

    let saga_orchestrator = SagaOrchestrator::new(
        db.clone(),
        lock_manager.clone(),
        SagaConfig::default(),
    )
    .with_outbox(outbox_publisher.clone());

    let idempotency_guard = IdempotencyGuard::new(
        db.clone(),
        Duration::from_secs(24 * 3600),
    );

    // 6. 启动后台任务
    let shutdown = CancellationToken::new();

    // Outbox Relay
    tokio::spawn({
        let relay = outbox_relay;
        let shutdown = shutdown.clone();
        async move { relay.start(shutdown).await.ok(); }
    });

    // Saga Recovery
    tokio::spawn({
        let orch = saga_orchestrator.clone();
        let shutdown = shutdown.clone();
        async move { orch.start_recovery(shutdown).await.ok(); }
    });

    // 7. 构建 AppState 并启动 HTTP 服务
    let state = AppState {
        db,
        event_bus,
        lock_manager,
        outbox_publisher,
        saga_orchestrator,
        idempotency_guard,
        // ... 业务 repositories
    };

    let routes = build_routes();
    let app = build_http_app(service_state, routes);
    serve(&config.server, app).await
}
```

---

## 附录 A: gRPC 2PC Service 定义

```protobuf
// proto/transaction/twopc.proto
syntax = "proto3";
package warpin.transaction.twopc;

service TwoPcService {
    rpc Prepare(PrepareRequest) returns (PrepareResponse);
    rpc Commit(CommitRequest) returns (CommitResponse);
    rpc Rollback(RollbackRequest) returns (RollbackResponse);
    rpc Recover(RecoverRequest) returns (RecoverResponse);
}

message PrepareRequest {
    string xid = 1;
    string tenant_id = 2;
    string trace_id = 3;
    bytes payload = 4;
    uint64 timeout_ms = 5;
}

message PrepareResponse {
    enum Result {
        READY = 0;
        READ_ONLY = 1;
        REFUSED = 2;
    }
    Result result = 1;
    string message = 2;
}

message CommitRequest {
    string xid = 1;
}

message CommitResponse {
    bool success = 1;
    string message = 2;
}

message RollbackRequest {
    string xid = 1;
}

message RollbackResponse {
    bool success = 1;
    string message = 2;
}

message RecoverRequest {
    string xid = 1;
}

message RecoverResponse {
    enum Status {
        PREPARED = 0;
        COMMITTED = 1;
        ROLLED_BACK = 2;
        UNKNOWN = 3;
    }
    Status status = 1;
}
```

## 附录 B: 配置文件模板

```toml
# configs/transaction.toml

[outbox]
use_cdc = false                    # CDC Relay 需要 PostgreSQL logical replication 配置
poll_interval_ms = 1000
batch_size = 100
max_retries = 5
retry_backoff_base_ms = 10000
cleanup_after_days = 7

[outbox.cdc]
slot_name = "warpin_outbox_slot"
publication_name = "warpin_outbox_pub"
poll_interval_ms = 100
max_batch_size = 500
status_update_interval_ms = 10000

[twopc]
prepare_timeout_ms = 10000
commit_retry_interval_ms = 1000
commit_max_retries = 4294967295    # u32::MAX
abort_timeout_ms = 30000
recovery_scan_interval_ms = 60000

[tcc]
try_timeout_ms = 5000
global_timeout_ms = 30000
confirm_cancel_retry_interval_ms = 1000
confirm_cancel_max_retries = 4294967295
reservation_ttl_ms = 300000        # 5 minutes

[saga]
step_timeout_ms = 30000
compensation_timeout_ms = 60000
compensation_max_retries = 4294967295
semantic_lock_ttl_ms = 600000      # 10 minutes
recovery_scan_interval_ms = 30000

[idempotency]
default_ttl_hours = 24
cleanup_interval_ms = 3600000      # 1 hour
```

## 附录 C: 状态机汇总

### 2PC 状态机

```
         ┌──────────────────────┐
         │        Init          │
         └──────────┬───────────┘
                    │ start
                    ▼
         ┌──────────────────────┐
         │      Preparing       │ ← persist before sending prepare
         └──────────┬───────────┘
               ┌────┴────┐
          all Ready   any Refused/Timeout
               │         │
               ▼         ▼
         ┌──────────┐ ┌──────────┐
         │ Prepared  │ │ Aborting │ ← persist decision
         └────┬─────┘ └────┬─────┘
              │             │
              ▼             ▼
         ┌──────────┐ ┌──────────┐
         │Committing│ │ Aborted  │ (terminal)
         └────┬─────┘ └──────────┘
              │
              ▼
         ┌──────────┐
         │Committed │ (terminal)
         └──────────┘
```

### TCC 状态机

```
         ┌──────────────────────┐
         │        Init          │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │       Trying         │
         └──────────┬───────────┘
               ┌────┴────┐
           all OK    any Failed/Timeout
               │         │
               ▼         ▼
         ┌──────────┐ ┌──────────┐
         │AllReserved│ │Cancelling│
         └────┬─────┘ └────┬─────┘
              │             │
              ▼             ▼
         ┌──────────┐ ┌──────────┐
         │Confirming│ │Cancelled │ (terminal)
         └────┬─────┘ └──────────┘
              │
              ▼
         ┌──────────┐
         │Confirmed │ (terminal)
         └──────────┘
```

### Saga 状态机

```
         ┌──────────────────────┐
         │       Pending        │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │       Running        │ ← executing steps forward
         └──────────┬───────────┘
               ┌────┴────┐
          all steps OK  any step Failed
               │              │
               ▼              ▼
         ┌──────────┐  ┌──────────────┐
         │Completed │  │ Compensating │ ← executing steps backward
         └──────────┘  └──────┬───────┘
            (terminal)   ┌────┴────┐
                  all compensated  compensation Failed
                         │              │
                         ▼              ▼
                   ┌──────────┐  ┌──────────┐
                   │  Failed  │  │ Aborted  │ ← needs manual intervention
                   └──────────┘  └──────────┘
                    (terminal)    (terminal)
```
