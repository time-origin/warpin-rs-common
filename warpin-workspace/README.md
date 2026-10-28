# warpin-workspace

Development candidate, distributed on crates.io under the unified workspace
version; not qualified for production deployment. Publication does not remove
the deployment gates below.

Reusable typed fixed-filesystem budgets, PostgreSQL pool reservations and a Linux
management-plane allocation backend. It has no business-domain dispatch and no
user command/path API. Applications authenticate requests and freeze the exact
resource-policy digest under their immutable release/attempt/fence authority.

Reservation expiry never implies namespace death. Reservations remain occupied
until verified death, exact owned filesystem teardown and atomic release. Disk
images bound filesystem blocks/inodes without modifying shared host filesystems.

The Linux backend is privileged management code, not code executed by a task.
Its production deployment needs a separately reviewed node profile, caller
transport, pool ownership, namespace entry and rollback plan. No manager is
installed by using this crate. Existing published object storage continues to
handle immutable inputs/results independently.

Each fixed management utility has a 120-second SIGKILL deadline owned by its
lock-holding guardian. Its watchdog waits for actual utility exit, including an
uninterruptible kernel operation; there is no forced watchdog exit or lease
expiry that releases a live operation's lock. Each output pipe is read
with a 1 MiB bound. These are management-plane operation limits, independent of
scientific task CPU, memory, deadline and file policies. Timeout never frees a
reservation or authorizes cleanup without the usual physical/namespace proof.

Crash recovery with an exact recorded namespace identity is implemented. An
uncertain LAUNCHING record without that identity deliberately retains capacity;
a production launch gate/handshake and reconciliation service are still required.
Input materialization precedes actual read-only filesystem sealing, whose proof
is persisted before launch admission. Returning verified role paths alone does
not constitute sandbox namespace integration. This candidate must not be treated as deployment ready.

Management bootstrap explicitly chooses a non-zero maximum in-flight operation
count. Clones share one per-manager/process admission domain; excess operations
are rejected before spawning, not queued as unlimited detached tasks. Accepted
operations settle independently of caller-future cancellation. Physical I/O and
proc/pidfd observations run through bounded admitted spawn_blocking work, whose
owned allocation guard returns to the settlement task and remains held through
the PostgreSQL phase result. Database failure leaves the prior conservative
phase and occupied capacity; it never fabricates release. This does not promise
continued async settlement after the whole Tokio runtime or process is killed;
those failures still need durable phase, guardian and Node recovery qualification.

A physical pool authority (current kernel boot UUID, canonical root device/inode
and path, task UID/GID) is atomically frozen under the PostgreSQL pool row lock
before first provision, including concurrent RESERVED requests from different
roots. Every facade operation and physical phase proof must match that durable
authority. Non-RESERVED missing directory/lock/ownership is an error, never a
new owner. Raw kernel namespace handles have no pool authority; only a manager
association can authorize durable namespace binding/death. Different boot IDs
are rejected without a separately trusted same-host continuity proof; this
candidate implements no automatic cross-boot reassignment or resource adoption.

Database bootstrap requires an explicit, dedicated `WorkspaceSchema`; `public`,
system namespaces and noncanonical identifiers are rejected. All ledger table
access is schema-qualified, independent of caller search_path or temporary
tables. Operator `install_schema` installs a version/checksum/catalog receipt
transactionally. Only an empty schema or the exact unpublished three-table
baseline can migrate. Partial/drifted catalogs and changed receipts reject;
there is no automatic repair or data deletion. Catalog references are qualified
against PostgreSQL 16 and include columns, defaults, collations, constraints,
indexes, relation options/RLS, inheritance, triggers and functions; the present
version permits no application function or trigger in the owning schema.

Each ledger transaction holds the shared migration advisory lock and actual
ACCESS SHARE relation locks through its catalog/receipt check and phase change.
Operator install/grant takes the exclusive matching advisory lock. This is the
governed operator protocol; it does not prevent a superuser bypassing it with
arbitrary concurrent DDL.

The operator owns schema/DDL and fixed pool configuration. `schema::roles::grant`
only grants a separately provisioned, explicit runtime role SELECT on the four
ledger tables, INSERT on allocation/first pool-authority columns, UPDATE on pool
reserved counters and allocation state/record/digest columns. Runtime cannot
write pool maxima or migration receipts, DELETE or perform DDL. Credentials and
role creation remain outside this library. Runtime verification binds the actual
current_user and session_user to the configured role and rejects broad role attributes,
memberships, PUBLIC ledger grants and excess table/column privileges. Runtime
verification also rejects every schema/table/column WITH GRANT OPTION, including
otherwise permitted USAGE, SELECT and column writes; runtime cannot delegate
its approved authority. PUBLIC schema permissions are outside this profile.
Production
bootstrap must use that verified runtime role; fixture SET ROLE projection is
not production login, transport authentication or Node attestation qualification.
