CREATE TABLE IF NOT EXISTS warpin_workspace_pools_v1 (
 pool_id text PRIMARY KEY,
 maximum_bytes bigint NOT NULL CHECK(maximum_bytes>0),
 maximum_inodes bigint NOT NULL CHECK(maximum_inodes>0),
 reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0 AND reserved_bytes<=maximum_bytes),
 reserved_inodes bigint NOT NULL DEFAULT 0 CHECK(reserved_inodes>=0 AND reserved_inodes<=maximum_inodes)
);
CREATE TABLE IF NOT EXISTS warpin_workspace_allocations_v1 (
 allocation_id uuid PRIMARY KEY,
 pool_id text NOT NULL REFERENCES warpin_workspace_pools_v1(pool_id),
 reserved_bytes bigint NOT NULL CHECK(reserved_bytes>0),
 reserved_inodes bigint NOT NULL CHECK(reserved_inodes>0),
 state text NOT NULL CHECK(state IN('RESERVED','PROVISIONED','LAUNCHING','ACTIVE','RETAINED','QUIESCENT','RELEASED')),
 record_json jsonb NOT NULL CHECK(jsonb_typeof(record_json)='object'),
 record_digest text NOT NULL CHECK(record_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS warpin_workspace_allocations_pool_v1 ON warpin_workspace_allocations_v1(pool_id,state);

CREATE TABLE IF NOT EXISTS warpin_workspace_pool_authorities_v1 (
 pool_id text PRIMARY KEY REFERENCES warpin_workspace_pools_v1(pool_id),
 authority_json jsonb NOT NULL CHECK(jsonb_typeof(authority_json)='object'),
 authority_digest text NOT NULL CHECK(authority_digest ~ '^sha256:[0-9a-f]{64}$')
);
