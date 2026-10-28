CREATE TABLE warpin_workspace_schema_versions_v1 (
 migration_id text PRIMARY KEY,
 migration_checksum text NOT NULL CHECK(migration_checksum ~ '^sha256:[0-9a-f]{64}$'),
 catalog_digest text NOT NULL CHECK(catalog_digest ~ '^sha256:[0-9a-f]{64}$'),
 installed_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);
