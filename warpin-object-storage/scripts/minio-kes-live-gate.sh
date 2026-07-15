#!/usr/bin/env bash
set -euo pipefail

# Compatibility-only live gate for the reviewed MinIO/KES adapter profile.
# The filesystem KES keystore below is intentionally ephemeral and MUST NOT be
# used as the production ArtifactEncryptionPolicy implementation.

umask 077

readonly KES_IMAGE='minio/kes@sha256:bb97b121b03b0acd04eecea63a5909ec2e56eab1a48e0cc418036b67502a64b0'
readonly MINIO_IMAGE='minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e'
readonly MC_IMAGE='minio/mc@sha256:aead63c77f9db9107f1696fb08ecb0faeda23729cde94b0f663edf4fe09728e3'
readonly BUCKET='r4-artifacts'
readonly KMS_KEY_NAME='minio-r4-default'
readonly KMS_KEY_IDENTITY='arn:aws:kms:minio-r4-default'
readonly CONTEXT_A_DIGEST='66faa8c7d7be5bbb206f0e891960aecb8d649c804378ed4d25a8f9d285621e32'
readonly CONTEXT_B_DIGEST='7d2db71ba9b05414d1801c6289a1caa6f9f38c2e30e6d2b8db79aa3553332af4'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CRATE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly WORKSPACE_DIR="$(cd -- "${CRATE_DIR}/.." && pwd)"
readonly RUN_TOKEN="$$-$(date +%s)"
readonly KES_NAME="warpin-kes-gate-${RUN_TOKEN}"
readonly MINIO_NAME="warpin-minio-gate-${RUN_TOKEN}"
readonly KMS_NETWORK="warpin-kms-gate-${RUN_TOKEN}"
readonly CLIENT_NETWORK="warpin-client-gate-${RUN_TOKEN}"
readonly WORK_DIR="$(mktemp -d -t warpin-minio-kes-gate.XXXXXX)"

cleanup_best_effort() {
    docker rm -f "${MINIO_NAME}" "${KES_NAME}" >/dev/null 2>&1 || true
    docker network rm "${CLIENT_NETWORK}" "${KMS_NETWORK}" >/dev/null 2>&1 || true
    rm -rf -- "${WORK_DIR}" || true
}
trap cleanup_best_effort EXIT INT TERM

cleanup_verified() {
    local failed=0
    if ! docker rm -f "${MINIO_NAME}" "${KES_NAME}" >/dev/null 2>&1; then
        failed=1
    fi
    if ! docker network rm "${CLIENT_NETWORK}" "${KMS_NETWORK}" >/dev/null 2>&1; then
        failed=1
    fi
    if ! rm -rf -- "${WORK_DIR}"; then
        failed=1
    fi
    local container
    for container in "${MINIO_NAME}" "${KES_NAME}"; do
        if docker container inspect "${container}" >/dev/null 2>&1; then
            failed=1
        fi
    done
    local network
    for network in "${CLIENT_NETWORK}" "${KMS_NETWORK}"; do
        if docker network inspect "${network}" >/dev/null 2>&1; then
            failed=1
        fi
    done
    if [[ -e "${WORK_DIR}" ]]; then
        failed=1
    fi
    (( failed == 0 ))
}

render_kes_config() {
    local output_file="$1"
    local bootstrap_identity="$2"
    local runtime_identity="$3"
    local metrics_identity="$4"
    {
        printf '%s\n' \
            'address: 0.0.0.0:7373' \
            '' \
            'admin:' \
            '  identity: disabled' \
            '' \
            'tls:' \
            '  key: /config/server.key' \
            '  cert: /config/server.crt' \
            '' \
            'policy:' \
            '  bootstrap-live-gate:' \
            '    allow:' \
            "    - /v1/key/create/${KMS_KEY_NAME}" \
            '    identities:' \
            "    - ${bootstrap_identity}" \
            '  runtime-live-gate:' \
            '    allow:' \
            "    - /v1/key/generate/${KMS_KEY_NAME}" \
            "    - /v1/key/decrypt/${KMS_KEY_NAME}" \
            '    identities:' \
            "    - ${runtime_identity}" \
            '  metrics-live-gate:' \
            '    allow:' \
            '    - /v1/status' \
            '    - /v1/metrics' \
            '    identities:' \
            "    - ${metrics_identity}" \
            '' \
            'keystore:' \
            '  fs:' \
            '    path: /data'
    } >"${output_file}"
}

self_check() {
    local fake_docker_state='absent'
    local policy_file="${WORK_DIR}/self-check-kes.yml"
    local bootstrap_policy
    local runtime_policy
    local metrics_policy
    docker() {
        case "${1:-} ${2:-}" in
            'rm -f'|'network rm')
                [[ "${fake_docker_state}" != 'remove-failure' ]]
                ;;
            'container inspect'|'network inspect')
                case "${fake_docker_state}" in
                    present)
                        return 0
                        ;;
                    one-container-remains)
                        [[ "${1:-}" == 'container' && $# -eq 3 && "${3:-}" == "${MINIO_NAME}" ]]
                        ;;
                    one-network-remains)
                        [[ "${1:-}" == 'network' && $# -eq 3 && "${3:-}" == "${CLIENT_NETWORK}" ]]
                        ;;
                    *)
                        return 1
                        ;;
                esac
                ;;
            *)
                return 1
                ;;
        esac
    }

    render_kes_config "${policy_file}" bootstrap-id runtime-id metrics-id
    grep -Fxq "    - /v1/key/create/${KMS_KEY_NAME}" "${policy_file}"
    grep -Fxq "    - /v1/key/generate/${KMS_KEY_NAME}" "${policy_file}"
    grep -Fxq "    - /v1/key/decrypt/${KMS_KEY_NAME}" "${policy_file}"
    grep -Fxq '    - /v1/status' "${policy_file}"
    grep -Fxq '    - /v1/metrics' "${policy_file}"
    if grep -Fq '*' "${policy_file}"; then
        echo 'self-check found a wildcard KES permission' >&2
        return 1
    fi
    bootstrap_policy="$(sed -n '/^  bootstrap-live-gate:/,/^  runtime-live-gate:/p' "${policy_file}")"
    runtime_policy="$(sed -n '/^  runtime-live-gate:/,/^  metrics-live-gate:/p' "${policy_file}")"
    metrics_policy="$(sed -n '/^  metrics-live-gate:/,/^keystore:/p' "${policy_file}")"
    grep -Fq "/v1/key/create/${KMS_KEY_NAME}" <<<"${bootstrap_policy}"
    if grep -Eq '/v1/key/(generate|decrypt)|/v1/(status|metrics)' <<<"${bootstrap_policy}"; then
        echo 'bootstrap KES policy exceeds exact key creation' >&2
        return 1
    fi
    grep -Fq "/v1/key/generate/${KMS_KEY_NAME}" <<<"${runtime_policy}"
    grep -Fq "/v1/key/decrypt/${KMS_KEY_NAME}" <<<"${runtime_policy}"
    if grep -Eq '/v1/key/create|/v1/(status|metrics)' <<<"${runtime_policy}"; then
        echo 'runtime KES policy exceeds exact generate/decrypt operations' >&2
        return 1
    fi
    grep -Fq '/v1/status' <<<"${metrics_policy}"
    grep -Fq '/v1/metrics' <<<"${metrics_policy}"
    if grep -Fq '/v1/key/' <<<"${metrics_policy}"; then
        echo 'metrics KES policy contains a key operation' >&2
        return 1
    fi

    cleanup_verified
    mkdir -p "${WORK_DIR}"
    fake_docker_state='remove-failure'
    if cleanup_verified; then
        echo 'self-check accepted a cleanup command failure' >&2
        return 1
    fi
    if [[ -e "${WORK_DIR}" ]]; then
        echo 'self-check left its temporary directory behind' >&2
        return 1
    fi
    mkdir -p "${WORK_DIR}"
    fake_docker_state='one-container-remains'
    if cleanup_verified; then
        echo 'self-check accepted one remaining container' >&2
        return 1
    fi
    mkdir -p "${WORK_DIR}"
    fake_docker_state='one-network-remains'
    if cleanup_verified; then
        echo 'self-check accepted one remaining network' >&2
        return 1
    fi
    printf '%s\n' 'minio_kes_live_gate_self_check=true'
}

if [[ "${1:-}" == '--self-check' ]]; then
    self_check
    trap - EXIT INT TERM
    exit 0
fi
if (( $# != 0 )); then
    echo 'usage: minio-kes-live-gate.sh [--self-check]' >&2
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command is unavailable: $1" >&2
        exit 1
    }
}

wait_for_https() {
    local ca_file="$1"
    local url="$2"
    local client_cert="${3:-}"
    local client_key="${4:-}"
    local attempt
    local -a client_args=()
    if [[ -n "${client_cert}" && -n "${client_key}" ]]; then
        client_args=(--cert "${client_cert}" --key "${client_key}")
    fi
    for attempt in {1..30}; do
        if curl --silent --fail --max-time 2 --cacert "${ca_file}" \
            "${client_args[@]}" "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "TLS readiness check failed" >&2
    return 1
}

kes_exec() {
    timeout 3 docker exec \
        --env KES_SERVER=https://localhost:7373 \
        --env KES_CLIENT_CERT=/config/metrics.crt \
        --env KES_CLIENT_KEY=/config/metrics.key \
        --env SSL_CERT_FILE=/config/server.crt \
        "${KES_NAME}" /kes "$@"
}

wait_for_kes() {
    local attempt
    for attempt in {1..30}; do
        if kes_exec status --json >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "KES mTLS readiness check failed" >&2
    return 1
}

kes_success_count() {
    local snapshot
    snapshot="$(kes_exec metric 2>/dev/null | head -n 1 || true)"
    jq -er '.kes_http_request_success | floor' <<<"${snapshot}"
}

run_mc() {
    docker run --rm \
        --network "${CLIENT_NETWORK}" \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --env SSL_CERT_FILE=/certs/ca.crt \
        --mount "type=bind,src=${WORK_DIR}/mc,dst=/mc" \
        --mount "type=bind,src=${WORK_DIR}/minio/ca.crt,dst=/certs/ca.crt,readonly" \
        --mount "type=bind,src=${WORK_DIR}/policy,dst=/policy,readonly" \
        "${MC_IMAGE}" --config-dir /mc "$@"
}

run_live_test() {
    local minio_port="$1"
    local mode="$2"
    local version_a="${3:-}"
    local version_b="${4:-}"
    local -a version_env=()
    if [[ "${mode}" == 'read' ]]; then
        version_env=(
            WARPIN_MINIO_VERSION_A="${version_a}"
            WARPIN_MINIO_VERSION_B="${version_b}"
        )
    fi
    env \
        WARPIN_MINIO_ENDPOINT="https://localhost:${minio_port}" \
        WARPIN_MINIO_BUCKET="${BUCKET}" \
        WARPIN_MINIO_ACCESS_KEY="${PROCESSING_USER}" \
        WARPIN_MINIO_SECRET_KEY="${PROCESSING_PASSWORD}" \
        WARPIN_MINIO_CA_PEM="${WORK_DIR}/minio/ca.crt" \
        WARPIN_MINIO_GATE_RUN_ID="${RUN_TOKEN}" \
        WARPIN_MINIO_GATE_MODE="${mode}" \
        "${version_env[@]}" \
        cargo test -p warpin-object-storage --all-features \
            --test minio_kes_live -- --ignored
}

for command in cargo curl docker jq openssl sha256sum; do
    require_command "${command}"
done

for image in "${KES_IMAGE}" "${MINIO_IMAGE}" "${MC_IMAGE}"; do
    if ! docker image inspect "${image}" >/dev/null 2>&1; then
        docker pull "${image}" >/dev/null
    fi
done

mkdir -p \
    "${WORK_DIR}/kes/keys" \
    "${WORK_DIR}/mc" \
    "${WORK_DIR}/minio/certs/CAs" \
    "${WORK_DIR}/minio/data" \
    "${WORK_DIR}/policy"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=bind,src=${WORK_DIR}/kes,dst=/work" \
    "${KES_IMAGE}" identity new \
        --dns "${KES_NAME}" \
        --dns localhost \
        --ip 127.0.0.1 \
        --key /work/server.key \
        --cert /work/server.crt \
        --expiry 1h \
        kes-live-gate >/dev/null
for identity_name in bootstrap runtime metrics; do
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --mount "type=bind,src=${WORK_DIR}/kes,dst=/work" \
        "${KES_IMAGE}" identity new \
            --key "/work/${identity_name}.key" \
            --cert "/work/${identity_name}.crt" \
            --expiry 1h \
            "${identity_name}-live-gate" >/dev/null
done

kes_identity_of() {
    local certificate_name="$1"
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --mount "type=bind,src=${WORK_DIR}/kes/${certificate_name},dst=/client.crt,readonly" \
        "${KES_IMAGE}" identity of /client.crt
}

KES_BOOTSTRAP_IDENTITY="$(kes_identity_of bootstrap.crt)"
KES_RUNTIME_IDENTITY="$(kes_identity_of runtime.crt)"
KES_METRICS_IDENTITY="$(kes_identity_of metrics.crt)"
readonly KES_BOOTSTRAP_IDENTITY KES_RUNTIME_IDENTITY KES_METRICS_IDENTITY
render_kes_config \
    "${WORK_DIR}/kes/config.yml" \
    "${KES_BOOTSTRAP_IDENTITY}" \
    "${KES_RUNTIME_IDENTITY}" \
    "${KES_METRICS_IDENTITY}"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj '/CN=warpin-minio-live-gate-ca' \
    -keyout "${WORK_DIR}/minio/ca.key" \
    -out "${WORK_DIR}/minio/ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=${MINIO_NAME}" \
    -addext "subjectAltName=DNS:${MINIO_NAME},DNS:localhost,IP:127.0.0.1" \
    -keyout "${WORK_DIR}/minio/certs/private.key" \
    -out "${WORK_DIR}/minio/server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 \
    -in "${WORK_DIR}/minio/server.csr" \
    -CA "${WORK_DIR}/minio/ca.crt" \
    -CAkey "${WORK_DIR}/minio/ca.key" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "${WORK_DIR}/minio/certs/public.crt" >/dev/null 2>&1
cp "${WORK_DIR}/kes/server.crt" "${WORK_DIR}/minio/certs/CAs/kes-server.crt"

MINIO_ROOT_USER="$(openssl rand -hex 12)"
MINIO_ROOT_PASSWORD="$(openssl rand -hex 24)"
PROCESSING_USER="processing-$(openssl rand -hex 8)"
PROCESSING_PASSWORD="$(openssl rand -hex 24)"
readonly MINIO_ROOT_USER MINIO_ROOT_PASSWORD PROCESSING_USER PROCESSING_PASSWORD

docker network create --internal "${KMS_NETWORK}" >/dev/null
docker network create "${CLIENT_NETWORK}" >/dev/null

docker run -d \
    --name "${KES_NAME}" \
    --network "${KMS_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=bind,src=${WORK_DIR}/kes,dst=/config,readonly" \
    --mount "type=bind,src=${WORK_DIR}/kes/keys,dst=/data" \
    "${KES_IMAGE}" server --config /config/config.yml >/dev/null
wait_for_kes

docker run --rm \
    --network "${KMS_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --env "KES_SERVER=https://${KES_NAME}:7373" \
    --env KES_CLIENT_CERT=/certs/bootstrap.crt \
    --env KES_CLIENT_KEY=/certs/bootstrap.key \
    --env SSL_CERT_FILE=/certs/server.crt \
    --mount "type=bind,src=${WORK_DIR}/kes/bootstrap.crt,dst=/certs/bootstrap.crt,readonly" \
    --mount "type=bind,src=${WORK_DIR}/kes/bootstrap.key,dst=/certs/bootstrap.key,readonly" \
    --mount "type=bind,src=${WORK_DIR}/kes/server.crt,dst=/certs/server.crt,readonly" \
    "${KES_IMAGE}" key create "${KMS_KEY_NAME}" >/dev/null

start_minio() {
    docker run -d \
        --name "${MINIO_NAME}" \
        --network "${KMS_NETWORK}" \
        --user "$(id -u):$(id -g)" \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --publish 127.0.0.1:0:9000 \
        --env HOME=/tmp \
        --env MINIO_BROWSER=off \
        --env "MINIO_ROOT_USER=${MINIO_ROOT_USER}" \
        --env "MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}" \
        --env "MINIO_KMS_KES_ENDPOINT=https://${KES_NAME}:7373" \
        --env MINIO_KMS_KES_CERT_FILE=/kes/runtime.crt \
        --env MINIO_KMS_KES_KEY_FILE=/kes/runtime.key \
        --env MINIO_KMS_KES_CAPATH=/certs/CAs/kes-server.crt \
        --env "MINIO_KMS_KES_KEY_NAME=${KMS_KEY_NAME}" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev \
        --mount "type=bind,src=${WORK_DIR}/minio/data,dst=/data" \
        --mount "type=bind,src=${WORK_DIR}/minio/certs,dst=/certs,readonly" \
        --mount "type=bind,src=${WORK_DIR}/kes/runtime.crt,dst=/kes/runtime.crt,readonly" \
        --mount "type=bind,src=${WORK_DIR}/kes/runtime.key,dst=/kes/runtime.key,readonly" \
        "${MINIO_IMAGE}" server /data --certs-dir /certs --address :9000 >/dev/null
    docker network connect "${CLIENT_NETWORK}" "${MINIO_NAME}"
}

start_minio
MINIO_PORT="$(docker port "${MINIO_NAME}" 9000/tcp | awk -F: 'NR == 1 { print $NF }')"
wait_for_https \
    "${WORK_DIR}/minio/ca.crt" \
    "https://localhost:${MINIO_PORT}/minio/health/ready"

docker run --rm \
    --network "${CLIENT_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --env SSL_CERT_FILE=/certs/ca.crt \
    --env "GATE_ACCESS_KEY=${MINIO_ROOT_USER}" \
    --env "GATE_SECRET_KEY=${MINIO_ROOT_PASSWORD}" \
    --mount "type=bind,src=${WORK_DIR}/mc,dst=/mc" \
    --mount "type=bind,src=${WORK_DIR}/minio/ca.crt,dst=/certs/ca.crt,readonly" \
    --entrypoint /bin/sh \
    "${MC_IMAGE}" -c \
        "mc --config-dir /mc alias set gate https://${MINIO_NAME}:9000 \"\${GATE_ACCESS_KEY}\" \"\${GATE_SECRET_KEY}\" >/dev/null" \
        >/dev/null
run_mc mb --ignore-existing "gate/${BUCKET}" >/dev/null
run_mc version enable "gate/${BUCKET}" >/dev/null

{
    printf '%s\n' \
        '{' \
        '  "Version": "2012-10-17",' \
        '  "Statement": [' \
        '    {' \
        '      "Effect": "Allow",' \
        '      "Action": ["s3:GetBucketLocation"],' \
        "      \"Resource\": [\"arn:aws:s3:::${BUCKET}\"]" \
        '    },' \
        '    {' \
        '      "Effect": "Allow",' \
        '      "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],' \
        "      \"Resource\": [\"arn:aws:s3:::${BUCKET}/live-gate/*\"]" \
        '    }' \
        '  ]' \
        '}'
} >"${WORK_DIR}/policy/processing.json"
run_mc admin policy create gate processing-live-gate /policy/processing.json >/dev/null
docker run --rm \
    --network "${CLIENT_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --env SSL_CERT_FILE=/certs/ca.crt \
    --env "PROCESSING_USER=${PROCESSING_USER}" \
    --env "PROCESSING_PASSWORD=${PROCESSING_PASSWORD}" \
    --mount "type=bind,src=${WORK_DIR}/mc,dst=/mc" \
    --mount "type=bind,src=${WORK_DIR}/minio/ca.crt,dst=/certs/ca.crt,readonly" \
    --entrypoint /bin/sh \
    "${MC_IMAGE}" -c \
        'mc --config-dir /mc admin user add gate "${PROCESSING_USER}" "${PROCESSING_PASSWORD}" >/dev/null && mc --config-dir /mc admin policy attach gate processing-live-gate --user "${PROCESSING_USER}" >/dev/null'

# Unit-level fail-closed coverage for absent/false/true/invalid bucket-key
# semantics remains part of the live profile gate rather than being inferred
# from the one server response shape used here.
cargo test -p warpin-object-storage --all-features bucket_key -- --nocapture

KES_BEFORE_WRITE="$(kes_success_count)"
run_live_test "${MINIO_PORT}" write
KES_AFTER_WRITE="$(kes_success_count)"
readonly KES_BEFORE_WRITE KES_AFTER_WRITE

LOGICAL_KEY="objects/live-${RUN_TOKEN}.json"
PATH_A="gate/${BUCKET}/live-gate/contexts/sha256=${CONTEXT_A_DIGEST}/${LOGICAL_KEY}"
PATH_B="gate/${BUCKET}/live-gate/contexts/sha256=${CONTEXT_B_DIGEST}/${LOGICAL_KEY}"
readonly LOGICAL_KEY PATH_A PATH_B
STAT_A="$(run_mc stat --json "${PATH_A}")"
STAT_B="$(run_mc stat --json "${PATH_B}")"
readonly STAT_A STAT_B

for stat in "${STAT_A}" "${STAT_B}"; do
    [[ "$(jq -r '.status' <<<"${stat}")" == 'success' ]]
    [[ "$(jq -r '.metadata["X-Amz-Server-Side-Encryption"]' <<<"${stat}")" == 'aws:kms' ]]
    [[ "$(jq -r '.metadata["X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"]' <<<"${stat}")" == "${KMS_KEY_IDENTITY}" ]]
    bucket_key_state="$(jq -r '.metadata["X-Amz-Server-Side-Encryption-Bucket-Key-Enabled"] // "absent"' <<<"${stat}")"
    [[ "${bucket_key_state}" == 'absent' || "${bucket_key_state}" == 'false' ]]
done

VERSION_A="$(jq -r '.versionID' <<<"${STAT_A}")"
VERSION_B="$(jq -r '.versionID' <<<"${STAT_B}")"
readonly VERSION_A VERSION_B
[[ -n "${VERSION_A}" && "${VERSION_A}" != 'null' ]]
[[ -n "${VERSION_B}" && "${VERSION_B}" != 'null' ]]

# Restart MinIO with the same immutable data and TLS/KES configuration. The
# post-restart library read is pinned to the two exact captured versions.
docker rm -f "${MINIO_NAME}" >/dev/null
start_minio
MINIO_PORT="$(docker port "${MINIO_NAME}" 9000/tcp | awk -F: 'NR == 1 { print $NF }')"
wait_for_https \
    "${WORK_DIR}/minio/ca.crt" \
    "https://localhost:${MINIO_PORT}/minio/health/ready"
KES_BEFORE_RESTART_READ="$(kes_success_count)"
run_live_test "${MINIO_PORT}" read "${VERSION_A}" "${VERSION_B}"
KES_AFTER_RESTART_READ="$(kes_success_count)"
readonly KES_BEFORE_RESTART_READ KES_AFTER_RESTART_READ

# The fixed KES release exposes only status-labelled aggregate request metrics,
# not route labels. Each snapshot accounts for its own prior metrics request,
# so subtract that one request before evaluating the two isolated phases. The
# operation meaning is inferred from the constrained Rust workflow: two managed
# writes in phase one, then two exact-version reads after MinIO restart.
WRITE_KES_OPERATIONS=$((KES_AFTER_WRITE - KES_BEFORE_WRITE - 1))
RESTART_READ_KES_OPERATIONS=$((KES_AFTER_RESTART_READ - KES_BEFORE_RESTART_READ - 1))
readonly WRITE_KES_OPERATIONS RESTART_READ_KES_OPERATIONS
if (( WRITE_KES_OPERATIONS < 1 )); then
    echo "insufficient controlled write-phase KES success delta: ${WRITE_KES_OPERATIONS}" >&2
    exit 1
fi
if (( RESTART_READ_KES_OPERATIONS < 1 )); then
    echo "insufficient controlled restart-read KES success delta: ${RESTART_READ_KES_OPERATIONS}" >&2
    exit 1
fi

KEY_IDENTITY_FINGERPRINT="$(printf '%s' "${KMS_KEY_IDENTITY}" | sha256sum | awk '{print $1}')"
readonly KEY_IDENTITY_FINGERPRINT
if ! cleanup_verified; then
    echo 'ephemeral resource cleanup verification failed' >&2
    exit 1
fi
trap - EXIT INT TERM
printf '%s\n' \
    'MinIO/KES compatibility gate: PASS' \
    'sse_kms=true' \
    "key_identity_fingerprint=sha256:${KEY_IDENTITY_FINGERPRINT}" \
    'context_bound_physical_objects=2' \
    'exact_version_post_restart_reads=2' \
    'kes_route_labels_available=false' \
    'inferred_generate_minimum=1' \
    "kes_write_phase_success_delta=${WRITE_KES_OPERATIONS}" \
    'inferred_post_restart_decrypt_minimum=1' \
    "kes_restart_read_success_delta=${RESTART_READ_KES_OPERATIONS}" \
    'ephemeral_resources_cleaned=true'
