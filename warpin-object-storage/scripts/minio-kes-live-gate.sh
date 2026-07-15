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
readonly KES_ONE_SHOT_PREFIX="warpin-kes-one-shot-gate-${RUN_TOKEN}"
readonly KES_ONE_SHOT_LABEL_KEY='com.warpin.live-gate.one-shot-run'
readonly KES_ONE_SHOT_LABEL_VALUE="${RUN_TOKEN}"
readonly KES_ONE_SHOT_LABEL="${KES_ONE_SHOT_LABEL_KEY}=${KES_ONE_SHOT_LABEL_VALUE}"
readonly KES_ONE_SHOT_LABEL_FILTER="label=${KES_ONE_SHOT_LABEL}"
readonly KES_ONE_SHOT_MAX_RECORDS=256
readonly KES_ONE_SHOT_MAX_RECORD_FILE_BYTES=65536
readonly KMS_NETWORK="warpin-kms-gate-${RUN_TOKEN}"
readonly CLIENT_NETWORK="warpin-client-gate-${RUN_TOKEN}"
readonly WORK_DIR="$(mktemp -d -t warpin-minio-kes-gate.XXXXXX)"
readonly ONE_SHOT_LEDGER="${WORK_DIR}/one-shot-containers.ledger"
readonly KES_SERVER_DIR="${WORK_DIR}/kes/server"
readonly KES_KEYSTORE_DIR="${WORK_DIR}/kes/keystore"
readonly KES_BOOTSTRAP_DIR="${WORK_DIR}/kes/bootstrap"
readonly KES_RUNTIME_DIR="${WORK_DIR}/kes/runtime"
readonly KES_METRICS_DIR="${WORK_DIR}/kes/metrics"

cleanup_best_effort() {
    local -a one_shot_containers=()
    collect_validated_one_shot_cleanup_names one_shot_containers || true
    if (( ${#one_shot_containers[@]} > 0 )); then
        docker rm -f -- "${one_shot_containers[@]}" >/dev/null 2>&1 || true
    fi
    docker rm -f -- "${MINIO_NAME}" "${KES_NAME}" >/dev/null 2>&1 || true
    docker network rm -- "${CLIENT_NETWORK}" "${KMS_NETWORK}" >/dev/null 2>&1 || true
    rm -rf -- "${WORK_DIR}" || true
}
trap cleanup_best_effort EXIT INT TERM

cleanup_verified() {
    local failed=0
    local -a one_shot_containers=()
    if ! collect_validated_one_shot_cleanup_names one_shot_containers; then
        failed=1
    fi
    if ! docker rm -f -- "${MINIO_NAME}" "${KES_NAME}" >/dev/null 2>&1; then
        failed=1
    fi
    local one_shot
    for one_shot in "${one_shot_containers[@]}"; do
        if docker container inspect -- "${one_shot}" >/dev/null 2>&1 \
            && ! docker rm -f -- "${one_shot}" >/dev/null 2>&1; then
            failed=1
        fi
    done
    local -a labeled_residuals=()
    if ! discover_labeled_one_shot_containers labeled_residuals \
        || (( ${#labeled_residuals[@]} > 0 )); then
        failed=1
    fi
    if ! docker network rm -- "${CLIENT_NETWORK}" "${KMS_NETWORK}" >/dev/null 2>&1; then
        failed=1
    fi
    if ! rm -rf -- "${WORK_DIR}"; then
        failed=1
    fi
    local container
    for container in "${MINIO_NAME}" "${KES_NAME}" "${one_shot_containers[@]}"; do
        if docker container inspect -- "${container}" >/dev/null 2>&1; then
            failed=1
        fi
    done
    local network
    for network in "${CLIENT_NETWORK}" "${KMS_NETWORK}"; do
        if docker network inspect -- "${network}" >/dev/null 2>&1; then
            failed=1
        fi
    done
    if [[ -e "${WORK_DIR}" || -L "${WORK_DIR}" ]]; then
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

assert_exact_private_key_set() {
    local directory="$1"
    local expected_name="$2"
    local -a keys=()
    local key
    for key in "${directory}"/*.key; do
        [[ -e "${key}" ]] || continue
        keys+=("$(basename -- "${key}")")
    done
    (( ${#keys[@]} == 1 )) && [[ "${keys[0]}" == "${expected_name}" ]]
}

parse_kes_success_count() {
    local snapshot="$1"
    if [[ -z "${snapshot}" ]]; then
        echo 'KES metrics snapshot was empty' >&2
        return 1
    fi
    local success_count
    if ! success_count="$(
        jq -esr '
            if length == 1
                and (.[0] | type) == "object"
                and (.[0].kes_http_request_success | type) == "number"
                and .[0].kes_http_request_success >= 0
                and (.[0].kes_http_request_success | floor) == .[0].kes_http_request_success
            then .[0].kes_http_request_success
            else error("expected one metrics object with a non-negative integer success count")
            end
        ' <<<"${snapshot}"
    )"; then
        echo 'KES metrics snapshot was not one valid JSON document' >&2
        return 1
    fi
    printf '%s\n' "${success_count}"
}

validate_one_shot_container_name() {
    local client_name="$1"
    local identity_name="$2"
    local LC_ALL=C
    case "${identity_name}" in
        bootstrap|metrics) ;;
        *) return 1 ;;
    esac
    local expected_prefix="${KES_ONE_SHOT_PREFIX}-${identity_name}-"
    [[ "${client_name}" == "${expected_prefix}"?* ]] \
        && (( ${#client_name} <= 128 )) \
        && [[ "${client_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

validate_one_shot_container_record() {
    local client_name="$1"
    validate_one_shot_container_name "${client_name}" bootstrap \
        || validate_one_shot_container_name "${client_name}" metrics
}

validate_private_work_dir() {
    [[ ! -L "${WORK_DIR}" && -d "${WORK_DIR}" ]]
}

validate_one_shot_label_contract() {
    local LC_ALL=C
    [[ "${KES_ONE_SHOT_LABEL_KEY}" =~ ^[a-z][a-z0-9.-]*[a-z0-9]$ ]] \
        && [[ "${KES_ONE_SHOT_LABEL_VALUE}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
        && (( ${#KES_ONE_SHOT_LABEL_VALUE} <= 128 )) \
        && [[ "${KES_ONE_SHOT_LABEL}" \
            == "${KES_ONE_SHOT_LABEL_KEY}=${KES_ONE_SHOT_LABEL_VALUE}" ]] \
        && [[ "${KES_ONE_SHOT_LABEL_FILTER}" == "label=${KES_ONE_SHOT_LABEL}" ]]
}

load_validated_one_shot_record_file() {
    local record_file="$1"
    local existence_policy="$2"
    local output_name="$3"
    local -n output_ref="${output_name}"
    output_ref=()
    validate_private_work_dir || return 1
    case "${record_file}" in
        "${ONE_SHOT_LEDGER}")
            [[ "${existence_policy}" == 'allow-absent' ]] || return 1
            ;;
        "${WORK_DIR}"/one-shot-containers.next.*|\
            "${WORK_DIR}"/one-shot-discovery.*)
            [[ "${existence_policy}" == 'require-existing' ]] || return 1
            [[ "${record_file#"${WORK_DIR}/"}" != */* ]] || return 1
            ;;
        *) return 1 ;;
    esac
    if [[ -L "${record_file}" ]]; then
        return 1
    fi
    if [[ ! -e "${record_file}" ]]; then
        [[ "${existence_policy}" == 'allow-absent' ]]
        return
    fi
    if [[ ! -f "${record_file}" ]]; then
        return 1
    fi

    local LC_ALL=C
    local actual_bytes
    actual_bytes="$(wc -c <"${record_file}")" || return 1
    if [[ ! "${actual_bytes}" =~ ^[0-9]+$ ]] \
        || (( actual_bytes > KES_ONE_SHOT_MAX_RECORD_FILE_BYTES )); then
        return 1
    fi
    local -a validated_records=()
    local -A seen_records=()
    local record=''
    local expected_bytes=0
    while IFS= read -r record; do
        if (( ${#validated_records[@]} >= KES_ONE_SHOT_MAX_RECORDS )); then
            return 1
        fi
        validate_one_shot_container_record "${record}" || return 1
        if [[ -n "${seen_records[${record}]:-}" ]]; then
            return 1
        fi
        seen_records["${record}"]=1
        validated_records+=("${record}")
        expected_bytes=$((expected_bytes + ${#record} + 1))
    done <"${record_file}"
    if [[ -n "${record}" ]]; then
        return 1
    fi
    if (( actual_bytes != expected_bytes )); then
        return 1
    fi
    output_ref=("${validated_records[@]}")
}

remove_one_shot_discovery_temp() {
    local discovery_file="$1"
    validate_private_work_dir || return 1
    [[ "${discovery_file}" == "${WORK_DIR}/one-shot-discovery."?* ]] \
        || return 1
    rm -rf -- "${discovery_file}" >/dev/null 2>&1 || return 1
    [[ ! -e "${discovery_file}" && ! -L "${discovery_file}" ]]
}

discover_labeled_one_shot_containers() {
    local output_name="$1"
    local -n output_ref="${output_name}"
    output_ref=()
    validate_private_work_dir || return 1
    validate_one_shot_label_contract || return 1
    local discovery_file
    discovery_file="$(
        mktemp "${WORK_DIR}/one-shot-discovery.XXXXXX" 2>/dev/null
    )" || return 1
    local -a empty_preflight=()
    if ! load_validated_one_shot_record_file \
        "${discovery_file}" require-existing empty_preflight \
        || (( ${#empty_preflight[@]} != 0 )); then
        remove_one_shot_discovery_temp "${discovery_file}" || true
        return 1
    fi
    if ! docker container ls \
        --all \
        --filter "${KES_ONE_SHOT_LABEL_FILTER}" \
        --format '{{.Names}}' \
        2>/dev/null >"${discovery_file}"; then
        remove_one_shot_discovery_temp "${discovery_file}" || true
        return 1
    fi
    local -a validated_names=()
    if ! load_validated_one_shot_record_file \
        "${discovery_file}" require-existing validated_names; then
        remove_one_shot_discovery_temp "${discovery_file}" || true
        return 1
    fi
    if ! remove_one_shot_discovery_temp "${discovery_file}"; then
        return 1
    fi
    output_ref=("${validated_names[@]}")
}

collect_validated_one_shot_cleanup_names() {
    local output_name="$1"
    local -n output_ref="${output_name}"
    output_ref=()
    local invalid_source=0
    local -a ledger_names=()
    local -a labeled_names=()
    if ! load_validated_one_shot_record_file \
        "${ONE_SHOT_LEDGER}" allow-absent ledger_names; then
        invalid_source=1
        ledger_names=()
    fi
    if ! discover_labeled_one_shot_containers labeled_names; then
        invalid_source=1
        labeled_names=()
    fi

    local -A seen_names=()
    local one_shot_name
    for one_shot_name in "${ledger_names[@]}" "${labeled_names[@]}"; do
        validate_one_shot_container_record "${one_shot_name}" || {
            invalid_source=1
            continue
        }
        if [[ -z "${seen_names[${one_shot_name}]:-}" ]]; then
            seen_names["${one_shot_name}"]=1
            output_ref+=("${one_shot_name}")
        fi
    done
    (( invalid_source == 0 ))
}

register_one_shot_container() {
    local client_name="$1"
    local identity_name="$2"
    validate_private_work_dir || return 1
    validate_one_shot_container_name "${client_name}" "${identity_name}" \
        || return 1
    local -a existing_records=()
    load_validated_one_shot_record_file \
        "${ONE_SHOT_LEDGER}" allow-absent existing_records || return 1
    local existing_record
    for existing_record in "${existing_records[@]}"; do
        [[ "${existing_record}" != "${client_name}" ]] || return 1
    done

    local next_ledger
    next_ledger="$(mktemp "${WORK_DIR}/one-shot-containers.next.XXXXXX")" \
        || return 1
    if ! {
        for existing_record in "${existing_records[@]}"; do
            printf '%s\n' "${existing_record}"
        done
        printf '%s\n' "${client_name}"
    } >"${next_ledger}"; then
        rm -f -- "${next_ledger}"
        return 1
    fi
    local -a candidate_records=()
    if ! load_validated_one_shot_record_file \
        "${next_ledger}" require-existing candidate_records \
        || (( ${#candidate_records[@]} != ${#existing_records[@]} + 1 )) \
        || [[ "${candidate_records[-1]}" != "${client_name}" ]] \
        || [[ -L "${ONE_SHOT_LEDGER}" ]] \
        || [[ -e "${ONE_SHOT_LEDGER}" && ! -f "${ONE_SHOT_LEDGER}" ]] \
        || ! mv -fT -- "${next_ledger}" "${ONE_SHOT_LEDGER}"; then
        rm -f -- "${next_ledger}"
        return 1
    fi
}

self_check() {
    local fake_docker_state='absent'
    local fake_one_shot="${KES_ONE_SHOT_PREFIX}-metrics-self-check"
    local fake_created_name=''
    local fake_container_present=0
    local fake_forbidden_docker_argument=''
    local fake_forbidden_docker_argument_seen=0
    local fake_discovery_temp_mode='normal'
    local fake_discovery_temp_path="${WORK_DIR}/one-shot-discovery.self-check"
    local fake_discovery_symlink_target="${WORK_DIR}/self-check-discovery-target"
    local fake_create_marker="${WORK_DIR}/self-check-created-container"
    local fake_create_count_file="${WORK_DIR}/self-check-create-count"
    local policy_file="${WORK_DIR}/self-check-kes.yml"
    local bootstrap_policy
    local runtime_policy
    local metrics_policy
    local secret_layout="${WORK_DIR}/self-check-secret-layout"
    mktemp() {
        local template="${1:-}"
        if [[ "${template}" == "${WORK_DIR}/one-shot-discovery."* ]]; then
            rm -rf -- "${fake_discovery_temp_path:-}"
            case "${fake_discovery_temp_mode:-normal}" in
                failure)
                    return 73
                    ;;
                symlink)
                    ln -s -- \
                        "${fake_discovery_symlink_target}" \
                        "${fake_discovery_temp_path}"
                    printf '%s\n' "${fake_discovery_temp_path}"
                    return 0
                    ;;
                directory)
                    mkdir "${fake_discovery_temp_path}"
                    printf '%s\n' "${fake_discovery_temp_path}"
                    return 0
                    ;;
                unwritable)
                    : >"${fake_discovery_temp_path}"
                    chmod 400 "${fake_discovery_temp_path}"
                    printf '%s\n' "${fake_discovery_temp_path}"
                    return 0
                    ;;
                normal) ;;
                *) return 74 ;;
            esac
        fi
        command mktemp "$@"
    }
    docker() {
        local argument
        if [[ -n "${fake_forbidden_docker_argument:-}" ]]; then
            for argument in "$@"; do
                if [[ "${argument}" == "${fake_forbidden_docker_argument}" ]]; then
                    fake_forbidden_docker_argument_seen=1
                fi
            done
        fi
        case "${1:-} ${2:-}" in
            create\ *)
                local create_count=0
                if [[ -f "${fake_create_count_file}" ]]; then
                    create_count="$(<"${fake_create_count_file}")"
                fi
                printf '%s\n' "$((create_count + 1))" >"${fake_create_count_file}"
                if [[ "${fake_docker_state}" == 'client-nonzero' \
                    || "${fake_docker_state}" == 'after-create-interruption' \
                    || "${fake_docker_state}" == 'ledger-append-failure' \
                    || "${fake_docker_state}" == 'create-empty-id' ]]; then
                    local previous_argument=''
                    for argument in "${@:2}"; do
                        if [[ "${previous_argument}" == '--name' ]]; then
                            printf '%s\n' "${argument}" >"${fake_create_marker}"
                            break
                        fi
                        previous_argument="${argument}"
                    done
                    if [[ "${fake_docker_state}" != 'create-empty-id' ]]; then
                        printf '%s\n' 'fake-one-shot-container-id'
                    fi
                    return 0
                fi
                if [[ "${fake_docker_state}" == 'create-failure' ]]; then
                    return 55
                fi
                return 1
                ;;
            'rm -f')
                if [[ "${fake_docker_state:-absent}" == 'remove-failure' ]]; then
                    return 1
                fi
                if [[ "${fake_docker_state:-absent}" == 'one-shot-remove-failure' ]]; then
                    for argument in "${@:3}"; do
                        if [[ "${argument}" == "${fake_one_shot:-}" ]]; then
                            return 1
                        fi
                    done
                fi
                for argument in "${@:3}"; do
                    if [[ -n "${fake_create_marker:-}" && -f "${fake_create_marker}" ]] \
                        && [[ "${argument}" == "$(<"${fake_create_marker}")" ]]; then
                        rm -f -- "${fake_create_marker}"
                    fi
                    if (( ${fake_container_present:-0} == 1 )) \
                        && [[ "${argument}" == "${fake_created_name:-}" ]]; then
                        fake_container_present=0
                    fi
                done
                return 0
                ;;
            'network rm')
                [[ "${fake_docker_state:-absent}" != 'remove-failure' ]]
                ;;
            'container ls')
                case "${fake_docker_state:-absent}" in
                    discovery-empty-output)
                        :
                        ;;
                    discovery-empty-line)
                        printf '\n'
                        ;;
                    discovery-trailing-empty)
                        printf '%s\n\n' "${fake_created_name:-}"
                        ;;
                    discovery-missing-final-newline)
                        printf '%s' "${fake_created_name:-}"
                        ;;
                    discovery-nul)
                        printf '%s\0%s\n' \
                            "${KES_ONE_SHOT_PREFIX}-metrics-label-" \
                            'fallback'
                        ;;
                    discovery-control)
                        printf '%s\t%s\n' \
                            "${KES_ONE_SHOT_PREFIX}-metrics-label-" \
                            'fallback'
                        ;;
                    discovery-valid)
                        printf '%s\n' "${fake_created_name:-}"
                        ;;
                    discovery-duplicate)
                        printf '%s\n%s\n' \
                            "${fake_created_name:-}" \
                            "${fake_created_name:-}"
                        ;;
                    discovery-invalid)
                        printf '%s\n' '--help'
                        ;;
                    discovery-docker-failure)
                        printf '%s\n' 'FORBIDDEN_DISCOVERY_SECRET_42' >&2
                        return 42
                        ;;
                    labeled-one-shot-present)
                        if (( ${fake_container_present:-0} == 1 )); then
                            printf '%s\n' "${fake_created_name:-}"
                        fi
                        ;;
                    labeled-one-shot-invalid)
                        printf '%s\n' '--help'
                        ;;
                    labeled-one-shot-wrong-run)
                        printf '%s\n' 'warpin-kes-one-shot-gate-wrong-run-metrics-label'
                        ;;
                    labeled-one-shot-wrong-identity)
                        printf '%s\n' "${KES_ONE_SHOT_PREFIX}-runtime-label"
                        ;;
                    labeled-one-shot-empty-record)
                        printf '%s\n\n%s\n' \
                            "${fake_created_name:-}" \
                            "${KES_ONE_SHOT_PREFIX}-bootstrap-label-second"
                        ;;
                    labeled-one-shot-duplicate)
                        printf '%s\n%s\n' \
                            "${fake_created_name:-}" \
                            "${fake_created_name:-}"
                        ;;
                    *) ;;
                esac
                ;;
            'container inspect'|'network inspect')
                local inspected_name=''
                if (( $# > 0 )); then
                    inspected_name="${!#}"
                fi
                if [[ "${fake_docker_state}" == 'client-nonzero' && "${1:-}" == 'container' ]]; then
                    printf '[{"Mounts":['
                    printf '{"Type":"bind","Source":"%s","Destination":"/identity","RW":false},' \
                        "${KES_METRICS_DIR}"
                    printf '{"Type":"bind","Source":"%s","Destination":"/trust/server.crt","RW":false}' \
                        "${KES_SERVER_DIR}/server.crt"
                    printf ']}]\n'
                    return 0
                fi
                case "${fake_docker_state}" in
                    present)
                        return 0
                        ;;
                    one-container-remains)
                        [[ "${1:-}" == 'container' \
                            && "${inspected_name}" == "${MINIO_NAME}" ]]
                        ;;
                    one-network-remains)
                        [[ "${1:-}" == 'network' \
                            && "${inspected_name}" == "${CLIENT_NETWORK}" ]]
                        ;;
                    one-shot-remains|one-shot-remove-failure)
                        [[ "${1:-}" == 'container' \
                            && "${inspected_name}" == "${fake_one_shot}" ]]
                        ;;
                    labeled-one-shot-present|discovery-trailing-empty|\
                        discovery-missing-final-newline|discovery-nul)
                        [[ "${1:-}" == 'container' \
                            && ${fake_container_present:-0} -eq 1 \
                            && "${inspected_name}" == "${fake_created_name:-}" ]]
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
    start_one_shot_client() {
        if [[ "${fake_docker_state}" == 'client-nonzero' ]]; then
            printf '%s\n' 'FORBIDDEN_RAW_CONTAINER_OUTPUT_42'
            return 42
        fi
        return 1
    }
    after_one_shot_create() {
        if [[ "${fake_docker_state}" == 'after-create-interruption' ]]; then
            fake_created_name="$(<"${fake_create_marker}")"
            fake_container_present=1
            cleanup_best_effort
            return 130
        fi
        return 0
    }
    before_one_shot_create() {
        if [[ "${fake_docker_state}" == 'before-create-interruption' ]]; then
            return 130
        fi
        return 0
    }
    reset_one_shot_boundary_fixture() {
        mkdir -p "${WORK_DIR}" "${KES_METRICS_DIR}" "${KES_SERVER_DIR}"
        rm -rf -- "${ONE_SHOT_LEDGER}"
        rm -f -- "${fake_create_marker}" "${fake_create_count_file}"
        fake_created_name=''
        fake_container_present=0
    }
    fake_create_count() {
        if [[ -f "${fake_create_count_file}" ]]; then
            printf '%s\n' "$(<"${fake_create_count_file}")"
        else
            printf '%s\n' 0
        fi
    }

    local -a discovery_byte_failures=()
    assert_no_discovery_temp_remains() {
        local fixture_name="$1"
        local leftover_path
        while IFS= read -r leftover_path; do
            discovery_byte_failures+=(
                "self-check left a discovery temp after ${fixture_name}"
            )
            rm -rf -- "${leftover_path}"
        done < <(
            find "${WORK_DIR}" -maxdepth 1 \
                -name 'one-shot-discovery.*' -print 2>/dev/null
        )
    }
    discovery_bytes_must_match() {
        local fixture_name="$1"
        local docker_state="$2"
        local expected_status="$3"
        local expected_count="$4"
        mkdir -p "${WORK_DIR}"
        fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
        fake_docker_state="${docker_state}"
        fake_discovery_temp_mode='normal'
        local -a discovered_names=()
        local actual_status='failure'
        if discover_labeled_one_shot_containers discovered_names; then
            actual_status='success'
        fi
        if [[ "${actual_status}" != "${expected_status}" ]]; then
            discovery_byte_failures+=(
                "self-check gave ${fixture_name} discovery status ${actual_status}"
            )
        fi
        if (( ${#discovered_names[@]} != expected_count )); then
            discovery_byte_failures+=(
                "self-check published names for ${fixture_name} discovery bytes"
            )
        fi
        if [[ "${expected_status}" == 'success' && expected_count -eq 1 ]] \
            && [[ "${discovered_names[0]:-}" != "${fake_created_name}" ]]; then
            discovery_byte_failures+=(
                "self-check changed the canonical valid discovery name"
            )
        fi
        assert_no_discovery_temp_remains "${fixture_name}"
    }
    discovery_temp_mode_must_fail() {
        local temp_mode="$1"
        mkdir -p "${WORK_DIR}"
        fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
        fake_docker_state='discovery-valid'
        fake_discovery_temp_mode="${temp_mode}"
        local -a discovered_names=()
        if discover_labeled_one_shot_containers discovered_names; then
            discovery_byte_failures+=(
                "self-check accepted ${temp_mode} discovery temp"
            )
        fi
        if (( ${#discovered_names[@]} != 0 )); then
            discovery_byte_failures+=(
                "self-check published names after ${temp_mode} discovery temp"
            )
        fi
        assert_no_discovery_temp_remains "${temp_mode} temp"
        fake_discovery_temp_mode='normal'
    }

    local -a ledger_attack_failures=()
    registration_fixture_must_fail_closed() {
        local fixture_name="$1"
        fake_docker_state='create-failure'
        if run_kes_client metrics metric >/dev/null 2>&1; then
            ledger_attack_failures+=(
                "self-check accepted ${fixture_name} during registration"
            )
        fi
        if [[ "$(fake_create_count)" -ne 0 ]]; then
            ledger_attack_failures+=(
                "self-check called docker create for ${fixture_name}"
            )
        fi
    }
    regular_ledger_fixture_must_fail_closed() {
        local fixture_name="$1"
        local fixture_content="$2"
        local original_ledger="${WORK_DIR}/self-check-original-ledger"
        reset_one_shot_boundary_fixture
        printf '%s' "${fixture_content}" >"${ONE_SHOT_LEDGER}"
        cp -- "${ONE_SHOT_LEDGER}" "${original_ledger}"
        registration_fixture_must_fail_closed "${fixture_name}"
        if [[ ! -f "${ONE_SHOT_LEDGER}" ]] \
            || ! cmp -s -- "${original_ledger}" "${ONE_SHOT_LEDGER}"; then
            ledger_attack_failures+=(
                "self-check changed ${fixture_name} after rejected registration"
            )
        fi
    }

    render_kes_config "${policy_file}" bootstrap-id runtime-id metrics-id

    mkdir -p \
        "${secret_layout}/server" \
        "${secret_layout}/bootstrap" \
        "${secret_layout}/runtime" \
        "${secret_layout}/metrics"
    : >"${secret_layout}/server/server.key"
    : >"${secret_layout}/bootstrap/bootstrap.key"
    : >"${secret_layout}/runtime/runtime.key"
    : >"${secret_layout}/metrics/metrics.key"
    assert_exact_private_key_set "${secret_layout}/server" server.key
    assert_exact_private_key_set "${secret_layout}/bootstrap" bootstrap.key
    assert_exact_private_key_set "${secret_layout}/runtime" runtime.key
    assert_exact_private_key_set "${secret_layout}/metrics" metrics.key
    if assert_exact_private_key_set "${secret_layout}/server" bootstrap.key; then
        echo 'self-check accepted a cross-identity private key set' >&2
        return 1
    fi
    if (( $(grep -Fc -- '--mount "type=bind,src=${WORK_DIR}/kes,dst=/config,readonly"' "${BASH_SOURCE[0]}") > 1 )); then
        echo 'self-check found the legacy shared KES server secret mount' >&2
        return 1
    fi
    if declare -f kes_exec | grep -Fq 'docker exec'; then
        echo 'self-check found metrics credentials executed inside the KES server' >&2
        return 1
    fi
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
    if [[ "$(parse_kes_success_count '{"kes_http_request_success":12}')" != 12 ]]; then
        echo 'self-check rejected one valid KES metrics document' >&2
        return 1
    fi
    local invalid_metrics
    for invalid_metrics in \
        '' \
        '{}' \
        '{"kes_http_request_success":' \
        '{"kes_http_request_success":-1}' \
        '{"kes_http_request_success":1.5}' \
        $'{"kes_http_request_success":1}\n{"kes_http_request_success":2}'; do
        if parse_kes_success_count "${invalid_metrics}" >/dev/null 2>&1; then
            echo 'self-check accepted an invalid KES metrics snapshot' >&2
            return 1
        fi
    done
    local valid_client_name="${KES_ONE_SHOT_PREFIX}-metrics-Valid_1.2"
    if ! register_one_shot_container "${valid_client_name}" metrics; then
        echo 'self-check rejected a valid one-shot container name' >&2
        return 1
    fi
    if [[ "$(<"${ONE_SHOT_LEDGER}")" != "${valid_client_name}" ]]; then
        echo 'self-check did not register exactly one valid container name' >&2
        return 1
    fi
    local overlong_suffix
    printf -v overlong_suffix '%*s' 130 ''
    overlong_suffix="${overlong_suffix// /a}"
    local invalid_client_name
    for invalid_client_name in \
        "${KES_ONE_SHOT_PREFIX}-metrics-bad"$'\n''name' \
        "${KES_ONE_SHOT_PREFIX}-metrics-bad/name" \
        "-${KES_ONE_SHOT_PREFIX}-metrics-leading" \
        "${KES_ONE_SHOT_PREFIX}-bootstrap-wrong-identity" \
        "${KES_ONE_SHOT_PREFIX}-metrics-${overlong_suffix}"; do
        if register_one_shot_container "${invalid_client_name}" metrics >/dev/null 2>&1; then
            echo 'self-check accepted an invalid one-shot container name' >&2
            return 1
        fi
    done
    if [[ "$(wc -l <"${ONE_SHOT_LEDGER}")" -ne 1 ]]; then
        echo 'self-check allowed an invalid name to alter the cleanup ledger' >&2
        return 1
    fi
    local sequence
    for sequence in {2..12}; do
        if ! register_one_shot_container \
            "${KES_ONE_SHOT_PREFIX}-metrics-history-${sequence}" \
            metrics; then
            echo 'self-check failed to append a sequential one-shot name' >&2
            return 1
        fi
    done
    if [[ "$(wc -l <"${ONE_SHOT_LEDGER}")" -ne 12 ]] \
        || [[ "$(sort -u "${ONE_SHOT_LEDGER}" | wc -l)" -ne 12 ]] \
        || [[ "$(head -n 1 "${ONE_SHOT_LEDGER}")" != "${valid_client_name}" ]] \
        || [[ "$(tail -n 1 "${ONE_SHOT_LEDGER}")" \
            != "${KES_ONE_SHOT_PREFIX}-metrics-history-12" ]]; then
        echo 'self-check lost or replaced sequential cleanup-ledger names' >&2
        return 1
    fi

    local real_work_dir="${WORK_DIR}.self-check-real"
    local symlink_work_dir_target="${WORK_DIR}.self-check-target"
    reset_one_shot_boundary_fixture
    rm -rf -- "${real_work_dir}" "${symlink_work_dir_target}"
    mv -- "${WORK_DIR}" "${real_work_dir}"
    mkdir "${symlink_work_dir_target}"
    ln -s -- "${symlink_work_dir_target}" "${WORK_DIR}"
    registration_fixture_must_fail_closed 'a symlinked private work directory'
    if find "${symlink_work_dir_target}" -mindepth 1 -print -quit | grep -q .; then
        ledger_attack_failures+=(
            'self-check wrote through a symlinked private work directory'
        )
    fi
    rm -f -- "${WORK_DIR}"
    rm -rf -- "${symlink_work_dir_target}"
    mv -- "${real_work_dir}" "${WORK_DIR}"

    local symlink_target="${WORK_DIR}/self-check-ledger-symlink-target"
    local symlink_target_before="${WORK_DIR}/self-check-ledger-symlink-target.before"
    reset_one_shot_boundary_fixture
    printf '%s\n' '--help' >"${symlink_target}"
    cp -- "${symlink_target}" "${symlink_target_before}"
    ln -s -- "${symlink_target}" "${ONE_SHOT_LEDGER}"
    registration_fixture_must_fail_closed 'a ledger symlink to a regular file'
    if [[ ! -L "${ONE_SHOT_LEDGER}" ]] \
        || [[ "$(readlink -- "${ONE_SHOT_LEDGER}")" != "${symlink_target}" ]] \
        || ! cmp -s -- "${symlink_target_before}" "${symlink_target}"; then
        ledger_attack_failures+=(
            'self-check changed a ledger symlink or its external target'
        )
    fi

    reset_one_shot_boundary_fixture
    local dangling_target="${WORK_DIR}/self-check-missing-ledger-target"
    rm -f -- "${dangling_target}"
    ln -s -- "${dangling_target}" "${ONE_SHOT_LEDGER}"
    registration_fixture_must_fail_closed 'a dangling ledger symlink'
    if [[ ! -L "${ONE_SHOT_LEDGER}" ]] \
        || [[ "$(readlink -- "${ONE_SHOT_LEDGER}")" != "${dangling_target}" ]]; then
        ledger_attack_failures+=(
            'self-check replaced a dangling ledger symlink'
        )
    fi

    reset_one_shot_boundary_fixture
    mkdir "${ONE_SHOT_LEDGER}"
    registration_fixture_must_fail_closed 'a ledger directory'
    if [[ ! -d "${ONE_SHOT_LEDGER}" || -L "${ONE_SHOT_LEDGER}" ]]; then
        ledger_attack_failures+=('self-check changed a rejected ledger directory')
    fi

    reset_one_shot_boundary_fixture
    mkfifo "${ONE_SHOT_LEDGER}"
    registration_fixture_must_fail_closed 'a ledger FIFO'
    if [[ ! -p "${ONE_SHOT_LEDGER}" || -L "${ONE_SHOT_LEDGER}" ]]; then
        ledger_attack_failures+=('self-check changed a rejected ledger FIFO')
    fi

    local history_name="${KES_ONE_SHOT_PREFIX}-metrics-history-valid"
    local wrong_run_name='warpin-kes-one-shot-gate-wrong-run-metrics-history'
    local wrong_identity_name="${KES_ONE_SHOT_PREFIX}-runtime-history"
    local overlong_history_name="${KES_ONE_SHOT_PREFIX}-metrics-${overlong_suffix}"
    regular_ledger_fixture_must_fail_closed \
        'an option-like historical ledger record' \
        $'--help\n'
    regular_ledger_fixture_must_fail_closed \
        'a wrong-run historical ledger record' \
        "${wrong_run_name}"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'an unsupported-identity historical ledger record' \
        "${wrong_identity_name}"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'an empty historical ledger record' \
        $'\n'
    regular_ledger_fixture_must_fail_closed \
        'a control-character historical ledger record' \
        "${KES_ONE_SHOT_PREFIX}-metrics-bad"$'\t'"record"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'a whitespace historical ledger record' \
        "${KES_ONE_SHOT_PREFIX}-metrics-bad record"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'an overlong historical ledger record' \
        "${overlong_history_name}"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'an invalid-Docker-character historical ledger record' \
        "${KES_ONE_SHOT_PREFIX}-metrics-bad/record"$'\n'
    regular_ledger_fixture_must_fail_closed \
        'a non-newline-terminated historical ledger record' \
        "${history_name}"
    regular_ledger_fixture_must_fail_closed \
        'duplicate historical ledger records' \
        "${history_name}"$'\n'"${history_name}"$'\n'

    reset_one_shot_boundary_fixture
    printf '%s\n' '--help' >"${ONE_SHOT_LEDGER}"
    fake_docker_state='absent'
    fake_forbidden_docker_argument='--help'
    fake_forbidden_docker_argument_seen=0
    cleanup_best_effort
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        ledger_attack_failures+=(
            'self-check passed an untrusted ledger record to best-effort Docker cleanup'
        )
    fi

    mkdir -p "${WORK_DIR}"
    printf '%s\n' '--help' >"${ONE_SHOT_LEDGER}"
    fake_forbidden_docker_argument_seen=0
    if cleanup_verified; then
        ledger_attack_failures+=(
            'self-check attested verified cleanup for a corrupt ledger'
        )
    fi
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        ledger_attack_failures+=(
            'self-check passed an untrusted ledger record to verified Docker cleanup'
        )
    fi

    mkdir -p "${WORK_DIR}"
    printf '%s\n' '--help' >"${ONE_SHOT_LEDGER}"
    fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
    fake_container_present=1
    fake_docker_state='labeled-one-shot-present'
    fake_forbidden_docker_argument_seen=0
    cleanup_best_effort
    if (( fake_container_present != 0 )); then
        ledger_attack_failures+=(
            'self-check did not use the run label to clean a corrupt-ledger container'
        )
    fi
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        ledger_attack_failures+=(
            'self-check passed corrupt ledger bytes during label fallback cleanup'
        )
    fi

    mkdir -p "${WORK_DIR}"
    printf '%s\n' '--help' >"${ONE_SHOT_LEDGER}"
    fake_container_present=1
    fake_docker_state='labeled-one-shot-present'
    fake_forbidden_docker_argument_seen=0
    if cleanup_verified; then
        ledger_attack_failures+=(
            'self-check hid ledger corruption behind successful label fallback cleanup'
        )
    fi
    if (( fake_container_present != 0 )); then
        ledger_attack_failures+=(
            'self-check verified cleanup left a run-labeled one-shot container'
        )
    fi
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        ledger_attack_failures+=(
            'self-check verified fallback passed corrupt ledger bytes to Docker'
        )
    fi

    local invalid_discovery_state
    for invalid_discovery_state in \
        labeled-one-shot-invalid \
        labeled-one-shot-wrong-run \
        labeled-one-shot-wrong-identity \
        labeled-one-shot-empty-record \
        labeled-one-shot-duplicate; do
        mkdir -p "${WORK_DIR}"
        : >"${ONE_SHOT_LEDGER}"
        fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
        fake_container_present=0
        fake_docker_state="${invalid_discovery_state}"
        fake_forbidden_docker_argument_seen=0
        if cleanup_verified; then
            ledger_attack_failures+=(
                "self-check accepted ${invalid_discovery_state} discovery output"
            )
        fi
        if (( fake_forbidden_docker_argument_seen != 0 )); then
            ledger_attack_failures+=(
                "self-check passed ${invalid_discovery_state} output to Docker"
            )
        fi
    done

    mkdir -p "${WORK_DIR}"
    : >"${ONE_SHOT_LEDGER}"
    fake_docker_state='absent'
    if ! cleanup_verified; then
        ledger_attack_failures+=(
            'self-check rejected a completely empty label discovery result'
        )
    fi

    mkdir -p "${WORK_DIR}"
    printf '%s\n' '--help' >"${ONE_SHOT_LEDGER}"
    fake_docker_state='labeled-one-shot-invalid'
    fake_forbidden_docker_argument_seen=0
    if cleanup_verified; then
        ledger_attack_failures+=(
            'self-check accepted corrupt ledger plus malicious label discovery output'
        )
    fi
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        ledger_attack_failures+=(
            'self-check passed corrupt ledger or malicious label output to Docker'
        )
    fi

    discovery_bytes_must_match \
        'zero-byte' discovery-empty-output success 0
    discovery_bytes_must_match \
        'single-newline' discovery-empty-line failure 0
    discovery_bytes_must_match \
        'trailing-empty-record' discovery-trailing-empty failure 0
    discovery_bytes_must_match \
        'missing-final-newline' discovery-missing-final-newline failure 0
    discovery_bytes_must_match \
        'embedded-NUL' discovery-nul failure 0
    discovery_bytes_must_match \
        'embedded-control' discovery-control failure 0
    discovery_bytes_must_match \
        'duplicate-record' discovery-duplicate failure 0
    discovery_bytes_must_match \
        'invalid-record' discovery-invalid failure 0
    discovery_bytes_must_match \
        'canonical-valid-record' discovery-valid success 1

    printf '%s\n' 'UNCHANGED_DISCOVERY_TARGET' \
        >"${fake_discovery_symlink_target}"
    local discovery_target_before
    discovery_target_before="$(sha256sum "${fake_discovery_symlink_target}")"
    discovery_temp_mode_must_fail failure
    discovery_temp_mode_must_fail symlink
    if [[ "$(sha256sum "${fake_discovery_symlink_target}")" \
        != "${discovery_target_before}" ]]; then
        discovery_byte_failures+=(
            'self-check changed an external discovery-temp symlink target'
        )
    fi
    discovery_temp_mode_must_fail directory
    discovery_temp_mode_must_fail unwritable

    mkdir -p "${WORK_DIR}"
    fake_docker_state='discovery-docker-failure'
    fake_discovery_temp_mode='normal'
    local discovery_error_file="${WORK_DIR}/self-check-discovery-error"
    local -a failed_discovery_names=()
    if discover_labeled_one_shot_containers failed_discovery_names \
        2>"${discovery_error_file}"; then
        discovery_byte_failures+=(
            'self-check accepted a nonzero Docker discovery command'
        )
    fi
    if (( ${#failed_discovery_names[@]} != 0 )); then
        discovery_byte_failures+=(
            'self-check published names after Docker discovery failure'
        )
    fi
    if grep -Fq 'FORBIDDEN_DISCOVERY_SECRET_42' "${discovery_error_file}"; then
        discovery_byte_failures+=(
            'self-check leaked Docker discovery stderr'
        )
    fi
    rm -f -- "${discovery_error_file}"
    assert_no_discovery_temp_remains 'Docker command failure'

    mkdir -p "${WORK_DIR}"
    : >"${ONE_SHOT_LEDGER}"
    fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
    fake_container_present=1
    fake_docker_state='discovery-empty-line'
    fake_forbidden_docker_argument="${fake_created_name}"
    fake_forbidden_docker_argument_seen=0
    if cleanup_verified; then
        discovery_byte_failures+=(
            'self-check hid a residual behind newline-only discovery bytes'
        )
    fi
    if (( fake_container_present != 1 )); then
        discovery_byte_failures+=(
            'self-check consumed newline-only discovery as a container operand'
        )
    fi
    if (( fake_forbidden_docker_argument_seen != 0 )); then
        discovery_byte_failures+=(
            'self-check passed newline-only discovery to Docker'
        )
    fi
    fake_container_present=0

    local normalized_discovery_state
    for normalized_discovery_state in \
        discovery-trailing-empty \
        discovery-missing-final-newline \
        discovery-nul; do
        mkdir -p "${WORK_DIR}"
        : >"${ONE_SHOT_LEDGER}"
        fake_created_name="${KES_ONE_SHOT_PREFIX}-metrics-label-fallback"
        fake_container_present=1
        fake_docker_state="${normalized_discovery_state}"
        fake_forbidden_docker_argument="${fake_created_name}"
        fake_forbidden_docker_argument_seen=0
        if cleanup_verified; then
            discovery_byte_failures+=(
                "self-check accepted ${normalized_discovery_state} cleanup bytes"
            )
        fi
        if (( fake_forbidden_docker_argument_seen != 0 )); then
            discovery_byte_failures+=(
                "self-check passed ${normalized_discovery_state} bytes to Docker"
            )
        fi
        if (( fake_container_present != 1 )); then
            discovery_byte_failures+=(
                "self-check removed a container from ${normalized_discovery_state} bytes"
            )
        fi
        fake_container_present=0
    done
    fake_forbidden_docker_argument=''

    if (( ${#discovery_byte_failures[@]} > 0 )); then
        printf '%s\n' "${discovery_byte_failures[@]}" >&2
        return 1
    fi
    fake_forbidden_docker_argument=''
    if (( ${#ledger_attack_failures[@]} > 0 )); then
        printf '%s\n' "${ledger_attack_failures[@]}" >&2
        return 1
    fi

    mkdir -p "${WORK_DIR}"
    : >"${ONE_SHOT_LEDGER}"
    fake_docker_state='client-nonzero'
    local client_failure
    if client_failure="$(run_kes_client metrics metric 2>&1)"; then
        echo 'self-check accepted a nonzero one-shot KES client' >&2
        return 1
    fi
    if grep -Fq 'FORBIDDEN_RAW_CONTAINER_OUTPUT_42' <<<"${client_failure}"; then
        echo 'self-check found one-shot container output in an error' >&2
        return 1
    fi
    if ! grep -Fq 'one-shot KES metrics client failed with exit status 42' <<<"${client_failure}"; then
        echo 'self-check found no structured nonzero one-shot error' >&2
        return 1
    fi
    local -a boundary_failures=()

    reset_one_shot_boundary_fixture
    fake_docker_state='before-create-interruption'
    if run_kes_client metrics metric >/dev/null 2>&1; then
        boundary_failures+=('self-check accepted an interruption before docker create')
    fi
    if [[ ! -f "${ONE_SHOT_LEDGER}" ]] \
        || [[ "$(wc -l <"${ONE_SHOT_LEDGER}")" -ne 1 ]]; then
        boundary_failures+=('self-check did not register a name before a pre-create interruption')
    fi
    if [[ "$(fake_create_count)" -ne 0 || -e "${fake_create_marker}" ]]; then
        boundary_failures+=('self-check created a container during a pre-create interruption')
    fi

    reset_one_shot_boundary_fixture
    fake_docker_state='create-failure'
    if run_kes_client metrics metric >/dev/null 2>&1; then
        boundary_failures+=('self-check accepted a one-shot create failure')
    fi
    if [[ ! -f "${ONE_SHOT_LEDGER}" ]] \
        || [[ "$(wc -l <"${ONE_SHOT_LEDGER}")" -ne 1 ]]; then
        boundary_failures+=('self-check did not register a name before a create failure')
    fi
    cleanup_best_effort
    if (( fake_container_present != 0 )) || [[ -e "${fake_create_marker}" ]]; then
        boundary_failures+=('self-check could not clean a registered create failure')
    fi

    reset_one_shot_boundary_fixture
    mkdir "${ONE_SHOT_LEDGER}"
    fake_docker_state='ledger-append-failure'
    if run_kes_client metrics metric >/dev/null 2>&1; then
        boundary_failures+=('self-check accepted a cleanup-ledger append failure')
    fi
    if [[ "$(fake_create_count)" -ne 0 ]]; then
        boundary_failures+=('self-check called docker create after ledger append failed')
    fi

    reset_one_shot_boundary_fixture
    fake_docker_state='create-empty-id'
    if run_kes_client metrics metric >/dev/null 2>&1; then
        boundary_failures+=('self-check accepted an empty create container id')
    fi
    if [[ ! -f "${ONE_SHOT_LEDGER}" ]] \
        || [[ "$(wc -l <"${ONE_SHOT_LEDGER}")" -ne 1 ]]; then
        boundary_failures+=('self-check did not retain the registered name for an empty create id')
    fi
    if [[ -e "${fake_create_marker}" ]]; then
        boundary_failures+=('self-check left the empty-id container present')
    fi

    reset_one_shot_boundary_fixture
    fake_docker_state='after-create-interruption'
    if run_kes_client metrics metric >/dev/null 2>&1; then
        boundary_failures+=('self-check accepted an interrupted one-shot create')
    fi
    if (( fake_container_present != 0 )); then
        boundary_failures+=('self-check left an unregistered interrupted container')
    fi
    if (( ${#boundary_failures[@]} > 0 )); then
        printf '%s\n' "${boundary_failures[@]}" >&2
        return 1
    fi
    mkdir -p "${WORK_DIR}"
    fake_docker_state='absent'

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
    mkdir -p "${WORK_DIR}"
    printf '%s\n' "${fake_one_shot}" >"${ONE_SHOT_LEDGER}"
    fake_docker_state='one-shot-remains'
    if cleanup_verified; then
        echo 'self-check accepted one remaining dynamic one-shot container' >&2
        return 1
    fi
    mkdir -p "${WORK_DIR}"
    printf '%s\n' "${fake_one_shot}" >"${ONE_SHOT_LEDGER}"
    fake_docker_state='one-shot-remove-failure'
    if cleanup_verified; then
        echo 'self-check accepted a dynamic one-shot deletion failure' >&2
        return 1
    fi
    printf '%s\n' 'minio_kes_live_gate_self_check=true'
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command is unavailable: $1" >&2
        exit 1
    }
}

assert_container_bind_mounts() {
    local container_name="$1"
    shift
    local actual
    local expected
    actual="$(
        docker container inspect -- "${container_name}" |
            jq -r '.[0].Mounts[] | select(.Type == "bind") | "\(.Source)|\(.Destination)|\(.RW)"' |
            sort
    )"
    expected="$(printf '%s\n' "$@" | sort)"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "unexpected bind mount set for ${container_name}" >&2
        return 1
    fi
}

assert_running_directory_files() {
    local container_name="$1"
    local directory="$2"
    local expected="$3"
    docker exec \
        --env "EXPECTED_VISIBLE_FILES=${expected}" \
        "${container_name}" /bin/sh -c \
            'set -eu
             visible_files="$(/usr/bin/ls -1 "$1")"
             [ "${visible_files}" = "${EXPECTED_VISIBLE_FILES}" ]' \
            visibility-check "${directory}"
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

allocate_one_shot_container_name() {
    local identity_name="$1"
    local reservation
    reservation="$(mktemp -d "${WORK_DIR}/one-shot-${identity_name}.XXXXXX")"
    printf '%s-%s-%s\n' \
        "${KES_ONE_SHOT_PREFIX}" \
        "${identity_name}" \
        "${reservation##*.}"
}

start_one_shot_client() {
    timeout 5 docker start --attach -- "$1"
}

before_one_shot_create() {
    :
}

after_one_shot_create() {
    :
}

run_kes_client() {
    local identity_name="$1"
    shift
    case "${identity_name}" in
        bootstrap|metrics) ;;
        *)
            echo 'unsupported one-shot KES client identity' >&2
            return 1
            ;;
    esac
    if ! validate_private_work_dir || ! validate_one_shot_label_contract; then
        echo 'invalid one-shot KES private runtime boundary' >&2
        return 1
    fi
    local identity_directory="${WORK_DIR}/kes/${identity_name}"
    local client_name
    client_name="$(allocate_one_shot_container_name "${identity_name}")"
    if ! register_one_shot_container "${client_name}" "${identity_name}"; then
        echo 'failed to register one-shot KES client for cleanup' >&2
        return 1
    fi
    if ! before_one_shot_create; then
        echo "one-shot KES ${identity_name} client interrupted before create" >&2
        return 1
    fi
    local container_id
    if ! container_id="$(docker create \
        --name "${client_name}" \
        --label "${KES_ONE_SHOT_LABEL}" \
        --network "${KMS_NETWORK}" \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --env "EXPECTED_PRIVATE_KEY=/identity/${identity_name}.key" \
        --env "KES_SERVER=https://${KES_NAME}:7373" \
        --env "KES_CLIENT_CERT=/identity/${identity_name}.crt" \
        --env "KES_CLIENT_KEY=/identity/${identity_name}.key" \
        --env SSL_CERT_FILE=/trust/server.crt \
        --mount "type=bind,src=${identity_directory},dst=/identity,readonly" \
        --mount "type=bind,src=${KES_SERVER_DIR}/server.crt,dst=/trust/server.crt,readonly" \
        --entrypoint /bin/sh \
        "${KES_IMAGE}" -c \
            'set -eu
             visible_keys="$(/usr/bin/ls -1 /identity/*.key)"
             [ "${visible_keys}" = "${EXPECTED_PRIVATE_KEY}" ]
             if [ "${1:-}" = metric ]; then
                 shift
                 metric_status=0
                 # The CLI is a monitor. A long rate plus an internal timeout
                 # emits one complete document and closes the container before
                 # the host captures its full attach stream.
                 /usr/bin/timeout 1 /kes metric --rate 1h "$@" >/tmp/kes-metric.json || metric_status=$?
                 [ "${metric_status}" -eq 124 ]
                 [ -s /tmp/kes-metric.json ]
                 /bin/cat /tmp/kes-metric.json
                 exit 0
             fi
             exec /kes "$@"' \
            client-entrypoint "$@")"; then
        echo "failed to create one-shot KES ${identity_name} client" >&2
        return 1
    fi
    if [[ -z "${container_id}" ]]; then
        docker rm -f -- "${client_name}" >/dev/null 2>&1 || true
        echo "one-shot KES ${identity_name} create returned no container id" >&2
        return 1
    fi
    if ! after_one_shot_create; then
        echo "one-shot KES ${identity_name} client interrupted after create" >&2
        return 1
    fi
    if ! assert_container_bind_mounts \
        "${client_name}" \
        "${identity_directory}|/identity|false" \
        "${KES_SERVER_DIR}/server.crt|/trust/server.crt|false"; then
        docker rm -f -- "${client_name}" >/dev/null 2>&1 || true
        return 1
    fi
    local client_output
    local start_status=0
    client_output="$(start_one_shot_client "${client_name}" 2>&1)" || start_status=$?
    local remove_status=0
    if ! docker rm -f -- "${client_name}" >/dev/null 2>&1; then
        remove_status=1
    fi
    if (( start_status != 0 )); then
        echo "one-shot KES ${identity_name} client failed with exit status ${start_status}" >&2
        return 1
    fi
    if (( remove_status != 0 )); then
        echo "failed to remove one-shot KES ${identity_name} client" >&2
        return 1
    fi
    printf '%s\n' "${client_output}"
}

kes_exec() {
    run_kes_client metrics "$@"
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
    if ! snapshot="$(kes_exec metric)"; then
        echo 'failed to obtain KES metrics snapshot' >&2
        return 1
    fi
    parse_kes_success_count "${snapshot}"
}

assert_consecutive_metrics_snapshots() {
    local attempt
    local success_count
    for attempt in {1..12}; do
        if ! success_count="$(kes_success_count)"; then
            echo "consecutive metrics snapshot ${attempt}/12 failed" >&2
            return 1
        fi
        if [[ ! "${success_count}" =~ ^[0-9]+$ ]]; then
            echo "consecutive metrics snapshot ${attempt}/12 was not an integer" >&2
            return 1
        fi
    done
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

if [[ "${1:-}" == '--self-check' ]]; then
    self_check
    trap - EXIT INT TERM
    exit 0
fi
if (( $# != 0 )); then
    echo 'usage: minio-kes-live-gate.sh [--self-check]' >&2
    exit 2
fi

for command in cargo curl docker jq openssl sha256sum; do
    require_command "${command}"
done

for image in "${KES_IMAGE}" "${MINIO_IMAGE}" "${MC_IMAGE}"; do
    if ! docker image inspect "${image}" >/dev/null 2>&1; then
        docker pull "${image}" >/dev/null
    fi
done

mkdir -p \
    "${KES_SERVER_DIR}" \
    "${KES_KEYSTORE_DIR}" \
    "${KES_BOOTSTRAP_DIR}" \
    "${KES_RUNTIME_DIR}" \
    "${KES_METRICS_DIR}" \
    "${WORK_DIR}/mc" \
    "${WORK_DIR}/minio/certs/CAs" \
    "${WORK_DIR}/minio/data" \
    "${WORK_DIR}/policy"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=bind,src=${KES_SERVER_DIR},dst=/work" \
    "${KES_IMAGE}" identity new \
        --dns "${KES_NAME}" \
        --dns localhost \
        --ip 127.0.0.1 \
        --key /work/server.key \
        --cert /work/server.crt \
        --expiry 1h \
        kes-live-gate >/dev/null
for identity_name in bootstrap runtime metrics; do
    identity_directory="${WORK_DIR}/kes/${identity_name}"
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --mount "type=bind,src=${identity_directory},dst=/work" \
        "${KES_IMAGE}" identity new \
            --key "/work/${identity_name}.key" \
            --cert "/work/${identity_name}.crt" \
            --expiry 1h \
            "${identity_name}-live-gate" >/dev/null
done

kes_identity_of() {
    local identity_name="$1"
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --mount "type=bind,src=${WORK_DIR}/kes/${identity_name}/${identity_name}.crt,dst=/client.crt,readonly" \
        "${KES_IMAGE}" identity of /client.crt
}

KES_BOOTSTRAP_IDENTITY="$(kes_identity_of bootstrap)"
KES_RUNTIME_IDENTITY="$(kes_identity_of runtime)"
KES_METRICS_IDENTITY="$(kes_identity_of metrics)"
readonly KES_BOOTSTRAP_IDENTITY KES_RUNTIME_IDENTITY KES_METRICS_IDENTITY
render_kes_config \
    "${KES_SERVER_DIR}/config.yml" \
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
cp "${KES_SERVER_DIR}/server.crt" "${WORK_DIR}/minio/certs/CAs/kes-server.crt"

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
    --mount "type=bind,src=${KES_SERVER_DIR},dst=/config,readonly" \
    --mount "type=bind,src=${KES_KEYSTORE_DIR},dst=/data" \
    "${KES_IMAGE}" server --config /config/config.yml >/dev/null
assert_container_bind_mounts \
    "${KES_NAME}" \
    "${KES_SERVER_DIR}|/config|false" \
    "${KES_KEYSTORE_DIR}|/data|true"
assert_running_directory_files \
    "${KES_NAME}" \
    /config \
    $'config.yml\nserver.crt\nserver.key'
wait_for_kes
assert_consecutive_metrics_snapshots

run_kes_client bootstrap key create "${KMS_KEY_NAME}" >/dev/null

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
        --mount "type=bind,src=${KES_RUNTIME_DIR}/runtime.crt,dst=/kes/runtime.crt,readonly" \
        --mount "type=bind,src=${KES_RUNTIME_DIR}/runtime.key,dst=/kes/runtime.key,readonly" \
        "${MINIO_IMAGE}" server /data --certs-dir /certs --address :9000 >/dev/null
    docker network connect "${CLIENT_NETWORK}" "${MINIO_NAME}"
    assert_container_bind_mounts \
        "${MINIO_NAME}" \
        "${WORK_DIR}/minio/certs|/certs|false" \
        "${WORK_DIR}/minio/data|/data|true" \
        "${KES_RUNTIME_DIR}/runtime.crt|/kes/runtime.crt|false" \
        "${KES_RUNTIME_DIR}/runtime.key|/kes/runtime.key|false"
    assert_running_directory_files \
        "${MINIO_NAME}" \
        /kes \
        $'runtime.crt\nruntime.key'
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
docker rm -f -- "${MINIO_NAME}" >/dev/null
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
    'consecutive_metrics_snapshots=12' \
    'kes_route_labels_available=false' \
    'inferred_generate_minimum=1' \
    "kes_write_phase_success_delta=${WRITE_KES_OPERATIONS}" \
    'inferred_post_restart_decrypt_minimum=1' \
    "kes_restart_read_success_delta=${RESTART_READ_KES_OPERATIONS}" \
    'ephemeral_resources_cleaned=true'
