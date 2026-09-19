#!/usr/bin/env bash

set -euo pipefail

mode=${TREETOP_REST_SCALE_MODE:-curve}
output_dir=${TREETOP_REST_SCALE_OUTPUT_DIR:-performance-results/policy-scale}
toolchain=${TREETOP_REST_SCALE_TOOLCHAIN:-1.98.1}

case "${mode}" in
    curve)
        policy_counts=(1000 10000 100000)
        soak_seconds=0
        ;;
    point)
        policy_counts=("${TREETOP_SCALE_POLICY_COUNT:-100000}")
        soak_seconds=0
        ;;
    soak)
        policy_counts=("${TREETOP_SCALE_POLICY_COUNT:-100000}")
        soak_seconds=${TREETOP_REST_SCALE_SOAK_SECONDS:-900}
        if [[ ! ${soak_seconds} =~ ^[1-9][0-9]*$ ]]; then
            echo "TREETOP_REST_SCALE_SOAK_SECONDS must be a positive integer in soak mode" >&2
            exit 1
        fi
        ;;
    *)
        echo "TREETOP_REST_SCALE_MODE must be curve, point, or soak" >&2
        exit 1
        ;;
esac

for policy_count in "${policy_counts[@]}"; do
    if [[ ! ${policy_count} =~ ^[1-9][0-9]*$ ]] || (( policy_count < 4 )); then
        echo "policy count must be an integer of at least four, got ${policy_count}" >&2
        exit 1
    fi
done

reload_interval=${TREETOP_REST_SCALE_RELOAD_INTERVAL_SECONDS:-60}
if [[ ! ${reload_interval} =~ ^[1-9][0-9]*$ ]]; then
    echo "TREETOP_REST_SCALE_RELOAD_INTERVAL_SECONDS must be a positive integer" >&2
    exit 1
fi

mkdir -p "${output_dir}"
summary_path="${output_dir}/summary.md"
: > "${summary_path}"

cargo "+${toolchain}" test --release --test policy_scale_characterization --no-run

for policy_count in "${policy_counts[@]}"; do
    run_dir="${output_dir}/${policy_count}"
    mkdir -p "${run_dir}"
    resources_path="${run_dir}/policy-scale-${policy_count}-resources.txt"
    log_path="${run_dir}/policy-scale-${policy_count}.log"

    echo "Running ${policy_count}-policy ${mode} characterization"
    /usr/bin/time -v -o "${resources_path}" \
        env \
        TREETOP_SCALE_POLICY_COUNT="${policy_count}" \
        TREETOP_REST_SCALE_OUTPUT_DIR="${run_dir}" \
        TREETOP_REST_SCALE_SOAK_SECONDS="${soak_seconds}" \
        TREETOP_REST_SCALE_RELOAD_INTERVAL_SECONDS="${reload_interval}" \
        cargo "+${toolchain}" test --release --test policy_scale_characterization \
        characterize_shared_policy_scale -- --ignored --exact --nocapture \
        2>&1 | tee "${log_path}"

    sed -n '1,$p' "${run_dir}/policy-scale-${policy_count}.md" >> "${summary_path}"
    {
        echo
        echo "### Whole-process resources"
        echo
        echo '```text'
        sed -n \
            -e '/User time/p' \
            -e '/System time/p' \
            -e '/Percent of CPU/p' \
            -e '/Elapsed (wall clock) time/p' \
            -e '/Maximum resident set size/p' \
            -e '/Swaps/p' \
            "${resources_path}"
        echo '```'
        echo
    } >> "${summary_path}"
done

echo "Combined scale summary: ${summary_path}"
echo "JSON, OpenMetrics, resource, and log artifacts: ${output_dir}/"
