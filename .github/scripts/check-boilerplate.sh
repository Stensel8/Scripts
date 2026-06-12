#!/usr/bin/env bash
#
# Verify that the common boilerplate block is byte-identical across all bash
# scripts in this repo, using .github/scripts/boilerplate.sh as the reference.
#
# Usage:
#   .github/scripts/check-boilerplate.sh
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly REFERENCE="$REPO_ROOT/.github/scripts/boilerplate.sh"
readonly BEGIN_MARKER="BEGIN COMMON BOILERPLATE"
readonly END_MARKER="END COMMON BOILERPLATE"

# Scripts that must carry the boilerplate block.
readonly REQUIRED_SCRIPTS=(
    "ansible/ansible_installer.sh"
    "docker/docker_installer.sh"
    "kubernetes/kubernetes_installer.sh"
    "nginx/nginx_installer.sh"
    "openssh/openssh_installer.sh"
    "podman/podman_installer.sh"
    "terraform/terraform_installer.sh"
    ".github/scripts/update-nginx-checksums.sh"
)

Get-BoilerplateBlock() {
    awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" \
        '$0 ~ begin, $0 ~ end' "$1"
}

[[ -f "$REFERENCE" ]] || { echo "ERROR: reference file not found: $REFERENCE" >&2; exit 1; }

reference_block="$(Get-BoilerplateBlock "$REFERENCE")"
[[ -n "$reference_block" ]] || { echo "ERROR: no boilerplate block in reference file" >&2; exit 1; }

failed=0
for script in "${REQUIRED_SCRIPTS[@]}"; do
    path="$REPO_ROOT/$script"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: required script missing: $script" >&2
        failed=1
        continue
    fi
    script_block="$(Get-BoilerplateBlock "$path")"
    if [[ -z "$script_block" ]]; then
        echo "ERROR: $script is missing the common boilerplate block" >&2
        failed=1
        continue
    fi
    if ! diff_output=$(diff -u <(echo "$reference_block") <(echo "$script_block")); then
        echo "ERROR: boilerplate in $script differs from the reference:" >&2
        echo "$diff_output" >&2
        failed=1
    else
        echo "OK: $script"
    fi
done

if [[ $failed -ne 0 ]]; then
    echo >&2
    echo "Boilerplate check failed. Copy the block from .github/scripts/boilerplate.sh verbatim." >&2
    exit 1
fi
echo "All boilerplate blocks are identical."
