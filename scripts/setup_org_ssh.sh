#!/usr/bin/env bash
# Load ORG_SSH_KEY for git@github.com (clone, fetch, push).
set -euo pipefail

if [ -z "${ORG_SSH_KEY:-}" ]; then
  echo "ORG_SSH_KEY not set; skipping SSH setup."
  exit 0
fi

KEY_PATH="${ORG_SSH_KEY_PATH:-${HOME}/.ssh/id_ed25519_org}"
mkdir -p "$(dirname "${KEY_PATH}")"
printf '%s\n' "${ORG_SSH_KEY}" > "${KEY_PATH}"
chmod 600 "${KEY_PATH}"

mkdir -p "${HOME}/.ssh"
ssh-keyscan github.com >> "${HOME}/.ssh/known_hosts" 2>/dev/null || true

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "ORG_SSH_KEY_PATH=${KEY_PATH}" >> "${GITHUB_ENV}"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "org_ssh_key_path=${KEY_PATH}" >> "${GITHUB_OUTPUT}"
fi

echo "ORG_SSH_KEY configured at ${KEY_PATH}"
