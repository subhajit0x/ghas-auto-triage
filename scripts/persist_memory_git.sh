#!/usr/bin/env bash
# Commit triage memory JSONL files on the current branch (used by ghas-llm workflow).
set -euo pipefail

HISTORY="${1:-.triage_history.jsonl}"
FEEDBACK="${2:-.human_feedback.jsonl}"
RUN_ID="${3:-local}"
DRY_RUN="${GHAS_LLM_MEMORY_GIT_DRY_RUN:-false}"
MAX_PUSH_ATTEMPTS="${GHAS_LLM_MEMORY_PUSH_RETRIES:-3}"

_configure_git_transport() {
  local transport="${1:-}"
  local repo="${GITHUB_REPOSITORY:-}"

  if [ -z "${repo}" ]; then
    repo="$(git remote get-url origin 2>/dev/null | sed -E 's#(git@github.com:|https://[^/]+/)(.+)(\.git)?#\2#')"
  fi
  if [ -z "${repo}" ]; then
    echo "::error::Cannot resolve repository slug for git push."
    return 1
  fi

  if [ "${transport}" = "ssh" ]; then
    if [ -z "${ORG_SSH_KEY_PATH:-}" ] || [ ! -f "${ORG_SSH_KEY_PATH}" ]; then
      echo "SSH push requested but ORG_SSH_KEY_PATH is not configured."
      return 1
    fi
    export GIT_SSH_COMMAND="ssh -i ${ORG_SSH_KEY_PATH} -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
    git remote set-url origin "git@github.com:${repo}.git"
    echo "Git transport: SSH (ORG_SSH_KEY)."
    return 0
  fi

  if [ -z "${transport}" ] && [ -n "${ORG_SSH_KEY_PATH:-}" ] && [ -f "${ORG_SSH_KEY_PATH}" ]; then
    export GIT_SSH_COMMAND="ssh -i ${ORG_SSH_KEY_PATH} -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
    git remote set-url origin "git@github.com:${repo}.git"
    echo "Git transport: SSH (ORG_SSH_KEY)."
    return 0
  fi

  local token="${GHAS_LLM_GIT_PUSH_TOKEN:-}"
  if [ -n "${token}" ]; then
    git remote set-url origin "https://x-access-token:${token}@github.com/${repo}.git"
    echo "Git transport: HTTPS token."
    return 0
  fi

  echo "Git transport: existing remote (no SSH key or push token configured)."
  return 0
}

touch "$HISTORY" "$FEEDBACK"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "::error::Not inside a git repository; cannot persist memory."
  exit 1
fi

if ! git config user.email >/dev/null 2>&1; then
  git config user.name "${GIT_COMMITTER_NAME:-github-actions[bot]}"
  git config user.email "${GIT_COMMITTER_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
fi

git add "$HISTORY" "$FEEDBACK"

if git diff --staged --quiet; then
  echo "No memory file changes to commit."
  exit 0
fi

BRANCH="${GITHUB_REF_NAME:-$(git branch --show-current)}"
if [ -z "${BRANCH}" ]; then
  echo "::error::Cannot resolve branch for memory push."
  exit 1
fi

git commit -m "chore(ghas-llm): update triage memory (run ${RUN_ID})"

if [ "${DRY_RUN}" = "true" ]; then
  echo "GHAS_LLM_MEMORY_GIT_DRY_RUN=true — committed locally; skipping push."
  exit 0
fi

_push_with_transport() {
  local transport="${1:-}"
  _configure_git_transport "${transport}" || return 1

  local attempt=1
  while [ "${attempt}" -le "${MAX_PUSH_ATTEMPTS}" ]; do
    git pull --rebase origin "${BRANCH}" || echo "::warning::git pull --rebase failed (attempt ${attempt})"
    if git push origin "HEAD:${BRANCH}"; then
      echo "Pushed memory files to ${BRANCH}."
      return 0
    fi
    echo "::warning::push attempt ${attempt}/${MAX_PUSH_ATTEMPTS} failed"
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}

# Prefer org deploy key (SSH); fall back to HTTPS token when SSH is unavailable or fails.
if [ -n "${ORG_SSH_KEY_PATH:-}" ] && [ -f "${ORG_SSH_KEY_PATH}" ]; then
  if _push_with_transport ssh; then
    exit 0
  fi
fi

if [ -n "${GHAS_LLM_GIT_PUSH_TOKEN:-}" ]; then
  echo "SSH push failed — retrying with HTTPS token..."
  unset GIT_SSH_COMMAND
  if _push_with_transport https; then
    exit 0
  fi
fi

echo "::error::Failed to push memory files after SSH and HTTPS attempts."
exit 1
