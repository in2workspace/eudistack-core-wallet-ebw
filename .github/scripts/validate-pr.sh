#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:?base ref is required}"
head_ref="${2:?head ref is required}"
actor="${3:-}"

if [[ "${base_ref}" == "main" ]]; then
  if [[ ! "${head_ref}" =~ ^(feature|hotfix)/EUD-[0-9]+-.+ ]] \
    && [[ ! "${head_ref}" =~ ^release/v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "::error::Branches targeting main must be feature/EUD-N-*, hotfix/EUD-N-* or release/vX.Y.Z."
    exit 1
  fi
elif [[ "${base_ref}" =~ ^release/v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  if [[ ! "${head_ref}" =~ ^hotfix/EUD-[0-9]+-.+ ]]; then
    echo "::error::Only hotfix/EUD-N-* branches may target a release branch."
    exit 1
  fi
else
  echo "::error::Unsupported pull request target: ${base_ref}"
  exit 1
fi

git fetch --no-tags origin "${base_ref}"

changed_files="$(git diff --name-only "origin/${base_ref}...HEAD")"
code_changes="$(printf '%s\n' "${changed_files}" \
  | grep -Ev '(^$|\.md$|^docs/|^\.github/|^LICENSE$|^\.gitignore$)' || true)"

if [[ -n "${code_changes}" && "${actor}" != "dependabot[bot]" ]] \
  && ! printf '%s\n' "${changed_files}" | grep -qx 'CHANGELOG.md'; then
  echo "::error::Code changes must update CHANGELOG.md under [Unreleased]."
  exit 1
fi

if [[ -n "${code_changes}" ]] && ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
  echo "::error::CHANGELOG.md must contain an [Unreleased] section."
  exit 1
fi

if printf '%s\n' "${changed_files}" | grep -q '^src/main/resources/db/.*\.sql$'; then
  migration_files="$(printf '%s\n' "${changed_files}" \
    | grep '^src/main/resources/db/.*\.sql$')"
  while IFS= read -r migration; do
    [[ -f "${migration}" ]] || continue
    if grep -Eiq \
      '(^|[[:space:]])(DROP[[:space:]]+(TABLE|COLUMN)|TRUNCATE[[:space:]]+TABLE|ALTER[[:space:]]+TABLE.*DROP|ALTER[[:space:]]+TABLE.*RENAME)' \
      "${migration}"; then
      echo "::error file=${migration}::Destructive migration detected. Use expand/contract across releases."
      exit 1
    fi
  done <<< "${migration_files}"
fi

