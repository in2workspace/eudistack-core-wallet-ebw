#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

[[ "$#" -ge 5 ]] \
  || fail "Usage: $0 REPOSITORY DIGEST REGION mutable|immutable|check-immutable TAG..."

repository="$1"
digest="$2"
region="$3"
mode="$4"
shift 4

[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Invalid image digest '$digest'."
[[ "$mode" == "mutable" || "$mode" == "immutable" || "$mode" == "check-immutable" ]] \
  || fail "Tag mode must be 'mutable', 'immutable', or 'check-immutable'."

manifest="$(
  aws ecr batch-get-image \
    --repository-name "$repository" \
    --image-ids imageDigest="$digest" \
    --query 'images[0].imageManifest' \
    --output text \
    --region "$region" \
    --no-cli-pager
)"
[[ -n "$manifest" && "$manifest" != "None" ]] \
  || fail "Digest '$digest' does not exist in ECR repository '$repository'."

for tag in "$@"; do
  [[ -n "$tag" ]] || fail "ECR tags cannot be empty."
  current_digest="$(
    aws ecr batch-get-image \
      --repository-name "$repository" \
      --image-ids imageTag="$tag" \
      --query 'images[0].imageId.imageDigest' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  if [[ "$current_digest" == "$digest" ]]; then
    echo "ECR tag '$tag' already points to '$digest'; no update is required."
    continue
  fi
  if [[ "$mode" != "mutable" && "$current_digest" != "None" ]]; then
    fail "Immutable ECR tag '$tag' already points to '$current_digest', not '$digest'."
  fi
  if [[ "$mode" == "check-immutable" ]]; then
    echo "Immutable ECR tag '$tag' is available for digest '$digest'."
    continue
  fi

  aws ecr put-image \
    --repository-name "$repository" \
    --image-tag "$tag" \
    --image-manifest "$manifest" \
    --region "$region" \
    --no-cli-pager > /dev/null
done
