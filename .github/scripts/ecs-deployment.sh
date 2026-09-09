#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

require_command() {
  command -v "$1" > /dev/null 2>&1 || fail "Required command '$1' is not available."
}

require_output_file() {
  [[ -n "${GITHUB_OUTPUT:-}" ]] || fail "GITHUB_OUTPUT is not configured."
}

validate_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Invalid image digest '$1'."
}

validate_version() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || fail "Invalid release version '$1'. Expected X.Y.Z."
}

inspect_deployment() {
  local cluster="$1"
  local service="$2"
  local container_name="$3"
  local region="$4"
  local output_json="$5"

  require_output_file

  aws ecs wait services-stable \
    --cluster "$cluster" \
    --services "$service" \
    --region "$region" \
    --no-cli-pager

  local task_definition_arn
  task_definition_arn="$(
    aws ecs describe-services \
      --cluster "$cluster" \
      --services "$service" \
      --query 'services[0].taskDefinition' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  [[ -n "$task_definition_arn" && "$task_definition_arn" != "None" ]] \
    || fail "ECS service '$service' has no active task definition."

  aws ecs describe-task-definition \
    --task-definition "$task_definition_arn" \
    --include TAGS \
    --region "$region" \
    --no-cli-pager > "$output_json"

  local container_count
  container_count="$(
    jq --arg name "$container_name" \
      '[.taskDefinition.containerDefinitions[] | select(.name == $name)] | length' \
      "$output_json"
  )"
  [[ "$container_count" == "1" ]] \
    || fail "Expected exactly one container named '$container_name'; found $container_count."

  local version_count
  version_count="$(
    jq '[.tags[]? | select(.key == "release.version")] | length' "$output_json"
  )"
  (( version_count <= 1 )) \
    || fail "Task definition '$task_definition_arn' has duplicate release.version tags."

  local image
  image="$(
    jq -r --arg name "$container_name" \
      '.taskDefinition.containerDefinitions[]
       | select(.name == $name)
       | .image' \
      "$output_json"
  )"

  local current_version
  current_version="$(
    jq -r \
      '[.tags[]? | select(.key == "release.version") | .value][0] // empty' \
      "$output_json"
  )"

  local legacy_bootstrap=false
  if [[ -z "$current_version" ]]; then
    if [[ "$image" =~ @sha256:[0-9a-fA-F]{64}$ ]]; then
      fail "Task definition '$task_definition_arn' is digest-pinned but release.version is missing."
    fi
    current_version="0.0.0"
    legacy_bootstrap=true
    echo "::notice::Legacy mutable deployment detected; using release version 0.0.0."
  else
    validate_version "$current_version"
    [[ "$image" =~ @sha256:[0-9a-fA-F]{64}$ ]] \
      || fail "Task definition '$task_definition_arn' has release.version metadata but uses mutable image '$image'."
  fi

  local task_arns_text
  task_arns_text="$(
    aws ecs list-tasks \
      --cluster "$cluster" \
      --service-name "$service" \
      --desired-status RUNNING \
      --query 'taskArns' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  [[ -n "$task_arns_text" && "$task_arns_text" != "None" ]] \
    || fail "ECS service '$service' has no running tasks."

  read -r -a task_arns <<< "$task_arns_text"
  local tasks_json
  tasks_json="$(mktemp)"
  aws ecs describe-tasks \
    --cluster "$cluster" \
    --tasks "${task_arns[@]}" \
    --region "$region" \
    --no-cli-pager > "$tasks_json"

  jq -e \
    --arg taskDefinition "$task_definition_arn" \
    --arg container "$container_name" \
    '
      (.failures | length) == 0
      and (.tasks | length) > 0
      and all(.tasks[]; .taskDefinitionArn == $taskDefinition)
      and all(
        .tasks[];
        ([.containers[] | select(.name == $container)] | length) == 1
      )
    ' "$tasks_json" > /dev/null \
    || fail "Running ECS tasks do not consistently use '$task_definition_arn' and container '$container_name'."

  local digest_count
  digest_count="$(
    jq --arg container "$container_name" \
      '[.tasks[].containers[] | select(.name == $container) | .imageDigest] | unique | length' \
      "$tasks_json"
  )"
  [[ "$digest_count" == "1" ]] \
    || fail "Running ECS tasks do not resolve to one application image digest."

  local observed_digest
  observed_digest="$(
    jq -r --arg container "$container_name" \
      '[.tasks[].containers[] | select(.name == $container) | .imageDigest] | unique[0]' \
      "$tasks_json"
  )"
  validate_digest "$observed_digest"

  {
    echo "task_definition_arn=$task_definition_arn"
    echo "image=$image"
    echo "observed_digest=$observed_digest"
    echo "version=$current_version"
    echo "legacy_bootstrap=$legacy_bootstrap"
  } >> "$GITHUB_OUTPUT"
  rm -f "$tasks_json"
}

register_task_definition() {
  local source_json="$1"
  local container_name="$2"
  local image="$3"
  local version="$4"
  local source_sha="$5"
  local digest="$6"
  local environment="$7"
  local workflow_run="$8"
  local region="$9"

  require_output_file
  validate_version "$version"
  validate_digest "$digest"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "Invalid source commit SHA '$source_sha'."
  [[ "$image" == *"@$digest" ]] || fail "Image '$image' is not pinned to '$digest'."

  local register_json
  register_json="$(mktemp)"
  local tags_json
  tags_json="$(mktemp)"

  jq \
    --arg name "$container_name" \
    --arg image "$image" \
    '
      .taskDefinition
      | del(
          .taskDefinitionArn,
          .revision,
          .status,
          .requiresAttributes,
          .compatibilities,
          .registeredAt,
          .registeredBy,
          .deregisteredAt
        )
      | .containerDefinitions |= map(
          if .name == $name then .image = $image else . end
        )
    ' "$source_json" > "$register_json"

  jq \
    --arg version "$version" \
    --arg sourceSha "$source_sha" \
    --arg digest "$digest" \
    --arg environment "$environment" \
    --arg workflowRun "$workflow_run" \
    '
      [.tags[]? | select(.key | startswith("release.") | not)]
      + [
          {key: "release.version", value: $version},
          {key: "release.source-sha", value: $sourceSha},
          {key: "release.image-digest", value: $digest},
          {key: "release.environment", value: $environment},
          {key: "release.workflow-run", value: $workflowRun}
        ]
    ' "$source_json" > "$tags_json"
  local tag_count
  tag_count="$(jq 'length' "$tags_json")"
  (( tag_count <= 50 )) || fail "The rendered task definition exceeds the ECS limit of 50 tags."

  local task_definition_arn
  task_definition_arn="$(
    aws ecs register-task-definition \
      --cli-input-json "file://$register_json" \
      --tags "file://$tags_json" \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  [[ -n "$task_definition_arn" && "$task_definition_arn" != "None" ]] \
    || fail "AWS did not return the registered task-definition ARN."

  echo "task_definition_arn=$task_definition_arn" >> "$GITHUB_OUTPUT"
  rm -f "$register_json" "$tags_json"
}

verify_runtime() {
  local cluster="$1"
  local service="$2"
  local container_name="$3"
  local expected_task_definition="$4"
  local expected_digest="$5"
  local region="$6"

  require_output_file
  validate_digest "$expected_digest"

  aws ecs wait services-stable \
    --cluster "$cluster" \
    --services "$service" \
    --region "$region" \
    --no-cli-pager

  local service_task_definition
  service_task_definition="$(
    aws ecs describe-services \
      --cluster "$cluster" \
      --services "$service" \
      --query 'services[0].taskDefinition' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  [[ "$service_task_definition" == "$expected_task_definition" ]] \
    || fail "ECS service uses '$service_task_definition', expected '$expected_task_definition'."

  local tasks_json
  tasks_json="$(mktemp)"

  local task_arns_text
  task_arns_text="$(
    aws ecs list-tasks \
      --cluster "$cluster" \
      --service-name "$service" \
      --desired-status RUNNING \
      --query 'taskArns' \
      --output text \
      --region "$region" \
      --no-cli-pager
  )"
  [[ -n "$task_arns_text" && "$task_arns_text" != "None" ]] \
    || fail "ECS service '$service' has no running tasks."
  read -r -a task_arns <<< "$task_arns_text"

  aws ecs describe-tasks \
    --cluster "$cluster" \
    --tasks "${task_arns[@]}" \
    --region "$region" \
    --no-cli-pager > "$tasks_json"

  jq -e \
    --arg taskDefinition "$expected_task_definition" \
    --arg container "$container_name" \
    --arg digest "$expected_digest" \
    '
      (.failures | length) == 0
      and (.tasks | length) > 0
      and all(.tasks[]; .taskDefinitionArn == $taskDefinition)
      and all(
        .tasks[];
        ([.containers[]
          | select(.name == $container and .imageDigest == $digest)]
         | length) == 1
      )
    ' "$tasks_json" > /dev/null \
    || fail "Running ECS tasks do not match task definition '$expected_task_definition' and digest '$expected_digest'."

  {
    echo "task_definition_arn=$expected_task_definition"
    echo "observed_digest=$expected_digest"
  } >> "$GITHUB_OUTPUT"
  rm -f "$tasks_json"
}

verify_deployment() {
  local cluster="$1"
  local service="$2"
  local container_name="$3"
  local expected_task_definition="$4"
  local expected_digest="$5"
  local expected_version="$6"
  local expected_source_sha="$7"
  local region="$8"

  require_output_file
  validate_digest "$expected_digest"
  validate_version "$expected_version"

  local task_definition_json
  task_definition_json="$(mktemp)"
  aws ecs describe-task-definition \
    --task-definition "$expected_task_definition" \
    --include TAGS \
    --region "$region" \
    --no-cli-pager > "$task_definition_json"

  jq -e \
    --arg container "$container_name" \
    --arg digest "$expected_digest" \
    --arg version "$expected_version" \
    --arg sourceSha "$expected_source_sha" \
    '
      ([.taskDefinition.containerDefinitions[]
        | select(.name == $container and (.image | endswith("@" + $digest)))]
       | length) == 1
      and ([.tags[]? | select(.key == "release.version" and .value == $version)]
           | length) == 1
      and ([.tags[]? | select(.key == "release.source-sha" and .value == $sourceSha)]
           | length) == 1
      and ([.tags[]? | select(.key == "release.image-digest" and .value == $digest)]
           | length) == 1
    ' "$task_definition_json" > /dev/null \
    || fail "Task definition image or release metadata does not match the expected release."
  rm -f "$task_definition_json"

  verify_runtime \
    "$cluster" \
    "$service" \
    "$container_name" \
    "$expected_task_definition" \
    "$expected_digest" \
    "$region"
}

require_command aws
require_command jq

command_name="${1:-}"
case "$command_name" in
  inspect)
    [[ "$#" == 6 ]] || fail "Usage: $0 inspect CLUSTER SERVICE CONTAINER REGION OUTPUT_JSON"
    inspect_deployment "$2" "$3" "$4" "$5" "$6"
    ;;
  register)
    [[ "$#" == 10 ]] \
      || fail "Usage: $0 register SOURCE_JSON CONTAINER IMAGE VERSION SOURCE_SHA DIGEST ENVIRONMENT RUN_ID REGION"
    register_task_definition "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"
    ;;
  verify)
    [[ "$#" == 9 ]] \
      || fail "Usage: $0 verify CLUSTER SERVICE CONTAINER TASK_DEFINITION DIGEST VERSION SOURCE_SHA REGION"
    verify_deployment "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
    ;;
  verify-runtime)
    [[ "$#" == 7 ]] \
      || fail "Usage: $0 verify-runtime CLUSTER SERVICE CONTAINER TASK_DEFINITION DIGEST REGION"
    verify_runtime "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  *)
    fail "Usage: $0 {inspect|register|verify|verify-runtime} ..."
    ;;
esac
