#!/usr/bin/env bash
# Deploy/update the TrustGate core stack and write its outputs to .env.aws.
#
#   infra/aws/deploy.sh                          # storage, metadata, queues only (no EC2)
#   CREATE_WORKER=true infra/aws/deploy.sh       # also launch the EC2 worker
#   ALERT_EMAIL=you@example.com infra/aws/deploy.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STACK="${STACK:-trustgate-dev-core}"
REGION="${AWS_REGION:-$(aws configure get region || echo ap-south-1)}"

params=(
  "CreateWorker=${CREATE_WORKER:-false}"
  "WorkerInstanceType=${WORKER_INSTANCE_TYPE:-m7g.2xlarge}"
  "DataVolumeGiB=${DATA_VOLUME_GIB:-200}"
  "AlertEmail=${ALERT_EMAIL:-}"
  "MonthlyBudgetUsd=${MONTHLY_BUDGET_USD:-50}"
)
if [[ -n "${WORKER_AMI:-}" ]]; then params+=("WorkerAmi=$WORKER_AMI"); fi

aws cloudformation deploy \
  --region "$REGION" \
  --stack-name "$STACK" \
  --template-file "$HERE/trustgate-core.yaml" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides "${params[@]}"

aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text |
  awk -F'\t' '
    $1=="Region"              {print "AWS_REGION=" $2}
    $1=="RawBucket"           {print "TRUSTGATE_RAW_BUCKET=" $2}
    $1=="LakeBucket"          {print "TRUSTGATE_LAKE_BUCKET=" $2}
    $1=="MetaTable"           {print "TRUSTGATE_META_TABLE=" $2}
    $1=="IngestQueueUrl"      {print "TRUSTGATE_INGEST_QUEUE_URL=" $2}
    $1=="MaintenanceQueueUrl" {print "TRUSTGATE_MAINTENANCE_QUEUE_URL=" $2}
    $1=="ReportsQueueUrl"     {print "TRUSTGATE_REPORTS_QUEUE_URL=" $2}
    $1=="GlueDatabase"        {print "TRUSTGATE_GLUE_DATABASE=" $2}
    $1=="WorkerInstanceId"    {print "TRUSTGATE_WORKER_INSTANCE_ID=" $2}
  ' > "$ROOT/.env.aws"
echo "TRUSTGATE_PROFILE=aws" >> "$ROOT/.env.aws"

echo "Wrote $ROOT/.env.aws"
cat "$ROOT/.env.aws"
