#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/gcp_scc_deploy_function.sh <PROJECT_ID> <REGION> <FUNCTION_NAME> <TOPIC> <PLATFORM_API_BASE> <TENANT_ID> <SECRET_NAME>
PROJECT_ID=${1:?}
REGION=${2:?}
FN=${3:-scc-pubsub-worker}
TOPIC=${4:-scc-findings}
API_BASE=${5:?}
TENANT=${6:?}
SECRET_NAME=${7:-platform-api-key}

gcloud config set project "$PROJECT_ID"
gcloud config set functions/region "$REGION"

pushd gcp/functions/scc_pubsub >/dev/null
# assumes Secret Manager has secret $SECRET_NAME
# deploy
gcloud functions deploy "$FN" \
  --region="$REGION" \
  --runtime=python311 \
  --trigger-topic="$TOPIC" \
  --entry-point=pubsub_entry \
  --set-env-vars=PLATFORM_API_BASE="$API_BASE",TENANT_ID="$TENANT",TLS_ENFORCE=1 \
  --set-secrets=PLATFORM_API_KEY=projects/$PROJECT_ID/secrets/$SECRET_NAME:latest
popd >/dev/null

echo "Deployed Cloud Function $FN in $REGION"
