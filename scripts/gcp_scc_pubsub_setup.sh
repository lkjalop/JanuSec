#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/gcp_scc_pubsub_setup.sh <PROJECT_ID> <TOPIC> <SUBSCRIPTION> <DLQ_TOPIC>
PROJECT_ID=${1:?project}
TOPIC=${2:-scc-findings}
SUB=${3:-scc-findings-sub}
DLQ=${4:-scc-findings-dlq}

gcloud config set project "$PROJECT_ID"
# Create topics
(gcloud pubsub topics describe "$TOPIC" >/dev/null 2>&1) || gcloud pubsub topics create "$TOPIC"
(gcloud pubsub topics describe "$DLQ" >/dev/null 2>&1) || gcloud pubsub topics create "$DLQ"
# Create subscription with DLQ
if ! gcloud pubsub subscriptions describe "$SUB" >/dev/null 2>&1; then
  gcloud pubsub subscriptions create "$SUB" \
    --topic="$TOPIC" \
    --dead-letter-topic="projects/$PROJECT_ID/topics/$DLQ" \
    --max-delivery-attempts=10 \
    --min-retry-delay=10s --max-retry-delay=600s
fi

echo "Created Pub/Sub resources: topic=$TOPIC sub=$SUB dlq=$DLQ"
