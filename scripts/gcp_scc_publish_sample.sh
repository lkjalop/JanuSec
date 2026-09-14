#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/gcp_scc_publish_sample.sh <PROJECT_ID> <TOPIC>
PROJECT_ID=${1:?}
TOPIC=${2:-scc-findings}

gcloud config set project "$PROJECT_ID"
DATA='{"findings":[{"category":"Public Access to Storage Bucket","severity":"MEDIUM","resourceName":"//storage.googleapis.com/projects/_/buckets/my-bucket","eventTime":"2025-12-01T12:34:56Z"}]}'
# Publish using gcloud
printf '%s' "$DATA" | gcloud pubsub topics publish "$TOPIC" --message-from-file=-
echo "Published sample to $TOPIC"
