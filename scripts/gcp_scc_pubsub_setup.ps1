param(
  [Parameter(Mandatory=$true)][string]$ProjectId,
  [string]$Topic = "scc-findings",
  [string]$Subscription = "scc-findings-sub",
  [string]$DlqTopic = "scc-findings-dlq"
)

$ErrorActionPreference = 'Stop'
& gcloud config set project $ProjectId | Out-Null

if (-not (gcloud pubsub topics describe $Topic 2>$null)) { gcloud pubsub topics create $Topic | Out-Null }
if (-not (gcloud pubsub topics describe $DlqTopic 2>$null)) { gcloud pubsub topics create $DlqTopic | Out-Null }

if (-not (gcloud pubsub subscriptions describe $Subscription 2>$null)) {
  gcloud pubsub subscriptions create $Subscription `
    --topic=$Topic `
    --dead-letter-topic="projects/$ProjectId/topics/$DlqTopic" `
    --max-delivery-attempts=10 `
    --min-retry-delay=10s --max-retry-delay=600s | Out-Null
}

Write-Host "Created Pub/Sub resources: topic=$Topic sub=$Subscription dlq=$DlqTopic"
