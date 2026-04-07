"""
EventBridge Rules Deployment (P0-B)
Deploys and tears down the five canonical Janusec EventBridge routing rules
that fan security events from AWS services into SQS / Kinesis targets.

Usage (one-shot deploy):
    python -m src.connectors.aws.eventbridge_rules --deploy \
        --sqs-arn arn:aws:sqs:us-east-1:123456789012:janusec-ingest \
        --kinesis-arn arn:aws:kinesis:us-east-1:123456789012:stream/janusec-stream \
        --region us-east-1

Env vars (alternative to CLI args):
    EB_SQS_ARN          — SQS target ARN
    EB_KINESIS_ARN      — Kinesis target ARN
    EB_REGION           — AWS region (default us-east-1)
    EB_RULE_PREFIX      — prefix for all rule names (default 'janusec-')
    EB_EVENT_BUS        — event bus name (default 'default')
"""
from __future__ import annotations

import argparse
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_REGION = os.getenv('EB_REGION', 'us-east-1')
_DEFAULT_PREFIX = os.getenv('EB_RULE_PREFIX', 'janusec-')
_DEFAULT_BUS = os.getenv('EB_EVENT_BUS', 'default')


# ---------------------------------------------------------------------------
# Rule definitions — the 5 canonical Janusec EventBridge rules
# ---------------------------------------------------------------------------

def _build_rules(sqs_arn: str, kinesis_arn: str) -> list[dict[str, Any]]:
    """Return the 5 rule definitions with their targets.

    Each entry has:
        name        — rule name (without prefix)
        description — human-readable purpose
        pattern     — EventBridge event pattern (dict)
        targets     — list of {Id, Arn} target dicts
    """
    return [
        {
            'name': 'guardduty-to-sqs',
            'description': 'Route GuardDuty findings to Janusec ingest SQS queue',
            'pattern': {
                'source': ['aws.guardduty'],
                'detail-type': ['GuardDuty Finding'],
            },
            'targets': [{'Id': 'JanusecSQS', 'Arn': sqs_arn}],
        },
        {
            'name': 'securityhub-to-kinesis',
            'description': 'Route Security Hub findings to Janusec Kinesis stream',
            'pattern': {
                'source': ['aws.securityhub'],
                'detail-type': ['Security Hub Findings - Imported'],
            },
            'targets': [{'Id': 'JanusecKinesis', 'Arn': kinesis_arn}],
        },
        {
            'name': 'cloudtrail-iam-to-kinesis',
            'description': 'Route high-value CloudTrail IAM API calls to Kinesis',
            'pattern': {
                'source': ['aws.cloudtrail'],
                'detail-type': ['AWS API Call via CloudTrail'],
                'detail': {
                    'eventSource': ['iam.amazonaws.com'],
                    'eventName': [
                        'CreateUser',
                        'AttachUserPolicy',
                        'CreateAccessKey',
                        'CreateLoginProfile',
                        'UpdateAssumeRolePolicy',
                        'PutRolePolicy',
                    ],
                },
            },
            'targets': [{'Id': 'JanusecKinesis', 'Arn': kinesis_arn}],
        },
        {
            'name': 'config-change-to-kinesis',
            'description': 'Route AWS Config compliance changes to Kinesis',
            'pattern': {
                'source': ['aws.config'],
                'detail-type': ['Config Rules Compliance Change'],
                'detail': {
                    'newEvaluationResult': {
                        'complianceType': ['NON_COMPLIANT'],
                    },
                },
            },
            'targets': [{'Id': 'JanusecKinesis', 'Arn': kinesis_arn}],
        },
        {
            'name': 'macie-to-sqs',
            'description': 'Route Macie data-classification findings to ingest SQS',
            'pattern': {
                'source': ['aws.macie2'],
                'detail-type': ['Macie Finding'],
            },
            'targets': [{'Id': 'JanusecSQS', 'Arn': sqs_arn}],
        },
    ]


# ---------------------------------------------------------------------------
# Deploy / teardown helpers
# ---------------------------------------------------------------------------

def deploy_rules(
    sqs_arn: str,
    kinesis_arn: str,
    region: str = _DEFAULT_REGION,
    prefix: str = _DEFAULT_PREFIX,
    event_bus: str = _DEFAULT_BUS,
) -> dict[str, Any]:
    """Deploy all 5 EventBridge rules and their targets.

    Returns a summary dict with per-rule status.
    """
    import json
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError('boto3 is required for EventBridge rule deployment') from exc

    client = boto3.client('events', region_name=region)
    rules = _build_rules(sqs_arn, kinesis_arn)
    results: dict[str, Any] = {}

    for rule in rules:
        full_name = prefix + rule['name']
        try:
            # Create / update rule
            client.put_rule(
                Name=full_name,
                EventBusName=event_bus,
                EventPattern=json.dumps(rule['pattern']),
                State='ENABLED',
                Description=rule['description'],
            )
            # Attach targets
            client.put_targets(
                Rule=full_name,
                EventBusName=event_bus,
                Targets=rule['targets'],
            )
            results[full_name] = {'status': 'deployed'}
            logger.info('eventbridge_rules: deployed %s', full_name)
        except Exception as exc:
            results[full_name] = {'status': 'failed', 'error': str(exc)}
            logger.error('eventbridge_rules: failed to deploy %s: %s', full_name, exc)

    return results


def teardown_rules(
    region: str = _DEFAULT_REGION,
    prefix: str = _DEFAULT_PREFIX,
    event_bus: str = _DEFAULT_BUS,
) -> dict[str, Any]:
    """Remove all EventBridge rules whose names start with *prefix*.

    Targets are removed before the rule is deleted (AWS requirement).
    """
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError('boto3 is required for EventBridge teardown') from exc

    client = boto3.client('events', region_name=region)
    results: dict[str, Any] = {}

    try:
        paginator = client.get_paginator('list_rules')
        for page in paginator.paginate(NamePrefix=prefix, EventBusName=event_bus):
            for r in page.get('Rules', []):
                name = r['Name']
                try:
                    # Fetch + remove targets first
                    targets_resp = client.list_targets_by_rule(
                        Rule=name, EventBusName=event_bus
                    )
                    target_ids = [t['Id'] for t in targets_resp.get('Targets', [])]
                    if target_ids:
                        client.remove_targets(
                            Rule=name, EventBusName=event_bus, Ids=target_ids
                        )
                    client.delete_rule(Name=name, EventBusName=event_bus)
                    results[name] = {'status': 'deleted'}
                    logger.info('eventbridge_rules: deleted %s', name)
                except Exception as exc:
                    results[name] = {'status': 'failed', 'error': str(exc)}
                    logger.error('eventbridge_rules: failed to delete %s: %s', name, exc)
    except Exception as exc:
        logger.error('eventbridge_rules: list_rules failed: %s', exc)
        results['_list_error'] = str(exc)

    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Deploy or tear down Janusec EventBridge rules')
    parser.add_argument('--deploy', action='store_true', help='Deploy all rules')
    parser.add_argument('--teardown', action='store_true', help='Delete all janusec-prefixed rules')
    parser.add_argument('--sqs-arn', default=os.getenv('EB_SQS_ARN', ''), help='SQS target ARN')
    parser.add_argument('--kinesis-arn', default=os.getenv('EB_KINESIS_ARN', ''), help='Kinesis target ARN')
    parser.add_argument('--region', default=_DEFAULT_REGION)
    parser.add_argument('--prefix', default=_DEFAULT_PREFIX)
    parser.add_argument('--event-bus', default=_DEFAULT_BUS)
    args = parser.parse_args()

    if args.deploy:
        if not args.sqs_arn or not args.kinesis_arn:
            print('ERROR: --sqs-arn and --kinesis-arn are required for --deploy', file=sys.stderr)
            sys.exit(1)
        import json as _json
        result = deploy_rules(args.sqs_arn, args.kinesis_arn, args.region, args.prefix, args.event_bus)
        print(_json.dumps(result, indent=2))
    elif args.teardown:
        import json as _json
        result = teardown_rules(args.region, args.prefix, args.event_bus)
        print(_json.dumps(result, indent=2))
    else:
        parser.print_help()
        sys.exit(1)
