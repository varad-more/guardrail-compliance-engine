#!/usr/bin/env python3
"""Lightweight Bedrock access smoke test for guardrail-compliance-engine."""

from __future__ import annotations

import os
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


def main() -> int:
    region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"
    print(f"Using region: {region}")

    try:
        sts = boto3.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        print(f"STS OK: {identity.get('Arn')}")
    except NoCredentialsError:
        print("ERROR: AWS credentials not found", file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as exc:
        print(f"ERROR: STS check failed: {exc}", file=sys.stderr)
        return 2

    try:
        bedrock = boto3.client("bedrock", region_name=region)
        models = bedrock.list_foundation_models(byOutputModality="TEXT")
        model_count = len(models.get("modelSummaries", []))
        print(f"Bedrock models visible: {model_count}")
    except (BotoCoreError, ClientError) as exc:
        print(f"ERROR: list_foundation_models failed: {exc}", file=sys.stderr)
        return 1

    try:
        guardrails = bedrock.list_guardrails(maxResults=20)
        guardrail_count = len(guardrails.get("guardrails", []))
        print(f"Bedrock guardrails visible: {guardrail_count}")
    except (BotoCoreError, ClientError) as exc:
        print(f"ERROR: list_guardrails failed: {exc}", file=sys.stderr)
        return 1

    print("Bedrock smoke test passed ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
