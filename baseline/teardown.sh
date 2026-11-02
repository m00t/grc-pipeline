#!/usr/bin/env bash
# teardown.sh - capture evidence, then destroy the account baseline.
# Run it the same day you apply: cost only stays in pennies if you tear down promptly.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"

echo "1) Capturing Security Hub findings as evidence before destroying..."
mkdir -p evidence
aws securityhub get-findings --region "$REGION" --max-results 50 \
  > evidence/security-hub-findings.json || echo "  (no findings yet, or Security Hub not enabled)"

echo "2) Destroying the baseline (CloudTrail, S3 log bucket, Security Hub subscriptions)..."
terraform destroy -auto-approve

echo
echo "Done. Verify nothing bills:"
echo "  - Security Hub standards detached: aws securityhub get-enabled-standards --region $REGION"
echo "  - CloudTrail gone:                 aws cloudtrail describe-trails --region $REGION"