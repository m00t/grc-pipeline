# Account baseline: native AWS controls that watch the account itself.
#   CloudTrail (multi-region, log file validation)  -> AU-2, AU-12, AU-10
#   Security Hub + NIST SP 800-53 Rev 5 standard     -> RA-5, SI-4
# Applied locally, separate from the gated module in the repo root.
# Billable (pennies): apply, capture findings, then destroy the same day.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project         = "compliance-lab"
      Environment     = "dev"
      ManagedBy       = "Terraform"
      ComplianceScope = "NIST"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  trail_name = "grc-baseline-trail"
  # Built from parts so the bucket policy can reference the trail before the trail exists.
  trail_arn = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------------------------
# Evidence bucket for CloudTrail logs: private, encrypted, public access blocked.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "grc-baseline-trail-logs-${random_id.suffix.hex}"
  force_destroy = true # same-day teardown: destroy removes the log objects too
}

# SC-28: encrypt at rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# AC-3: block all public access.
resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Only THIS trail (aws:SourceArn) and this account's AWS Config may write here, and only over TLS.
data "aws_iam_policy_document" "trail_logs" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # AWS Config delivery: only from this account, only into config/AWSLogs/<account>/.
  statement {
    sid       = "AWSConfigBucketCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.trail_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/config/AWSLogs/${local.account_id}/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail_logs.arn, "${aws_s3_bucket.trail_logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = data.aws_iam_policy_document.trail_logs.json

  depends_on = [aws_s3_bucket_public_access_block.trail_logs]
}

# ---------------------------------------------------------------------------
# CloudTrail: AU-2 / AU-12 (account-wide event logging), AU-10 (log file validation).
# Management events only (free). No data events.
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "baseline" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

# ---------------------------------------------------------------------------
# Security Hub: RA-5 / SI-4. Only the NIST 800-53 Rev 5 standard is subscribed.
# enable_default_standards = false stops AWS also turning on its default standards,
# which would multiply the number of billable checks.
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"

  depends_on = [aws_securityhub_account.this]
}

output "trail_name" {
  value = aws_cloudtrail.baseline.name
}

output "trail_logs_bucket" {
  value = aws_s3_bucket.trail_logs.id
}