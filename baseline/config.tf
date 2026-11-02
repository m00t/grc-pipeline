# AWS Config: gives Security Hub's NIST 800-53 controls the resource data they evaluate.
# Without a configuration recorder, the standard stays INCOMPLETE
# (NO_AVAILABLE_CONFIGURATION_RECORDER) and almost no findings are produced.
# Billable (cents): per configuration item recorded and per rule evaluation. Destroy the same day.

# AWS-managed role that lets Config read resource configurations.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "grc-baseline-recorder"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# Config snapshots go to the same private, encrypted log bucket, under config/.
resource "aws_config_delivery_channel" "this" {
  name           = "grc-baseline-delivery"
  s3_bucket_name = aws_s3_bucket.trail_logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.trail_logs]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}