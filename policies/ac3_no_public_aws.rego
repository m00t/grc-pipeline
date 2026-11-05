# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: Every aws_s3_bucket must have a public access block with all four flags true.
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: Add aws_s3_bucket_public_access_block referencing the bucket, all four flags true.
package compliance.ac3_aws

import rego.v1

# The four flags that primary_public_access and log_public_access must set to true.
required_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

# Deny any bucket (primary or log) with no public access block pointing at it.
deny contains msg if {
	some bucket in input.configuration.root_module.resources
	bucket.type == "aws_s3_bucket"
	address := sprintf("%s.%s", [bucket.type, bucket.name])
	count(blocks_for(address)) == 0
	msg := sprintf(
		"AC-3: %s has no public access block. Remediation: add an aws_s3_bucket_public_access_block with bucket = %s.id and all four flags set to true.",
		[address, address],
	)
}

# Deny any bucket whose public access block has a flag not set to true.
deny contains msg if {
	some bucket in input.configuration.root_module.resources
	bucket.type == "aws_s3_bucket"
	address := sprintf("%s.%s", [bucket.type, bucket.name])
	some block in blocks_for(address)
	bad := [flag | some flag in required_flags; not flag_is_true(block, flag)]
	count(bad) > 0
	msg := sprintf(
		"AC-3: %s does not set %s to true. Remediation: set all four flags to true on %s.",
		[block, concat(", ", bad), block],
	)
}

# Finds the public access block whose bucket = line points at this bucket,
# example is primary_public_access has bucket = aws_s3_bucket.primary.id.
blocks_for(address) := {block |
	some pab in input.configuration.root_module.resources
	pab.type == "aws_s3_bucket_public_access_block"
	some ref in pab.expressions.bucket.references
	refers_to(ref, address)
	block := sprintf("%s.%s", [pab.type, pab.name])
}

# True if the plan sets this flag to true on this block.
# Flag values come from planned_values, not configuration.
flag_is_true(block, flag) if {
	some r in input.planned_values.root_module.resources
	r.address == block
	r.values[flag] == true
}

# Matches "aws_s3_bucket.primary" and "aws_s3_bucket.primary.id".
refers_to(ref, address) if ref == address

refers_to(ref, address) if startswith(ref, concat("", [address, "."]))