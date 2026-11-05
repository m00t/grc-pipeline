# GRC Pipeline: Policy-as-Code Compliance for AWS

An end-to-end pipeline that takes AWS infrastructure from "it works" to "it is audit-defensible", with
code doing the checking instead of people. Every control is enforced by policy before deployment, every
change is gated in CI, the evidence is signed so it cannot be quietly edited, and the whole system is
mapped to **NIST SP 800-53 Rev 5** in OSCAL, so an assessor can follow a link from a control to its proof
and verify it without talking to anyone.

## How It Works

| Stage | What it does | Section |
|---|---|---|
| 1. Infrastructure as code | Terraform S3 buckets: encrypted, public access blocked, tagged, versioned, access-logged | [Controls](#enforced-nist-sp-800-53-controls) |
| 2. Policy as code | Rego policies deny any Terraform plan that breaks a control; 6/6 unit tests pass | [Policy-as-Code](#policy-as-code-controls) |
| 3. CI gate | Every pull request generates the plan in CI and runs the policies; branch protection blocks a failing merge | [CI Gate](#ci-policy-gate), [Keyless CI](#keyless-ci-generating-the-plan-with-github-oidc) |
| 4. Signed evidence | Each run's evidence is hashed and signed with Cosign keyless; an Object Lock vault proved write-once preservation | [Chain of Custody](#evidence-chain-of-custody) |
| 5. Native monitoring | CloudTrail, AWS Config and Security Hub (NIST 800-53) findings, captured and signed | [Account Baseline](#account-baseline-native-aws-controls) |
| 6. OSCAL mapping | A profile and component definition linking each control to signed evidence | [OSCAL](#oscal-control-mapping) |

## Enforced NIST SP 800-53 Controls

* **SC-28 (Protection of Information at Rest):** Server-side encryption on every bucket. *Policy-enforced in the gate.*
* **AC-3 (Access Enforcement):** S3 Public Access Block with all four flags on every bucket. *Policy-enforced in the gate.*
* **CM-6 (Configuration Settings):** Four required baseline tags on every taggable resource (*policy-enforced*), and versioning on the primary bucket (*implemented in Terraform, not yet policy-enforced*).
* **AU-3 (Content of Audit Records):** S3 server access logging from the primary bucket to a dedicated log bucket. *Implemented in Terraform, not yet policy-enforced.*

## Repository Structure

* `main.tf`: Core resource definitions, encryption, access controls, and logging configurations.
* `variables.tf`: Input variables for customization.
* `outputs.tf`: Module outputs including encryption details.
* `verify.sh`: Post-apply validation script for control verification.
* `evidence/`: Evidence files bundled and signed by every gate run: policy test output, plan JSON, and the redacted Security Hub and CloudTrail captures.
* `policies/`: Rego policies and unit tests that enforce SC-28, AC-3 and CM-6 against the Terraform plan.
* `.github/workflows/grc-gate.yml`: CI policy gate that runs the policies on every pull request to `main`.
* `verify-evidence.sh`: Verifies a signed evidence bundle's integrity, authenticity and timeliness. Prints `CHAIN INTACT` only if every check passes.
* `vault/`: Terraform for the S3 Object Lock evidence vault (write-once storage for signed evidence).
* `baseline/`: Terraform for the account baseline (multi-region CloudTrail with log file validation, AWS Config, Security Hub with NIST 800-53 Rev 5) and `teardown.sh`.
* `oscal/`: OSCAL workspace (compliance-trestle): the profile and component definition mapping this pipeline to NIST SP 800-53 Rev 5.
* `attestations/`: Published signed evidence bundles that the OSCAL evidence links point at.

## Usage

```bash
# Deploy the compliant storage (Terraform >= 1.6, AWS credentials)
terraform init
terraform plan -out tfplan -var="environment=dev" -var="project_name=compliance-lab"
terraform apply tfplan

# Run the policy unit tests (OPA)
opa test policies/ -v

# Gate a plan locally, as CI does (Conftest)
terraform show -json tfplan > plan.json
conftest test plan.json -p policies --all-namespaces

# Verify a signed evidence bundle (Cosign)
cd attestations/pr-12 && bash ../../verify-evidence.sh evidence.tar.gz

# Validate the OSCAL documents (compliance-trestle)
cd oscal
trestle validate -f profiles/grc-pipeline-profile/profile.json
trestle validate -f component-definitions/my-pipeline/component-definition.json
```

## Policy-as-Code Controls

Rego policies (Open Policy Agent) read the Terraform plan and deny any plan that violates a control.

| Control | Policy | Denies |
|---|---|---|
| **SC-28** Protection of Information at Rest | `policies/sc28_encryption_aws.rego` | Any bucket with no matching encryption configuration |
| **AC-3** Access Enforcement | `policies/ac3_no_public_aws.rego` | Any bucket whose public access block is missing or has any of its four flags not set to `true` |
| **CM-6** Configuration Settings | `policies/cm6_required_tags_aws.rego` | Any taggable resource missing one of the four required tags |

### Test Results

```
policies\sc28_encryption_aws_test.rego:24:
data.compliance.sc28_aws.test_unencrypted_bucket_denied: PASS (2.0935ms)

policies\cm6_required_tags_aws_test.rego:24:
data.compliance.cm6_aws.test_all_tags_present_passes: PASS (2.6631ms)
policies\cm6_required_tags_aws_test.rego:28:
data.compliance.cm6_aws.test_missing_tags_denied: PASS (2.6631ms)

policies\sc28_encryption_aws_test.rego:20:
data.compliance.sc28_aws.test_compliant_bucket_passes: PASS (2.0935ms)

policies\ac3_no_public_aws_test.rego:39:
data.compliance.ac3_aws.test_missing_pab_denied: PASS (2.6631ms)
policies\ac3_no_public_aws_test.rego:35:
data.compliance.ac3_aws.test_complete_pab_passes: PASS (3.1359ms)
--------------------------------------------------------------------------------
PASS: 6/6
```

### Design Note: Match by Reference

At plan time the bucket name is unknown, because its random suffix isn't generated until apply. So the
policies can't match an encryption configuration or public access block to its bucket by name.
Instead they match by reference: the plan JSON records that the encryption resource's `bucket`
argument points at `aws_s3_bucket.primary.id`, and the policy compares that reference to the bucket's
address.

## CI Policy Gate

Every pull request to `main` runs `.github/workflows/grc-gate.yml`. Nobody reviews a change for
encryption, public access or tagging by hand: the pipeline does it in seconds.

**What the gate does:**

1. Assumes a read-only AWS role through GitHub OIDC (no stored keys) and generates the Terraform plan from the branch's code.
2. Installs Conftest at a pinned version (`0.62.0`) and runs the SC-28, AC-3 and CM-6 policies against the plan.
3. Bundles the evidence, hashes it and signs it with Cosign keyless signing.
4. Uploads the signed bundle (`evidence.tar.gz`, `.sha256`, `.sig.bundle`) as a build artifact on every run, pass or fail.
5. Fails the job last if any policy reported a violation (fail closed), so even a failed run's evidence is signed and kept.

**What happens when a control breaks:** the matching policy fails, the `grc-gate` check goes red,
and branch protection on `main` requires that check to pass, so the pull request cannot be merged
by anyone until the violation is fixed. The failure message names the resource and the remediation,
and the evidence artifact keeps a record of the failure.

| Pull request | Change | Result |
|---|---|---|
| [#1](https://github.com/m00t/grc-pipeline/pull/1) | Compliant plan | ✅ `grc-gate` passed, merged |
| [#2](https://github.com/m00t/grc-pipeline/pull/2) | Plan with the primary bucket's encryption removed | ❌ SC-28 failed, merge blocked |

Example failure from #2:

```
SC-28: aws_s3_bucket.primary has no server-side encryption configuration.
Remediation: add an aws_s3_bucket_server_side_encryption_configuration with bucket = aws_s3_bucket.primary.id.
```

## Keyless CI: Generating the Plan with GitHub OIDC

The gate generates the Terraform plan itself on every pull request, from the code in the branch,
instead of trusting a committed `plan.json`. To do that, CI needs to read AWS, and it does so
without any stored credentials.

**How it works:** GitHub issues the workflow a short-lived, signed OIDC token that identifies the
exact repository and event. AWS trusts GitHub as an identity provider and exchanges that token for
temporary credentials on a read-only IAM role (`ReadOnlyAccess`). The credentials expire on their
own within the hour. The role's trust policy accepts tokens only from this repository, matched on
GitHub's immutable account and repository IDs, so a renamed or recreated repository with the same
name cannot assume it.

**Why keyless beats stored credentials:** a stored access key is a long-lived secret. It can leak
through logs, forks or a compromised CI system, it works from anywhere until someone notices and
revokes it, and it has to be rotated by hand. With OIDC there is no secret to steal. Every session
is minted on demand, scoped to one repository, limited to read-only access, and expires
automatically. Each login is also recorded in AWS CloudTrail as a web-identity session tied to the
repository and event, which gives auditors a clear trail of who accessed the account and why.

| Pull request | Change | Result |
|---|---|---|
| [#4](https://github.com/m00t/grc-pipeline/pull/4) | Generate the plan in CI via OIDC | ✅ Plan generated from `main.tf`, all policies passed |
| [#5](https://github.com/m00t/grc-pipeline/pull/5) | Primary bucket encryption removed from `main.tf` | ❌ SC-28 failed, merge blocked |

**Lesson learned:** the first OIDC attempt was denied (`Not authorized to perform
sts:AssumeRoleWithWebIdentity`). The CloudTrail record of the failed login showed that GitHub's
token subject includes immutable IDs (`repo:OWNER@ID/REPO@ID:pull_request`), not the
`repo:OWNER/REPO:*` format the trust policy expected. Updating the trust policy to that format
fixed it, and it binds the role more tightly than a name-based match.

## Evidence Chain of Custody

Every gate run, pass or fail, packages its evidence (the CI-generated `plan.json` and the policy
results) into `evidence.tar.gz` and signs it with Cosign keyless signing. The signing identity is the
workflow run itself: GitHub's OIDC token proves it is `grc-gate.yml` in this repository, Sigstore
issues a short-lived certificate bound to that identity, and the signature is recorded in Sigstore's
public transparency log (Rekor). There is no private key to store, rotate or leak. The pass/fail
decision runs as the last step, so a failed run is signed and preserved too.

| Custody property | Question | Artifact that proves it |
|---|---|---|
| **Integrity** | Has it changed? | `evidence.tar.gz.sha256`: SHA-256 of the bundle, recomputed by `verify-evidence.sh` |
| **Authenticity** | Who produced it? | `evidence.sig.bundle`: signature plus Sigstore certificate naming this repository's `.github/workflows/grc-gate.yml` as the signer (`m00t/grc-pipeline`; bundles signed before the rename name `m00t/grc-terraform-aws-bucket`) |
| **Timeliness** | When was it produced? | `evidence.sig.bundle`: Rekor transparency-log entry with a signed timestamp |
| **Preservation** | Can it still be retrieved unaltered? | S3 Object Lock vault (`vault/main.tf`): each run's signed bundle is written once in GOVERNANCE mode; `verify-evidence.sh` confirms retention is in the future and the vaulted copy matches byte for byte |

`verify-evidence.sh` pins the OIDC issuer to GitHub Actions and the certificate identity to this
repository's `grc-gate.yml` workflow, so a valid signature from any other repository or workflow is
rejected.

### Tamper Test

Signed evidence from [#7](https://github.com/m00t/grc-pipeline/pull/7), verified locally:

| Test | Result |
|---|---|
| Original bundle | ✅ `CHAIN INTACT` |
| One line appended to the bundle | ❌ `FAIL: INTEGRITY`: hash changed from `5fb4c035…` to `e3053ae0…` |
| One line appended **and** the `.sha256` sidecar rewritten to match | ❌ `FAIL: AUTHENTICITY`: the signature still binds the original hash (`5fb4c035…`), and only this repository's workflow can produce a new one |

The third test is the one that matters: a hash on its own can be regenerated by anyone, but the
signature cannot be forged without running as this repository's workflow, and that proof lives in
Sigstore, not in any account an attacker could compromise.

### Immutable Evidence Vault

When the `VAULT_BUCKET` repository variable is set, each gate run also writes its signed bundle to an
S3 bucket with versioning and Object Lock (GOVERNANCE mode, 1-day default retention). The pipeline's
role can only `s3:PutObject` under `evidence/`: no read, delete, retention change or governance bypass.
The vault itself is encrypted, blocks public access, and passes the same SC-28, AC-3 and CM-6 policies.

| Test | Result |
|---|---|
| `verify-evidence.sh` with the vaulted copy | ✅ All four properties pass, `CHAIN INTACT` |
| Admin attempts to delete the locked evidence version | ❌ `AccessDenied ... object protected by object lock` |

The vault is short-lived by design: applied, exercised with one run's evidence, verified, then torn down
the same day.

## Account Baseline: Native AWS Controls

`baseline/` turns on the native controls that watch the account itself, captures what they report as
evidence, and is torn down the same day.

| Control | Implementation | Evidence |
|---|---|---|
| **AU-2** Event Logging | Multi-region CloudTrail recording management events (no billable data events) | `evidence/cloudtrail-status.json` |
| **AU-12** Audit Record Generation | One trail covering every region and global service events | `evidence/cloudtrail-status.json` (`IsLogging: true`) |
| **AU-10** Non-repudiation | `enable_log_file_validation = true`: CloudTrail delivers a signed digest file every hour, so any change to a log file after delivery is detectable | `evidence/cloudtrail-status.json` (digest delivery timestamps) |
| **RA-5** Vulnerability Monitoring and Scanning | Security Hub with only the NIST SP 800-53 Rev 5 standard subscribed (297 automated controls) | `evidence/security-hub-findings.json` |
| **SI-4** System Monitoring | Security Hub continuously evaluating the account against the standard | `evidence/security-hub-findings.json`, `evidence/security-hub-standards.json` |

The log bucket is private, encrypted (SSE-S3), blocks public access, denies non-TLS requests, and its
policy lets CloudTrail write only when `aws:SourceArn` is this trail, and AWS Config only from this account.

### The AWS Config Gap

The first run left AWS Config off. Security Hub reported the gap itself: the NIST standard stayed
`INCOMPLETE` with reason `NO_AVAILABLE_CONFIGURATION_RECORDER`, and after more than an hour it had
produced no findings, because most NIST controls evaluate Config data. A missing control surfaced by an
automated check is valid evidence, but it also meant the scanning control (RA-5) was not actually
working. The second run added a short-lived Config recorder (`baseline/config.tf`), and findings arrived
within minutes.

### What the Findings Surfaced

Selected results from `evidence/security-hub-findings.json`:

| Control | Severity | Status | Meaning |
|---|---|---|---|
| IAM.6 | CRITICAL | FAILED | Root user has no hardware MFA |
| GuardDuty.1 | HIGH | FAILED | GuardDuty threat detection not enabled |
| EC2.2 | HIGH | FAILED | Default VPC security group allows traffic |
| CloudTrail.1 | INFORMATIONAL | PASSED | Multi-region trail with management events |
| CloudTrail.2 | MEDIUM | FAILED | Trail logs use SSE-S3; the standard expects KMS |
| CloudTrail.5 | MEDIUM | FAILED | Trail not integrated with CloudWatch Logs |
| S3.9 / S3.11 / S3.14 | MEDIUM / LOW | FAILED | Log bucket lacks access logging, event notifications, versioning |

The CloudTrail and S3 findings apply to the baseline built here: private and encrypted was not enough
for the NIST bar. They are recorded as gaps rather than fixed, because the baseline exists to observe and
then be torn down.

### Evidence Handling

The AWS account ID and IAM user name were redacted from all three evidence files before commit. They
are bundled and signed by the same keyless Cosign pipeline as every other gate run, and can be checked
with `verify-evidence.sh`.

**Cost discipline:** applied and torn down the same day with `baseline/teardown.sh`. CloudTrail
management events are free; Security Hub and Config billed only for the checks and resources recorded
while running.

## OSCAL Control Mapping

The pipeline's proof lives in engineering formats: Terraform, Rego, JSON and signed bundles. OSCAL, NIST's
machine-readable format for controls and evidence, is the bridge to an assessor. `oscal/` is a
[compliance-trestle](https://github.com/oscal-compass/compliance-trestle) workspace with two documents, both
validating `VALID` against OSCAL 1.2.1:

| Document | What it says |
|---|---|
| [Profile](oscal/profiles/grc-pipeline-profile/profile.json) | The claim: exactly four controls (`ac-3`, `au-3`, `cm-6`, `sc-28`) selected from the official NIST SP 800-53 Rev 5 catalog, and nothing else |
| [Component definition](oscal/component-definitions/my-pipeline/component-definition.json) | How each control is met: a plain-language description, the Terraform resource types that implement it, and a `rel: evidence` link to a signed bundle |

The descriptions state the limits honestly: AU-3 logging and CM-6 versioning are implemented in Terraform
but not enforced by a policy in the gate.

### Traversal

An assessor can walk the chain without contacting anyone:

```
NIST 800-53 catalog -> profile (4 controls) -> component (how) -> evidence href -> signed bundle -> verify
```

Following the SC-28 evidence link to [`attestations/pr-12/`](attestations/pr-12/), downloading the bundle and
its sidecars, and running `verify-evidence.sh` prints `CHAIN INTACT`: a machine-readable control statement,
an evidence link, a signed bundle and a passing verification, connected end to end.
