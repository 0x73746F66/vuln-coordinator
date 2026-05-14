---
title: "IaC — Terraform and Nix flake misconfigurations"
description: "Triaging VNX-TF-* findings: per-rule fixes for the eight built-in rules, plus Nix flake handling."
weight: 50
---

IaC findings are usually faster to fix than SCA or SAST — the code change is small, the verification (`terraform plan`) is quick, and the deploy is gated by the existing change-management process. The catch is that an applied misconfiguration may have created cloud state that survives the fix; rolling back the Terraform doesn't always roll back the data exposure it caused.

## What IaC scanning finds

Findings land in `.vulnetix/sast.sarif` with `ruleId: VNX-TF-NNN`. Eight built-in Terraform rules at the time of writing, plus pattern coverage for Nix flake misconfigurations. Targets:

- `*.tf` — HashiCorp Terraform HCL.
- `flake.nix`, `flake.lock` — Nix flakes.

The standard SARIF location fields point to the `.tf` line. Reading the rule's docs page (`/docs/sast-rules/vnx-tf-NNN/`) gives the Bad / Good example for that specific pattern.

```bash
# Every IaC finding, with file + line
jq '.runs[].results[]
    | select(.ruleId | startswith("VNX-TF-"))
    | {
        ruleId,
        file: .locations[0].physicalLocation.artifactLocation.uri,
        line: .locations[0].physicalLocation.region.startLine,
        message: .message.text
      }' .vulnetix/sast.sarif

# Group by rule for "which misconfigurations are most common in our IaC"
jq '[.runs[].results[]
     | select(.ruleId | startswith("VNX-TF-"))
     | .ruleId]
    | group_by(.)
    | map({rule: .[0], count: length})
    | sort_by(-.count)' .vulnetix/sast.sarif

# All flagged Terraform modules — for splitting work across team
jq '[.runs[].results[]
     | select(.ruleId | startswith("VNX-TF-"))
     | .locations[0].physicalLocation.artifactLocation.uri]
    | unique' .vulnetix/sast.sarif
```

## The eight Terraform rules

Severities and CWE mappings from the Vulnetix docs. Each pattern below has a worked HCL example.

### VNX-TF-001: public S3 bucket access (High, CWE-200)

The S3 default has changed over the years; the rule catches both the legacy ACL setting and the newer policy-based public exposure.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_s3_bucket" "public_assets" {
  bucket = "yourorg-public-assets"
  acl    = "public-read"   # FLAGGED
}
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "yourorg-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# For content that needs to be globally readable, front the bucket
# with CloudFront + Origin Access Control. The bucket itself stays private.
resource "aws_cloudfront_distribution" "assets" {
  # ... origin points at the S3 bucket via OAC
}
```
{{< /tab >}}
{{< /tabs >}}

After deploying the fix, verify the public-access-block landed:

```bash
aws s3api get-public-access-block --bucket yourorg-assets
# All four flags should be true
```

If the bucket was previously public, audit access logs for the exposure window and document anything that needs disclosure.

### VNX-TF-002: unrestricted security group ingress (High, CWE-284)

`0.0.0.0/0` on a non-public port (SSH 22, RDP 3389, database ports) is the textbook misconfiguration that ends up in the news.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_security_group" "ssh" {
  name = "allow-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # FLAGGED
  }
}
```
{{< /tab >}}
{{< tab name="Good (narrow CIDR)" >}}
```hcl
resource "aws_security_group" "ssh" {
  name = "allow-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.bastion_cidr]   # e.g. ["10.0.1.0/24"]
  }
}
```
{{< /tab >}}
{{< tab name="Good (no SSH at all)" >}}
```hcl
# Use SSM Session Manager for shell access — no SSH port open
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```
{{< /tab >}}
{{< /tabs >}}

The strongest version is no port open at all: SSM Session Manager (AWS), IAP tunnelling (GCP), or Bastion service (Azure) let you reach an instance without an inbound SSH rule.

### VNX-TF-003: missing CloudTrail logging (Medium)

CloudTrail-equivalent on the other clouds. Without it, you have no audit trail when something goes wrong.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
# No CloudTrail resource — silent infrastructure
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_cloudtrail" "primary" {
  name                          = "primary"
  s3_bucket_name                = aws_s3_bucket.audit_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
```
{{< /tab >}}
{{< /tabs >}}

`enable_log_file_validation` produces a digest file so you can detect tampering. The bucket for the logs should itself be private and lifecycle-rule-protected.

### VNX-TF-004: missing log retention / encryption (Medium)

CloudWatch Logs / equivalent: data is plaintext by default, and groups have no retention by default.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_cloudwatch_log_group" "app" {
  name = "/aws/lambda/myapp"
  # no retention, no KMS key
}
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/lambda/myapp"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}
```
{{< /tab >}}
{{< /tabs >}}

### VNX-TF-005: missing EBS encryption (Medium, CWE-311)

EBS volumes are unencrypted by default unless the account-level "Encrypt by default" flag is set.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted = false (the default)
}
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}

# Better: set account-level default
resource "aws_ebs_encryption_by_default" "default" {
  enabled = true
}
```
{{< /tab >}}
{{< /tabs >}}

The account-level setting is the more robust answer because it catches volumes created by any path, including those provisioned outside Terraform.

### VNX-TF-006: EC2 instance metadata service v1 exposure (Medium)

IMDSv1 is unauthenticated and accessible from any pod / container on the host. An SSRF in an application becomes a credential-theft vector via IMDSv1. IMDSv2 requires a session token, which an SSRF can't typically obtain.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_instance" "web" {
  ami           = "ami-..."
  instance_type = "t3.small"
  metadata_options {
    http_tokens = "optional"   # FLAGGED — IMDSv1 still allowed
  }
}
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_instance" "web" {
  ami           = "ami-..."
  instance_type = "t3.small"
  metadata_options {
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 1            # blocks containerised access
    http_endpoint               = "enabled"
  }
}
```
{{< /tab >}}
{{< /tabs >}}

Set `http_put_response_hop_limit = 1` to prevent a container running on the host from reaching IMDS via the host's network namespace.

### VNX-TF-007: missing RDS encryption (Medium, CWE-311)

Same shape as EBS — encryption-at-rest off by default on older RDS configurations.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_db_instance" "primary" {
  identifier         = "myapp-primary"
  allocated_storage  = 100
  engine             = "postgres"
  engine_version     = "16.3"
  instance_class     = "db.t3.medium"
  # storage_encrypted = false (default)
}
```
{{< /tab >}}
{{< tab name="Good" >}}
```hcl
resource "aws_db_instance" "primary" {
  identifier               = "myapp-primary"
  allocated_storage        = 100
  engine                   = "postgres"
  engine_version           = "16.3"
  instance_class           = "db.t3.medium"
  storage_encrypted        = true
  kms_key_id               = aws_kms_key.rds.arn
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
}
```
{{< /tab >}}
{{< /tabs >}}

Existing unencrypted RDS instances can't be encrypted in-place — you'll need to snapshot, encrypt the snapshot, restore from it, and switch over. Plan it as a maintenance window.

### VNX-TF-008: hardcoded credentials in resources (High, CWE-798)

Provider blocks, RDS instances, and service-specific resources all have password / secret fields that get left as literals.

{{< tabs >}}
{{< tab name="Bad" >}}
```hcl
resource "aws_db_instance" "primary" {
  identifier = "myapp"
  username   = "admin"
  password   = "Hunter2!"   # FLAGGED
}
```
{{< /tab >}}
{{< tab name="Good (SSM Parameter Store)" >}}
```hcl
data "aws_ssm_parameter" "db_password" {
  name            = "/myapp/db/admin/password"
  with_decryption = true
}

resource "aws_db_instance" "primary" {
  identifier = "myapp"
  username   = "admin"
  password   = data.aws_ssm_parameter.db_password.value
}
```
{{< /tab >}}
{{< tab name="Good (random + Secrets Manager)" >}}
```hcl
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db" {
  name = "myapp/db/admin"
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({ username = "admin", password = random_password.db.result })
}

resource "aws_db_instance" "primary" {
  identifier = "myapp"
  manage_master_user_password = true   # RDS reads from Secrets Manager automatically
}
```
{{< /tab >}}
{{< /tabs >}}

The `manage_master_user_password` option (relatively recent) lets RDS own the password lifecycle and read it from Secrets Manager — no Terraform state needs the value at all.

The hardcoded-credentials rule also catches AWS access keys, GCP service account keys, and similar in provider blocks. Provider credentials should always come from environment variables or workload identity, never inline.

## Worked example: hardening a public S3 bucket end-to-end

The starting state — a bucket exposed for serving static assets, found by VNX-TF-001:

```hcl
# BEFORE
resource "aws_s3_bucket" "assets" {
  bucket = "yourorg-public-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "${aws_s3_bucket.assets.arn}/*"
    }]
  })
}
```

The fix — bucket goes private, CloudFront fronts it via Origin Access Control:

```hcl
# AFTER
resource "aws_s3_bucket" "assets" {
  bucket = "yourorg-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudfront_origin_access_control" "assets" {
  name                              = "s3-assets-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "assets" {
  enabled = true
  origin {
    domain_name              = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_id                = "s3-assets"
    origin_access_control_id = aws_cloudfront_origin_access_control.assets.id
  }
  default_cache_behavior {
    target_origin_id       = "s3-assets"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6"  # Managed-CachingOptimized
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
  restrictions {
    geo_restriction { restriction_type = "none" }
  }
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.assets.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.assets.arn }
      }
    }]
  })
}
```

Verification:

```bash
# 1. Apply
terraform plan -out=tf.plan
terraform apply tf.plan

# 2. Confirm bucket is private
aws s3api get-public-access-block --bucket yourorg-assets

# 3. Confirm direct access is denied
curl -I https://yourorg-assets.s3.amazonaws.com/some-object.jpg
# HTTP/1.1 403 Forbidden

# 4. Confirm CloudFront access works
curl -I https://d1234.cloudfront.net/some-object.jpg
# HTTP/2 200
```

## Nix flake handling

Nix flakes are a smaller part of Vulnetix's IaC coverage. Findings on `flake.nix` and `flake.lock` typically flag stale input pins or insecure default settings on derivations.

Fixing a stale `flake.lock`:

```bash
# Update one specific input
nix flake lock --update-input nixpkgs

# Update all inputs (less common — risk of drift)
nix flake update

# Override an input to a fork or local path
nix flake lock --override-input nixpkgs github:nixos/nixpkgs/nixos-23.11
```

`flake.lock` entries are immutable git revisions + `narHash` digests, so the integrity story is strong. The drift problem is usually about staleness — a `flake.lock` from a year ago references nixpkgs commits without the latest CVE fixes.

## Producing the OpenVEX

IaC findings always go to OpenVEX. Subject can be either the source manifest (pre-apply, for the finding-and-fix in source) or the cloud resource ARN (post-apply, for the resolved live state).

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-tf-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T13:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "VNX-TF-001",
        "description": "Public S3 bucket access via aws_s3_bucket.acl = public-read. CWE-200. See https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-001/"
      },
      "products": [{
        "@id": "arn:aws:s3:::yourorg-assets",
        "identifiers": { "purl": "pkg:terraform/yourorg/yourrepo/modules/storage/main.tf" }
      }],
      "status": "fixed",
      "action_statement": "Bucket renamed to yourorg-assets, public ACL removed. aws_s3_bucket_public_access_block attached with all four flags true. CloudFront distribution with Origin Access Control fronts the bucket for public-facing assets. Verified post-apply with aws s3api get-public-access-block and a direct curl against the bucket endpoint returning 403. See MR !198. Audit of previous access logs filed as INC-2026-051."
    }
  ]
}
```
{{< /outcome >}}
