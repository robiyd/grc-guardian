# GRC Guardian - Terraform Infrastructure

This Terraform configuration creates a simulated AWS organization environment for testing the GRC Guardian compliance engine. It deploys intentionally compliant and non-compliant resources to validate the compliance scanning capabilities.

## What Gets Deployed

### S3 Buckets (4 total)

**Compliant Buckets:**
1. `org-prod-logs-private` - Block public access ON, encryption ON, versioning ON
2. `org-dev-backups-encrypted` - Block public access ON, encryption ON, versioning ON

**Non-Compliant Buckets:**
3. `org-prod-assets-public` - Intentionally allows public read access (Principal="*")
4. `org-dev-data-unencrypted` - No encryption, no versioning

### IAM Resources

**Users:**
- `dev-no-mfa` - User without MFA enabled (non-compliant)
- `old-access-key-user` - User with access key for rotation testing (non-compliant)

**Roles:**
- `GuardianAuditAgentReadOnly` - Least-privilege read-only role for the compliance agent
  - Access to: AWS Config, S3 metadata, IAM read, CloudTrail, STS

### CloudTrail

- Trail: `grc-guardian-trail`
- Management events logging enabled
- Logs stored in dedicated S3 bucket

### AWS Config

- Configuration recorder: `grc-guardian-recorder`
- Delivery channel configured with S3 bucket
- **9 AWS Managed Config Rules:**
  1. `s3-bucket-public-read-prohibited`
  2. `s3-bucket-public-write-prohibited`
  3. `s3-bucket-server-side-encryption-enabled`
  4. `s3-bucket-versioning-enabled`
  5. `root-account-mfa-enabled`
  6. `iam-user-mfa-enabled`
  7. `access-keys-rotated` (max age: 90 days)
  8. `iam-password-policy`
  9. `cloudtrail-enabled`

## Prerequisites

- AWS CLI configured with credentials
- Terraform >= 1.5.0
- Appropriate IAM permissions to create:
  - S3 buckets
  - IAM users, roles, and policies
  - CloudTrail trails
  - AWS Config recorders and rules

## Deployment Instructions

### 1. Initialize Terraform

```bash
cd infra/terraform
terraform init
```

This downloads the AWS provider and initializes the working directory.

### 2. Review the Plan

```bash
terraform plan
```

This shows you what resources will be created. Review the output to ensure it matches expectations.

### 3. Apply the Configuration

```bash
terraform apply
```

Type `yes` when prompted to confirm the deployment.

**Expected Output:**
- 4 S3 buckets created
- 2 IAM users created
- 1 IAM role with policies created
- CloudTrail trail enabled
- AWS Config recorder started
- 9 Config rules deployed

### 4. Wait for AWS Config Evaluation

**IMPORTANT:** After the initial deployment, AWS Config needs time to:
- Discover all resources in the account
- Evaluate compliance against the 9 rules
- Generate compliance reports

**Wait 5-10 minutes** before querying compliance status.

### 5. Verify Deployment

```bash
# View all outputs
terraform output

# Check Config rule compliance
aws configservice describe-compliance-by-config-rule --region us-east-1

# List all Config rules
aws configservice describe-config-rules --region us-east-1

# Check specific bucket compliance
aws configservice get-compliance-details-by-resource \
  --resource-type AWS::S3::Bucket \
  --resource-id org-prod-assets-public-<account-id> \
  --region us-east-1
```

## Expected Compliance Results

### Compliant Resources
- `org-prod-logs-private` (all checks pass)
- `org-dev-backups-encrypted` (all checks pass)
- CloudTrail trail (enabled and logging)
- `GuardianAuditAgentReadOnly` role (least-privilege)

### Non-Compliant Resources
- `org-prod-assets-public` (fails public read/write checks)
- `org-dev-data-unencrypted` (fails encryption and versioning checks)
- `dev-no-mfa` user (fails MFA check)
- `old-access-key-user` (fails access key rotation check after 90 days)

## Testing the GRC Guardian Agent

Once deployed, use the `GuardianAuditAgentReadOnly` role ARN to authenticate the GRC Guardian agent:

```bash
# Get the role ARN
terraform output guardian_audit_agent_role_arn

# Configure agent to use the role
export GRC_GUARDIAN_ROLE_ARN=$(terraform output -raw guardian_audit_agent_role_arn)
```

The agent can then:
1. Query AWS Config for compliance state
2. Inspect S3 bucket configurations
3. Analyze IAM policies
4. Retrieve CloudTrail logs
5. Generate compliance reports

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

Type `yes` when prompted.

**Note:** This will delete:
- All 4 S3 buckets (must be empty first)
- IAM users and roles
- CloudTrail trail
- AWS Config recorder and rules

## Cost Considerations

Running this lab environment will incur costs:
- AWS Config: ~$2-3/month for 9 rules + recorder
- CloudTrail: ~$2/month for management events
- S3 storage: <$1/month (minimal data)

**Total estimated cost: ~$5-7/month**

## Troubleshooting

### Config Recorder Not Starting

If the Config recorder fails to start:

```bash
# Check recorder status
aws configservice describe-configuration-recorder-status --region us-east-1

# Manually start the recorder
aws configservice start-configuration-recorder \
  --configuration-recorder-name grc-guardian-recorder \
  --region us-east-1
```

### S3 Bucket Policy Errors

If the public bucket policy fails to apply, ensure:
1. Block public access settings allow policies with Principal="*"
2. The `depends_on` is correctly set for the public access block

### Config Rules Not Evaluating

AWS Config requires discovery time. Wait at least 10 minutes, then:

```bash
# Trigger manual evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names s3-bucket-public-read-prohibited \
  --region us-east-1
```

## Next Steps

1. Wait for Config evaluation to complete
2. Run the GRC Guardian API service
3. Trigger a compliance scan via the API
4. Review generated evidence artifacts
5. Examine compliance reports

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Account (us-east-1)                  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ AWS Config                                              │ │
│  │ - Recorder: grc-guardian-recorder                      │ │
│  │ - Rules: 9 managed rules                               │ │
│  │ - S3 Bucket: grc-guardian-config-<account-id>          │ │
│  └─────────────────┬──────────────────────────────────────┘ │
│                    │ Evaluates compliance                   │
│                    ▼                                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ S3 Buckets (Test Targets)                              │ │
│  │ - org-prod-logs-private (✅ COMPLIANT)                 │ │
│  │ - org-dev-backups-encrypted (✅ COMPLIANT)             │ │
│  │ - org-prod-assets-public (❌ NONCOMPLIANT)             │ │
│  │ - org-dev-data-unencrypted (❌ NONCOMPLIANT)           │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ IAM Resources                                           │ │
│  │ - Users: dev-no-mfa, old-access-key-user               │ │
│  │ - Role: GuardianAuditAgentReadOnly (read-only)         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CloudTrail                                              │ │
│  │ - Trail: grc-guardian-trail                            │ │
│  │ - S3 Bucket: grc-guardian-cloudtrail-logs-<acct-id>    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ GRC Guardian Agent queries via
                           │ GuardianAuditAgentReadOnly role
                           ▼
              ┌─────────────────────────┐
              │  GRC Guardian Agent     │
              │  (External System)      │
              └─────────────────────────┘
```

## Security Notes

- The `GuardianAuditAgentReadOnly` role has NO write permissions
- All S3 buckets (except the intentionally public one) block public access
- CloudTrail logs all management events for audit purposes
- Access keys are output as sensitive values (use `terraform output -json` to retrieve)

## Support

For issues with this Terraform configuration, check:
1. [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
2. [AWS Config Documentation](https://docs.aws.amazon.com/config/)
3. [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
