# =============================================================================
# Terraform Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# S3 Bucket Names
# -----------------------------------------------------------------------------
output "s3_bucket_prod_logs_private" {
  description = "Name of the compliant production logs bucket"
  value       = aws_s3_bucket.prod_logs_private.id
}

output "s3_bucket_dev_backups_encrypted" {
  description = "Name of the compliant dev backups bucket"
  value       = aws_s3_bucket.dev_backups_encrypted.id
}

output "s3_bucket_prod_assets_public" {
  description = "Name of the non-compliant public assets bucket"
  value       = aws_s3_bucket.prod_assets_public.id
}

output "s3_bucket_dev_data_unencrypted" {
  description = "Name of the non-compliant unencrypted data bucket"
  value       = aws_s3_bucket.dev_data_unencrypted.id
}

output "s3_buckets_summary" {
  description = "Summary of all simulated S3 buckets"
  value = {
    compliant = [
      aws_s3_bucket.prod_logs_private.id,
      aws_s3_bucket.dev_backups_encrypted.id
    ]
    non_compliant = [
      aws_s3_bucket.prod_assets_public.id,
      aws_s3_bucket.dev_data_unencrypted.id
    ]
  }
}

# -----------------------------------------------------------------------------
# IAM Role ARN
# -----------------------------------------------------------------------------
output "guardian_audit_agent_role_arn" {
  description = "ARN of the GuardianAuditAgentReadOnly IAM role"
  value       = aws_iam_role.guardian_audit_agent.arn
}

output "guardian_audit_agent_role_name" {
  description = "Name of the GuardianAuditAgentReadOnly IAM role"
  value       = aws_iam_role.guardian_audit_agent.name
}

# -----------------------------------------------------------------------------
# IAM Users
# -----------------------------------------------------------------------------
output "iam_user_dev_no_mfa" {
  description = "IAM user without MFA (non-compliant)"
  value       = aws_iam_user.dev_no_mfa.name
}

output "iam_user_old_access_key" {
  description = "IAM user with access key (non-compliant)"
  value       = aws_iam_user.old_access_key_user.name
}

output "old_access_key_id" {
  description = "Access key ID for old-access-key-user (SENSITIVE - for testing only)"
  value       = aws_iam_access_key.old_access_key.id
  sensitive   = true
}

output "old_access_key_secret" {
  description = "Secret access key for old-access-key-user (SENSITIVE - for testing only)"
  value       = aws_iam_access_key.old_access_key.secret
  sensitive   = true
}

# -----------------------------------------------------------------------------
# CloudTrail
# -----------------------------------------------------------------------------
output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

# -----------------------------------------------------------------------------
# AWS Config
# -----------------------------------------------------------------------------
output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "config_s3_bucket" {
  description = "S3 bucket for AWS Config snapshots"
  value       = aws_s3_bucket.config.id
}

output "config_rule_names" {
  description = "List of all AWS Config rule names"
  value = [
    aws_config_config_rule.s3_bucket_public_read_prohibited.name,
    aws_config_config_rule.s3_bucket_public_write_prohibited.name,
    aws_config_config_rule.s3_bucket_server_side_encryption_enabled.name,
    aws_config_config_rule.s3_bucket_versioning_enabled.name,
    aws_config_config_rule.root_account_mfa_enabled.name,
    aws_config_config_rule.iam_user_mfa_enabled.name,
    aws_config_config_rule.access_keys_rotated.name,
    aws_config_config_rule.iam_password_policy.name,
    aws_config_config_rule.cloudtrail_enabled.name
  ]
}

# -----------------------------------------------------------------------------
# Summary Information
# -----------------------------------------------------------------------------
output "deployment_summary" {
  description = "Summary of the GRC Guardian lab deployment"
  value = {
    aws_account_id = data.aws_caller_identity.current.account_id
    aws_region     = data.aws_region.current.name
    s3_buckets = {
      compliant_count     = 2
      non_compliant_count = 2
      total               = 4
    }
    config_rules_count = 9
    iam_users_count    = 2
    cloudtrail_enabled = true
    config_enabled     = true
  }
}

output "next_steps" {
  description = "Instructions for next steps after deployment"
  value = <<-EOT

    ✅ GRC Guardian Lab Environment Deployed Successfully!

    Next Steps:
    1. Wait 5-10 minutes for AWS Config to evaluate all resources
    2. Check Config compliance: aws configservice describe-compliance-by-config-rule
    3. Use the GuardianAuditAgentReadOnly role ARN for agent authentication
    4. Test S3 compliance scanning on the 4 buckets
    5. Verify IAM user compliance checks (MFA, access key rotation)

    Important Resources:
    - Guardian Agent Role ARN: ${aws_iam_role.guardian_audit_agent.arn}
    - Config Recorder: ${aws_config_configuration_recorder.main.name}
    - CloudTrail: ${aws_cloudtrail.main.name}

    Non-Compliant Resources (Expected):
    - ${aws_s3_bucket.prod_assets_public.id} (public access)
    - ${aws_s3_bucket.dev_data_unencrypted.id} (no encryption/versioning)
    - ${aws_iam_user.dev_no_mfa.name} (no MFA)
    - ${aws_iam_user.old_access_key_user.name} (access key not rotated)

  EOT
}
