# =============================================================================
# IAM Users and Roles
# =============================================================================

# -----------------------------------------------------------------------------
# IAM User: dev-no-mfa (NONCOMPLIANT - no MFA enabled)
# -----------------------------------------------------------------------------
resource "aws_iam_user" "dev_no_mfa" {
  name = "dev-no-mfa"

  tags = {
    Name        = "dev-no-mfa"
    Environment = "dev"
    Compliance  = "NONCOMPLIANT"
    Description = "Test user without MFA for compliance testing"
  }
}

resource "aws_iam_user_policy_attachment" "dev_no_mfa_readonly" {
  user       = aws_iam_user.dev_no_mfa.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# -----------------------------------------------------------------------------
# IAM User: old-access-key-user (NONCOMPLIANT - access key not rotated)
# -----------------------------------------------------------------------------
resource "aws_iam_user" "old_access_key_user" {
  name = "old-access-key-user"

  tags = {
    Name        = "old-access-key-user"
    Environment = "dev"
    Compliance  = "NONCOMPLIANT"
    Description = "Test user with access key for rotation testing"
  }
}

resource "aws_iam_access_key" "old_access_key" {
  user = aws_iam_user.old_access_key_user.name
}

resource "aws_iam_user_policy_attachment" "old_access_key_user_readonly" {
  user       = aws_iam_user.old_access_key_user.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# -----------------------------------------------------------------------------
# IAM Role: GuardianAuditAgentReadOnly
# Least-privilege READ ONLY access for the compliance agent
# -----------------------------------------------------------------------------
resource "aws_iam_role" "guardian_audit_agent" {
  name        = "GuardianAuditAgentReadOnly"
  description = "Read-only role for GRC Guardian compliance scanning"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "GuardianAuditAgentReadOnly"
    Environment = "prod"
    Compliance  = "COMPLIANT"
    Description = "Read-only role for compliance agent"
  }
}

# Custom policy for least-privilege read access
resource "aws_iam_policy" "guardian_audit_readonly" {
  name        = "GuardianAuditReadOnlyPolicy"
  description = "Least-privilege read-only policy for GRC Guardian agent"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # AWS Config read access
      {
        Sid    = "ConfigReadAccess"
        Effect = "Allow"
        Action = [
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "config:BatchGet*",
          "config:SelectResourceConfig"
        ]
        Resource = "*"
      },
      # S3 read access for compliance checks
      {
        Sid    = "S3ReadAccess"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketAcl",
          "s3:GetBucketLogging",
          "s3:GetBucketTagging"
        ]
        Resource = "*"
      },
      # IAM read access
      {
        Sid    = "IAMReadAccess"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails"
        ]
        Resource = "*"
      },
      # CloudTrail read access
      {
        Sid    = "CloudTrailReadAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      # STS assume role (for cross-account if needed later)
      {
        Sid      = "STSAssumeRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/GuardianAuditAgentReadOnly"
      },
      # CloudWatch Logs read (for audit trails)
      {
        Sid    = "CloudWatchLogsReadAccess"
        Effect = "Allow"
        Action = [
          "logs:Describe*",
          "logs:Get*",
          "logs:List*",
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      },
      # EC2 read (for network config compliance)
      {
        Sid    = "EC2ReadAccess"
        Effect = "Allow"
        Action = [
          "ec2:Describe*"
        ]
        Resource = "*"
      },
      # Organizations read (for org structure)
      {
        Sid    = "OrganizationsReadAccess"
        Effect = "Allow"
        Action = [
          "organizations:Describe*",
          "organizations:List*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "GuardianAuditReadOnlyPolicy"
  }
}

resource "aws_iam_role_policy_attachment" "guardian_audit_agent_policy" {
  role       = aws_iam_role.guardian_audit_agent.name
  policy_arn = aws_iam_policy.guardian_audit_readonly.arn
}

# Attach AWS managed SecurityAudit policy (additional read-only permissions)
resource "aws_iam_role_policy_attachment" "guardian_audit_agent_security_audit" {
  role       = aws_iam_role.guardian_audit_agent.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
