# SOC 2 CC6.1: Logical and Physical Access Controls

## Control ID
CC6.1

## Framework
SOC 2 (Trust Services Criteria)

## Control Family
Common Criteria - Logical and Physical Access Controls

## Control Summary
The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives. This includes:
- Identifying and authenticating users
- Considering network segmentation
- Managing the identification, authentication, and authorization process
- Managing privileged access credentials and removing access when no longer authorized

## What GRC Guardian Checks

### AWS Config Rules Mapped
- `iam-user-mfa-enabled` - Multi-factor authentication required
- `root-account-mfa-enabled` - Root account has MFA
- `s3-bucket-public-read-prohibited` - Data not publicly accessible
- `s3-bucket-public-write-prohibited` - Write access restricted
- `iam-password-policy` - Strong password requirements enforced

### AWS Resources Evaluated
- IAM Users and authentication settings
- S3 Bucket access controls
- VPC security groups and NACLs
- KMS encryption keys

## Expected Evidence Fields
- `resource_type`: AWS::IAM::User, AWS::S3::Bucket
- `compliance_type`: COMPLIANT, NON_COMPLIANT
- `annotation`: Access control configuration details
- `timestamp`: Assessment timestamp

## Remediation Guidance
To achieve SOC 2 compliance:
1. Implement MFA for all user accounts
2. Enforce strong password policies (14+ chars, complexity)
3. Remove public access from all S3 buckets containing customer data
4. Implement network segmentation using VPCs and security groups
5. Review and document access provisioning/deprovisioning procedures
6. Conduct quarterly access reviews

## Trust Service Principle
**Security Principle**: The system is protected against unauthorized access (both physical and logical).

This control is foundational for SOC 2 Type II audits and must demonstrate:
- Controls are suitably designed
- Controls operated effectively throughout the audit period

## References
- AICPA Trust Services Criteria: CC6.1
- AWS SOC 2 Compliance: https://aws.amazon.com/compliance/soc-2-audits/
- SOC 2 Security Trust Services Category

## Keywords
SOC2, logical access, physical access, authentication, authorization, MFA, access controls, identity management, trust services, security principle
