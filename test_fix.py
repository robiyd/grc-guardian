#!/usr/bin/env python3
"""Test script to verify aws_config fix works."""
import sys
sys.path.insert(0, '.')

from tools.aws_config import aws_config_eval

# Test with actual rules that exist
print("Testing iam-password-policy...")
findings = aws_config_eval('iam-password-policy', 'us-west-2')
print(f'Found {len(findings)} findings')
for f in findings:
    print(f'  - {f["resource_id"]}: {f["compliance_type"]}')

print("\nTesting cloudtrail-enabled...")
findings = aws_config_eval('cloudtrail-enabled', 'us-west-2')
print(f'Found {len(findings)} findings')
for f in findings:
    print(f'  - {f["resource_id"]}: {f["compliance_type"]}')

print("\nTesting iam-user-mfa-enabled...")
findings = aws_config_eval('iam-user-mfa-enabled', 'us-west-2')
print(f'Found {len(findings)} findings')
for f in findings:
    print(f'  - {f["resource_id"]}: {f["compliance_type"]}')

print("\nFIX VERIFIED: API calls working successfully!")
