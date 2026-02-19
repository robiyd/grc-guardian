#!/usr/bin/env python3
"""Quick test to verify the system works."""

import sys
sys.path.insert(0, ".")

from agent.orchestrator import build_and_execute_plan

print("Testing GRC Guardian with 3 different prompts...")
print("=" * 80)

# Test 1: Simple S3 check
print("\n1. Testing: 'Check S3 security'")
result1 = build_and_execute_plan("Check S3 security", env="prod", region="us-west-2")
findings1 = result1.get("execution", {}).get("all_findings", [])
print(f"   Result: {len(findings1)} findings")

# Test 2: Simple IAM check
print("\n2. Testing: 'Check IAM users'")
result2 = build_and_execute_plan("Check IAM users", env="prod", region="us-west-2")
findings2 = result2.get("execution", {}).get("all_findings", [])
print(f"   Result: {len(findings2)} findings")

# Test 3: Generic scan
print("\n3. Testing: 'Run compliance scan'")
result3 = build_and_execute_plan("Run compliance scan", env="prod", region="us-west-2")
findings3 = result3.get("execution", {}).get("all_findings", [])
print(f"   Result: {len(findings3)} findings")

# Test 4: Prompt injection attempt
print("\n4. Testing prompt injection: 'Check S3; DROP TABLE --'")
result4 = build_and_execute_plan("Check S3; DROP TABLE config_rules; --", env="prod", region="us-west-2")
findings4 = result4.get("execution", {}).get("all_findings", [])
print(f"   Result: {len(findings4)} findings")

print("\n" + "=" * 80)
print("SUMMARY:")
print(f"  Test 1: {len(findings1)} findings ({'PASS' if len(findings1) > 0 else 'FAIL'})")
print(f"  Test 2: {len(findings2)} findings ({'PASS' if len(findings2) > 0 else 'FAIL'})")
print(f"  Test 3: {len(findings3)} findings ({'PASS' if len(findings3) > 0 else 'FAIL'})")
print(f"  Test 4: {len(findings4)} findings ({'PASS' if len(findings4) > 0 else 'FAIL'})")

all_passed = all(len(f) > 0 for f in [findings1, findings2, findings3, findings4])
print(f"\n{'[SUCCESS]' if all_passed else '[FAIL]'} All tests {'passed' if all_passed else 'had issues'}")
