#!/usr/bin/env python3
"""Test the API endpoint with various prompts."""

import requests
import time

BASE_URL = "http://localhost:8000"

def test_scan(prompt_name, prompt):
    """Test a single scan via API."""
    print(f"\nTesting: {prompt_name}")
    print(f"Prompt: '{prompt}'")

    response = requests.post(
        f"{BASE_URL}/api/v1/ask",
        headers={"X-API-Key": "dev-key-change-in-production"},
        json={
            "prompt": prompt,
            "env": "prod",
            "region": "us-west-2",
        },
    )

    if response.status_code == 200:
        data = response.json()
        run_id = data.get("run_id")
        print(f"Run ID: {run_id}")
        print(f"Summary: {data.get('summary', 'N/A')}")

        # Check findings
        findings = data.get("findings", [])
        print(f"Findings: {len(findings)} total")
        return len(findings) > 0
    else:
        print(f"ERROR: Scan failed with status {response.status_code}")
        print(response.text)
        return False

def main():
    """Run API tests."""
    print("=" * 80)
    print("GRC GUARDIAN API ENDPOINT TEST")
    print("=" * 80)

    # Wait for server to be ready
    print("\nWaiting for API server to be ready...")
    for i in range(10):
        try:
            response = requests.get(f"{BASE_URL}/")
            if response.status_code == 200:
                print("API server is ready!")
                break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    else:
        print("ERROR: API server not responding")
        return 1

    # Run tests
    tests = [
        ("Normal S3 Check", "Check S3 security"),
        ("Vague Prompt", "audit"),
        ("Prompt Injection", "Check IAM; DROP TABLE users; --"),
    ]

    results = []
    for name, prompt in tests:
        success = test_scan(name, prompt)
        results.append((name, success))
        time.sleep(2)  # Avoid rate limiting

    # Summary
    print("\n" + "=" * 80)
    print("API TEST SUMMARY")
    print("=" * 80)
    passed = sum(1 for _, success in results if success)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {len(tests) - passed}")

    for name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"  {status} {name}")

    if passed == len(tests):
        print("\n[SUCCESS] All API tests passed!")
        return 0
    else:
        print(f"\n[FAIL] {len(tests) - passed} tests failed")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
