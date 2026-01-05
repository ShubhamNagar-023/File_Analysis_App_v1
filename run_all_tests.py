#!/usr/bin/env python3
"""
Comprehensive test runner for all file analysis test scripts.
This script runs all test files and validates their outputs.
"""

import subprocess
import sys
import json
from pathlib import Path

# Define test configurations
TESTS = [
    {
        "name": "Text File Test",
        "script": "text_test.py",
        "file": "test_files/sample.txt",
        "expected_type": "TEXT"
    },
    {
        "name": "DOCX File Test",
        "script": "docx_test.py",
        "file": "test_files/sample.docx",
        "expected_type": "DOCX"
    },
    {
        "name": "PDF File Test",
        "script": "pdf_test.py",
        "file": "test_files/sample.pdf",
        "expected_type": "PDF"
    },
    {
        "name": "Image File Test",
        "script": "image_test.py",
        "file": "test_files/sample.jpg",
        "expected_type": "IMAGE_JPEG"
    }
]

def run_test(test_config):
    """Run a single test and validate output."""
    print(f"\n{'='*80}")
    print(f"Running: {test_config['name']}")
    print(f"Script: {test_config['script']}")
    print(f"File: {test_config['file']}")
    print(f"{'='*80}")
    
    try:
        # Run the test script
        result = subprocess.run(
            ["python3", test_config["script"], test_config["file"]],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"❌ FAILED - Exit code: {result.returncode}")
            print(f"STDERR: {result.stderr}")
            return False
        
        # Check if output contains expected file type
        output = result.stdout
        if test_config["expected_type"] in output:
            print(f"✅ PASSED - File type '{test_config['expected_type']}' detected correctly")
            
            # Check for key components in output
            checks = {
                "PART 1": "Running PART 1" in output,
                "PART 2": "Running PART 2" in output,
                "PART 3": "Running PART 3" in output,
                "File Ingestion": "secure_file_ingestion" in output,
                "Cryptographic Identity": "cryptographic_identity" in output,
                "Magic Detection": "magic_detection" in output,
                "Entropy Analysis": "global_entropy" in output,
                "Risk Scoring": "risk_score" in output,
                "Analysis Complete": "ANALYSIS COMPLETE - ALL THREE PARTS" in output
            }
            
            print("\nComponent Checks:")
            for check_name, passed in checks.items():
                status = "✅" if passed else "❌"
                print(f"  {status} {check_name}")
            
            all_passed = all(checks.values())
            return all_passed
        else:
            print(f"❌ FAILED - Expected file type '{test_config['expected_type']}' not found in output")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ FAILED - Test timed out")
        return False
    except Exception as e:
        print(f"❌ FAILED - Exception: {e}")
        return False

def main():
    """Run all tests and report results."""
    print("="*80)
    print("FILE ANALYSIS APPLICATION - COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    # Check if test files exist
    print("\nChecking test files...")
    all_files_exist = True
    for test in TESTS:
        file_path = Path(test["file"])
        exists = file_path.exists()
        status = "✅" if exists else "❌"
        print(f"  {status} {test['file']}")
        if not exists:
            all_files_exist = False
    
    if not all_files_exist:
        print("\n❌ ERROR: Some test files are missing!")
        print("Please run the test file creation script first.")
        return 1
    
    # Run all tests
    results = []
    for test in TESTS:
        passed = run_test(test)
        results.append({
            "test": test["name"],
            "passed": passed
        })
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r["passed"])
    failed_tests = total_tests - passed_tests
    
    for result in results:
        status = "✅ PASS" if result["passed"] else "❌ FAIL"
        print(f"{status} - {result['test']}")
    
    print(f"\nTotal: {total_tests} tests")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    
    if failed_tests == 0:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        return 0
    else:
        print(f"\n⚠️  {failed_tests} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
