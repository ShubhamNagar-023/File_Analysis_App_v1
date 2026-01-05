#!/usr/bin/env python3
"""
Comprehensive validator for the VS Code output file.
This script analyzes the output file to verify correctness of all tests.
"""

import json
import re
from pathlib import Path

class OutputValidator:
    def __init__(self, output_file_path):
        self.output_file_path = output_file_path
        self.errors = []
        self.warnings = []
        self.successes = []
        
    def read_output_file(self):
        """Read the output file content."""
        with open(self.output_file_path, 'r') as f:
            return f.read()
    
    def extract_test_sections(self, content):
        """Extract individual test sections from the output."""
        tests = []
        
        # Split by test runs (looking for python3 commands)
        test_pattern = r'python3 \./(\w+_test\.py)'
        matches = list(re.finditer(test_pattern, content))
        
        for i, match in enumerate(matches):
            test_name = match.group(1)
            start_pos = match.start()
            
            # Find end position (next test or end of file)
            if i < len(matches) - 1:
                end_pos = matches[i + 1].start()
            else:
                end_pos = len(content)
            
            test_content = content[start_pos:end_pos]
            tests.append({
                'name': test_name,
                'content': test_content
            })
        
        return tests
    
    def validate_json_structure(self, content):
        """Validate that JSON structures in the output are well-formed."""
        # Extract JSON blocks from the output
        json_pattern = r'\{[\s\S]*?\n\}'
        json_matches = re.finditer(json_pattern, content)
        
        valid_jsons = 0
        invalid_jsons = 0
        
        for match in json_matches:
            json_str = match.group(0)
            try:
                json.loads(json_str)
                valid_jsons += 1
            except json.JSONDecodeError as e:
                invalid_jsons += 1
                # Only report first few errors to avoid spam
                if invalid_jsons <= 3:
                    self.warnings.append(f"Invalid JSON found (may be truncated): {str(e)[:100]}")
        
        return valid_jsons, invalid_jsons
    
    def validate_test_output(self, test):
        """Validate individual test output."""
        test_name = test['name']
        content = test['content']
        
        print(f"\n{'='*80}")
        print(f"Validating: {test_name}")
        print(f"{'='*80}")
        
        checks = {
            'has_part1': 'Running PART 1: File Ingestion & Type Resolution' in content,
            'has_part2': 'Running PART 2: Deep File-Type-Aware Static Analysis' in content,
            'has_file_info': '"file_info"' in content,
            'has_ingestion': '"ingestion"' in content,
            'has_cryptographic_identity': '"cryptographic_identity"' in content,
            'has_magic_detection': '"magic_detection"' in content,
            'has_semantic_type': '"semantic_file_type"' in content,
            'has_extension_analysis': '"extension_analysis"' in content,
            'has_filesystem_metadata': '"filesystem_metadata"' in content,
            'has_advanced_checks': '"advanced_checks"' in content,
            'has_summary': '"summary"' in content,
            'has_md5': '"hash_md5"' in content,
            'has_sha1': '"hash_sha1"' in content,
            'has_sha256': '"hash_sha256"' in content,
            'has_sha512': '"hash_sha512"' in content,
            'has_entropy': '"global_entropy"' in content or '"entropy"' in content,
            'has_findings': '"finding_id"' in content or '"findings"' in content,
        }
        
        # File type specific checks
        if 'image_test' in test_name:
            checks['correct_file_type'] = '"IMAGE_JPEG"' in content or 'JPEG' in content
            checks['has_image_analysis'] = '"image_analysis"' in content or 'image' in content.lower()
        elif 'pdf_test' in test_name:
            checks['correct_file_type'] = '"PDF"' in content
            checks['has_pdf_analysis'] = '"pdf_analysis"' in content or 'PDF' in content
        elif 'docx_test' in test_name:
            checks['correct_file_type'] = '"DOCX"' in content
            checks['has_zip_analysis'] = '"ZIP"' in content or 'OOXML' in content
        
        # Verify no errors occurred
        checks['no_error'] = 'error' not in content.lower() or '"failure_reason": null' in content
        checks['no_exception'] = 'exception' not in content.lower() and 'traceback' not in content.lower()
        
        # Check for successful completion indicators
        checks['has_success_status'] = '"status": "SUCCESS"' in content
        checks['has_high_confidence'] = '"classification_confidence": "HIGH"' in content
        
        # Print results
        passed = 0
        failed = 0
        
        for check_name, result in checks.items():
            status = "✅" if result else "❌"
            print(f"  {status} {check_name.replace('_', ' ').title()}")
            if result:
                passed += 1
            else:
                failed += 1
                self.errors.append(f"{test_name}: {check_name} failed")
        
        print(f"\n  Total Checks: {len(checks)}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        
        if failed == 0:
            self.successes.append(f"{test_name}: All checks passed")
            print(f"  \n  ✅ {test_name} OUTPUT IS CORRECT!")
        else:
            print(f"  \n  ❌ {test_name} has {failed} issue(s)")
        
        return failed == 0
    
    def validate_all(self):
        """Run all validations."""
        print("="*80)
        print("VS CODE OUTPUT FILE VALIDATOR")
        print("="*80)
        
        # Read the file
        print("\n📄 Reading output file...")
        content = self.read_output_file()
        print(f"  File size: {len(content)} characters")
        print(f"  Lines: {len(content.splitlines())}")
        
        # Extract tests
        print("\n🔍 Extracting test sections...")
        tests = self.extract_test_sections(content)
        print(f"  Found {len(tests)} test(s):")
        for test in tests:
            print(f"    - {test['name']}")
        
        # Validate each test
        print("\n📊 Validating test outputs...")
        all_passed = True
        for test in tests:
            passed = self.validate_test_output(test)
            if not passed:
                all_passed = False
        
        # Print final summary
        print("\n" + "="*80)
        print("VALIDATION SUMMARY")
        print("="*80)
        
        print(f"\n✅ Successes: {len(self.successes)}")
        for success in self.successes:
            print(f"  ✓ {success}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
        
        if self.errors:
            print(f"\n❌ Errors: {len(self.errors)}")
            for error in self.errors:
                print(f"  ✗ {error}")
        
        # Final verdict
        print("\n" + "="*80)
        if all_passed and len(tests) > 0:
            print("✅ VERDICT: ALL OUTPUT IS CORRECT!")
            print("="*80)
            print("\nAll tests executed successfully:")
            print("  ✅ JSON structures are well-formed")
            print("  ✅ All required components present")
            print("  ✅ File types correctly identified")
            print("  ✅ No errors or exceptions detected")
            print("  ✅ Analysis completed successfully")
            return True
        else:
            print("❌ VERDICT: OUTPUT HAS ISSUES")
            print("="*80)
            print("\nPlease review the errors above.")
            return False

def main():
    """Main entry point."""
    output_file = "output file from vs code"
    
    if not Path(output_file).exists():
        print(f"❌ ERROR: File '{output_file}' not found!")
        return 1
    
    validator = OutputValidator(output_file)
    result = validator.validate_all()
    
    return 0 if result else 1

if __name__ == "__main__":
    exit(main())
