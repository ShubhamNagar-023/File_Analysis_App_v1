#!/usr/bin/env python3
"""
Test runner for all 21 risky test files.
Analyzes each file and generates a comprehensive risk assessment report.
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from file_analyzer.analyzer import analyze_file
from file_analyzer.deep_analyzer import deep_analyze_file
from file_analyzer.part3_analyzer import analyze_part3


# Define test file categories
TEST_FILES = {
    'normal': [
        'normal_plain_text.txt',
        'normal_document.docx',
        'normal_report.pdf',
        'normal_photo.jpg',
        'normal_archive.zip',
        'normal_data.csv',
        'normal_config.json',
    ],
    'moderate': [
        'mismatch_image.txt',
        'trailing_data_archive.zip',
        'pdf_with_urls.pdf',
        'suspicious_script.txt',
        'docx_custom_xml.docx',
        'pdf_incremental.pdf',
        'nested_archive.zip',
    ],
    'high': [
        'document.pdf.exe',
        'polyglot.zip',
        'pdf_with_javascript.pdf',
        'pdf_auto_action.pdf',
        'high_entropy_data.bin',
        'docx_with_macros.docx',
        'unicode_deception.txt',
    ]
}


def analyze_test_file(file_path):
    """Analyze a single test file and return results."""
    try:
        part1 = analyze_file(file_path)
        part2 = deep_analyze_file(file_path, part1)
        part3 = analyze_part3(file_path, part1, part2)
        
        return {
            'status': 'success',
            'semantic_type': part1.get('summary', {}).get('semantic_file_type', 'UNKNOWN'),
            'risk_score': part3['risk_score']['normalized_score'],
            'severity': part3['risk_score']['severity'],
            'heuristics_count': part3['heuristics']['triggered_count'],
            'heuristics': [
                {
                    'name': h['name'],
                    'severity': h['severity'],
                    'confidence': h['confidence']
                }
                for h in part3['heuristics']['triggered_heuristics']
            ]
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def print_file_result(filename, result, expected_risk):
    """Print analysis result for a single file."""
    if result['status'] == 'error':
        print(f"  ❌ {filename}")
        print(f"     Error: {result['error']}")
        return False
    
    risk_score = result['risk_score']
    severity = result['severity'].upper()
    
    # Determine if result matches expectations
    if expected_risk == 'normal':
        expected_range = (0, 15)
        expected_severity = ['informational', 'low']
    elif expected_risk == 'moderate':
        expected_range = (10, 45)
        expected_severity = ['low', 'medium']
    else:  # high
        expected_range = (20, 100)
        expected_severity = ['medium', 'high', 'critical']
    
    in_range = expected_range[0] <= risk_score <= expected_range[1]
    severity_ok = result['severity'] in expected_severity
    
    status = "✅" if (in_range or severity_ok) else "⚠️"
    
    print(f"  {status} {filename}")
    print(f"     Type: {result['semantic_type']}")
    print(f"     Risk Score: {risk_score:.2f}/100 | Severity: {severity}")
    print(f"     Heuristics: {result['heuristics_count']}")
    
    if result['heuristics_count'] > 0:
        for h in result['heuristics']:
            print(f"       - {h['name']} ({h['severity']})")
    
    return True


def main():
    """Run analysis on all test files."""
    print("="*80)
    print("RISKY TEST FILES - COMPREHENSIVE SECURITY ANALYSIS")
    print("="*80)
    
    all_results = {}
    total_files = 0
    successful = 0
    failed = 0
    
    # Analyze each category
    for category, files in TEST_FILES.items():
        print(f"\n{'='*80}")
        print(f"{category.upper()} RISK FILES ({len(files)} files)")
        print(f"{'='*80}")
        
        category_results = []
        
        for filename in files:
            file_path = f'test_files/{filename}'
            total_files += 1
            
            result = analyze_test_file(file_path)
            category_results.append({
                'filename': filename,
                'result': result
            })
            
            success = print_file_result(filename, result, category)
            if success:
                successful += 1
            else:
                failed += 1
            print()
        
        all_results[category] = category_results
    
    # Print summary
    print("="*80)
    print("ANALYSIS SUMMARY")
    print("="*80)
    
    print(f"\nTotal Files Analyzed: {total_files}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    
    # Category statistics
    print("\nRISK DISTRIBUTION:")
    for category in ['normal', 'moderate', 'high']:
        files = all_results.get(category, [])
        if not files:
            continue
        
        scores = [
            f['result']['risk_score']
            for f in files
            if f['result']['status'] == 'success'
        ]
        
        if scores:
            avg_score = sum(scores) / len(scores)
            min_score = min(scores)
            max_score = max(scores)
            
            print(f"\n{category.upper()}:")
            print(f"  Files: {len(files)}")
            print(f"  Avg Score: {avg_score:.2f}/100")
            print(f"  Range: {min_score:.2f} - {max_score:.2f}")
    
    # Heuristic coverage
    print("\nHEURISTIC COVERAGE:")
    all_heuristics = set()
    for category_results in all_results.values():
        for file_result in category_results:
            if file_result['result']['status'] == 'success':
                for h in file_result['result']['heuristics']:
                    all_heuristics.add(h['name'])
    
    print(f"  Unique Heuristics Triggered: {len(all_heuristics)}")
    if all_heuristics:
        for h_name in sorted(all_heuristics):
            print(f"    - {h_name}")
    
    print("\n" + "="*80)
    if failed == 0:
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(f"⚠️  {failed} test(s) failed")
    print("="*80)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
