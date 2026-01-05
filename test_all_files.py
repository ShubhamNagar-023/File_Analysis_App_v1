#!/usr/bin/env python3
"""
Test All Files - Analyze all test files and export results

This script:
1. Finds all files in test_files/ directory
2. Runs complete analysis on each file
3. Exports results in all three formats (JSON, HTML, PDF)
4. Organizes exports in test_output/ directory

Usage:
    python test_all_files.py
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat


def print_banner(text, char="="):
    """Print a formatted banner"""
    print("\n" + char * 80)
    print(text)
    print(char * 80)


def analyze_and_export(file_path: Path, export_dir: Path):
    """
    Analyze a single file and export to all formats.
    Uses a separate database for each file to avoid ID conflicts.
    
    Args:
        file_path: Path to file to analyze
        export_dir: Directory for exports
    
    Returns:
        Tuple of (success: bool, error_message: str or None)
    """
    try:
        print(f"\n📄 Analyzing: {file_path.name}")
        print(f"   Size: {file_path.stat().st_size:,} bytes")
        
        # Run PART 1
        part1 = analyze_file(str(file_path))
        semantic_type = part1.get('summary', {}).get('semantic_file_type', 'UNKNOWN')
        
        # Run PART 2
        part2 = deep_analyze_file(str(file_path), part1)
        total_findings = part2.get('summary', {}).get('total_findings', 0)
        
        # Run PART 3
        part3 = analyze_part3(str(file_path), part1, part2)
        risk_score = part3.get('risk_score', {}).get('normalized_score', 0)
        severity = part3.get('risk_score', {}).get('severity', 'unknown')
        
        print(f"   Type: {semantic_type}")
        print(f"   Findings: {total_findings}")
        print(f"   Risk: {risk_score:.1f}/100 ({severity.upper()})")
        
        # Create export subdirectory for this file
        base_filename = file_path.stem
        file_export_dir = export_dir / base_filename
        file_export_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a separate database for this file
        db_path = file_export_dir / f"{base_filename}_analysis.db"
        db = AnalysisDatabase(str(db_path))
        
        # Create case and session for this file
        case_id = db.create_case(
            name=f"Analysis of {file_path.name}",
            description=f"Analysis of {semantic_type} file",
            metadata={
                "analyst": "automated",
                "file_type": semantic_type,
                "original_path": str(file_path)
            }
        )
        
        session_id = db.create_session(
            case_id=case_id,
            name=f"Session for {file_path.name}",
            description=f"Analysis session for {file_path.name}"
        )
        
        # Store in database
        record_id = db.import_analysis(
            session_id=session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3,
        )
        
        # Export to all formats
        exporter = Exporter(db)
        
        # Export JSON
        json_path = file_export_dir / f"{base_filename}_analysis.json"
        exported_json = exporter.export_record(record_id, str(json_path), ExportFormat.JSON)
        
        # Export HTML
        html_path = file_export_dir / f"{base_filename}_analysis.html"
        exported_html = exporter.export_record(record_id, str(html_path), ExportFormat.HTML)
        
        # Export PDF
        pdf_path = file_export_dir / f"{base_filename}_analysis.pdf"
        exported_pdf = exporter.export_record(record_id, str(pdf_path), ExportFormat.PDF)
        
        # Close database
        db.close()
        
        print(f"   ✅ Exported:")
        print(f"      JSON: {Path(exported_json).stat().st_size:,} bytes")
        print(f"      HTML: {Path(exported_html).stat().st_size:,} bytes")
        print(f"      PDF:  {Path(exported_pdf).stat().st_size:,} bytes")
        
        return True, None
        
    except Exception as e:
        error_msg = f"Error analyzing {file_path.name}: {str(e)}"
        print(f"   ❌ {error_msg}")
        import traceback
        traceback.print_exc()
        
        return False, error_msg


def main():
    """Main entry point"""
    print_banner("TEST ALL FILES - COMPREHENSIVE ANALYSIS", "=")
    
    # Setup paths
    test_files_dir = Path("test_files")
    test_output_dir = Path("test_output")
    
    # Validate test files directory exists
    if not test_files_dir.exists():
        print(f"❌ Error: Test files directory not found: {test_files_dir}")
        sys.exit(1)
    
    # Create test output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = test_output_dir / timestamp
    export_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n📁 Test Files Directory: {test_files_dir.absolute()}")
    print(f"📁 Export Directory: {export_dir.absolute()}")
    
    # Find all test files
    test_files = sorted([
        f for f in test_files_dir.iterdir()
        if f.is_file() and not f.name.startswith('.')
    ])
    
    if not test_files:
        print(f"\n❌ No test files found in {test_files_dir}")
        sys.exit(1)
    
    print(f"\n📊 Found {len(test_files)} test files to analyze")
    
    # Analyze each file
    print_banner("ANALYZING FILES", "-")
    
    success_count = 0
    failure_count = 0
    errors = []
    
    for i, file_path in enumerate(test_files, 1):
        print(f"\n[{i}/{len(test_files)}]", end=" ")
        
        success, error_msg = analyze_and_export(file_path, export_dir)
        
        if success:
            success_count += 1
        else:
            failure_count += 1
            errors.append((file_path.name, error_msg))
    
    # Generate summary
    print_banner("ANALYSIS COMPLETE", "=")
    
    print(f"\n📊 Summary:")
    print(f"   Total Files: {len(test_files)}")
    print(f"   ✅ Successful: {success_count}")
    print(f"   ❌ Failed: {failure_count}")
    
    if errors:
        print(f"\n⚠️  Errors:")
        for filename, error_msg in errors:
            print(f"   - {filename}: {error_msg}")
    
    print(f"\n📁 Results Location:")
    print(f"   {export_dir.absolute()}")
    
    # Create index file
    create_index_html(export_dir, test_files, success_count, failure_count, timestamp)
    
    print(f"\n🌐 Index File:")
    print(f"   {export_dir / 'index.html'}")
    
    print("\n" + "=" * 80)
    
    # Exit code
    if failure_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


def create_index_html(export_dir: Path, test_files: list, success_count: int, failure_count: int, timestamp: str):
    """Create an HTML index file listing all analyzed files"""
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Files Analysis - {timestamp}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 20px;
            line-height: 1.6;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin-right: 30px;
            font-size: 1.1em;
        }}
        .success {{ color: #28a745; }}
        .failure {{ color: #dc3545; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: #007bff;
            color: white;
            font-weight: 600;
        }}
        tr:nth-child(even) {{
            background: #f9f9f9;
        }}
        tr:hover {{
            background: #e9ecef;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
            margin-right: 10px;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-json {{ background: #ffc107; color: #000; }}
        .badge-html {{ background: #17a2b8; color: white; }}
        .badge-pdf {{ background: #dc3545; color: white; }}
        .timestamp {{
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Test Files Analysis Report</h1>
        
        <div class="summary">
            <div class="summary-item">
                <strong>Total Files:</strong> {len(test_files)}
            </div>
            <div class="summary-item success">
                <strong>✅ Successful:</strong> {success_count}
            </div>
            <div class="summary-item failure">
                <strong>❌ Failed:</strong> {failure_count}
            </div>
            <div class="summary-item timestamp">
                <strong>Generated:</strong> {timestamp}
            </div>
        </div>
        
        <h2>📂 Analyzed Files</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>File Name</th>
                    <th>Export Formats</th>
                </tr>
            </thead>
            <tbody>
"""
    
    # Add table rows for each file
    for i, file_path in enumerate(test_files, 1):
        base_filename = file_path.stem
        file_export_dir = export_dir / base_filename
        
        # Check if exports exist
        json_exists = (file_export_dir / f"{base_filename}_analysis.json").exists()
        html_exists = (file_export_dir / f"{base_filename}_analysis.html").exists()
        pdf_exists = (file_export_dir / f"{base_filename}_analysis.pdf").exists()
        
        html_content += f"""
                <tr>
                    <td>{i}</td>
                    <td><strong>{file_path.name}</strong></td>
                    <td>
"""
        
        if json_exists:
            html_content += f'                        <a href="{base_filename}/{base_filename}_analysis.json" class="badge badge-json">JSON</a>\n'
        if html_exists:
            html_content += f'                        <a href="{base_filename}/{base_filename}_analysis.html" class="badge badge-html">HTML</a>\n'
        if pdf_exists:
            html_content += f'                        <a href="{base_filename}/{base_filename}_analysis.pdf" class="badge badge-pdf">PDF</a>\n'
        
        if not (json_exists or html_exists or pdf_exists):
            html_content += '                        <span style="color: #dc3545;">❌ Failed</span>\n'
        
        html_content += """                    </td>
                </tr>
"""
    
    html_content += """            </tbody>
        </table>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #6c757d;">
            <p>Generated by File Analysis Application</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write index file
    index_path = export_dir / "index.html"
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


if __name__ == "__main__":
    main()
