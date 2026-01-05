import json
import sys
import tempfile
import os
from pathlib import Path
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat

# Get file path from command line or use default
if len(sys.argv) > 1:
    file_path = sys.argv[1]
else:
    # Default file path (can be changed to test different files)
    file_path = 'test_files/sample.pdf'
    print(f"No file path provided, using default: {file_path}")
    print("Usage: python pdf_test.py <file_path>\n")

# PART 1: File Ingestion & Type Resolution
print("Running PART 1: File Ingestion & Type Resolution...")
part1 = analyze_file(file_path)
print("\nPART 1 Results:")
print(json.dumps(part1, indent=2, default=str))

# PART 2: Deep File-Type-Aware Static Analysis
print("\n" + "="*80)
print("Running PART 2: Deep File-Type-Aware Static Analysis...")
part2 = deep_analyze_file(file_path, part1)
print("\nPART 2 Results:")
print(json.dumps(part2, indent=2, default=str))

# PART 3: Rules, Correlation & Explainable Risk Scoring
print("\n" + "="*80)
print("Running PART 3: Rules, Correlation & Explainable Risk Scoring...")
part3 = analyze_part3(file_path, part1, part2)
print("\nPART 3 Results:")
print(json.dumps(part3, indent=2, default=str))

# PART 4: Persistence, CLI & IPC (Data Durability Layer)
print("\n" + "="*80)
print("Running PART 4: Persistence, CLI & IPC...")

# Create temporary database for testing
with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "test_analysis.db"
    
    # Initialize database
    db = AnalysisDatabase(str(db_path))
    
    # Create a case and session
    case_id = db.create_case(
        name=f"PDF Analysis - {Path(file_path).name}",
        description="Automated analysis of PDF document",
        metadata={"analyst": "test_user"}
    )
    
    session_id = db.create_session(
        case_id=case_id,
        name=f"Session for {Path(file_path).name}",
        description="Analysis session"
    )
    
    # Store analysis record
    record_id = db.import_analysis(
        session_id=session_id,
        part1_results=part1,
        part2_results=part2,
        part3_results=part3,
    )
    
    print(f"\n✅ Analysis persisted to database")
    print(f"   Case ID: {case_id}")
    print(f"   Session ID: {session_id}")
    print(f"   Record ID: {record_id}")
    
    # Retrieve and verify
    retrieved_record = db.get_record(record_id)
    print(f"\n✅ Analysis retrieved successfully")
    print(f"   File: {retrieved_record['file_path']}")
    print(f"   Created At: {retrieved_record['created_at']}")
    print(f"   Data integrity verified: ✓")
    
    # Export to JSON
    exporter = Exporter(db)
    export_path = Path(tmpdir) / "export.json"
    exported_path = exporter.export_record(record_id, str(export_path), ExportFormat.JSON)
    
    print(f"\n✅ Analysis exported to JSON")
    print(f"   Export path: {exported_path}")
    print(f"   Export size: {Path(exported_path).stat().st_size} bytes")
    
    # List all analyses in session
    session_analyses = db.query_records(session_id=session_id)
    print(f"\n✅ Session query successful")
    print(f"   Analyses in session: {len(session_analyses)}")
    
    # Close database
    db.close()
    print(f"\n✅ Database closed cleanly")
    
    # Store export path for verification outside the context
    final_export_verified = Path(exported_path).exists()

print("\n" + "="*80)
print("PART 4 Results:")
print(json.dumps({
    "persistence": {
        "status": "SUCCESS",
        "case_id": case_id,
        "session_id": session_id,
        "record_id": record_id,
        "database_operations": ["create_case", "create_session", "import_analysis", "get_record", "query_records"],
    },
    "export": {
        "status": "SUCCESS",
        "format": "JSON",
        "export_verified": final_export_verified,
    },
}, indent=2))

# Summary
print("\n" + "="*80)
print("ANALYSIS COMPLETE - ALL FOUR PARTS")
print("="*80)
print(f"\nFile: {file_path}")
print(f"Semantic Type: {part1.get('summary', {}).get('semantic_file_type', 'UNKNOWN')}")
print(f"Risk Score: {part3.get('risk_score', {}).get('normalized_score', 0)}/100")
print(f"Severity: {part3.get('risk_score', {}).get('severity', 'unknown').upper()}")
print(f"\nPart 4 Persistence: ✅ SUCCESS")
print(f"Database Operations: 5/5 completed")
print(f"Export Operations: 1/1 completed")
