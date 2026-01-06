#!/usr/bin/env python3
"""
File Analysis API Server
Production-grade REST API for file analysis.

Usage:
    python api_server.py [--port PORT] [--host HOST]

Default: http://localhost:5000
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
import argparse

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Global database instance
db = None
exporter = None
upload_folder = None

def init_app(db_path=None):
    """Initialize the application"""
    global db, exporter, upload_folder
    
    # Create exports directory
    exports_dir = Path("exports")
    exports_dir.mkdir(exist_ok=True)
    
    # Create upload folder with restrictive permissions
    upload_folder = Path(tempfile.mkdtemp(prefix="file_analysis_uploads_"))
    upload_folder.chmod(0o700)  # Owner-only access
    
    # Initialize database
    if db_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")  # Add microseconds
        db_path = exports_dir / timestamp / "analysis.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
    
    db = AnalysisDatabase(str(db_path))
    exporter = Exporter(db)
    
    print(f"✓ Database initialized: {db_path}")
    print(f"✓ Upload folder: {upload_folder}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyze an uploaded file
    
    Request:
        - file: File upload (multipart/form-data)
        - case_name: Optional case name
        - session_name: Optional session name
    
    Response:
        - record_id: Analysis record ID
        - results: Complete analysis results
        - exports: Paths to export files
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    try:
        # Save uploaded file
        filename = file.filename
        file_path = upload_folder / filename
        file.save(str(file_path))
        
        print(f"Analyzing: {filename}")
        
        # Run analysis
        part1 = analyze_file(str(file_path))
        part2 = deep_analyze_file(str(file_path), part1)
        part3 = analyze_part3(str(file_path), part1, part2)
        
        # Create case and session
        case_name = request.form.get('case_name', f'Case_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        session_name = request.form.get('session_name', f'Session_{filename}')
        
        case_id = db.create_case(name=case_name, description=f"Analysis of {filename}")
        session_id = db.create_session(case_id=case_id, name=session_name)
        
        # Import to database
        record_id = db.import_analysis(
            session_id=session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3
        )
        
        # Get record
        record = db.get_record(record_id)
        
        # Export to files
        export_base = Path(db.db_path).parent
        json_path = export_base / f"{Path(filename).stem}_analysis.json"
        html_path = export_base / f"{Path(filename).stem}_analysis.html"
        pdf_path = export_base / f"{Path(filename).stem}_analysis.pdf"
        
        exporter.export_record(record_id, str(json_path), ExportFormat.JSON)
        exporter.export_record(record_id, str(html_path), ExportFormat.HTML)
        exporter.export_record(record_id, str(pdf_path), ExportFormat.PDF)
        
        return jsonify({
            'success': True,
            'record_id': record_id,
            'case_id': case_id,
            'session_id': session_id,
            'results': {
                'file_name': record['file_name'],
                'file_size': record['file_size'],
                'semantic_file_type': record['semantic_file_type'],
                'risk_score': record['risk_score'],
                'severity': record['severity'],
                'sha256_hash': record['sha256_hash'],
                'created_at': record['created_at']
            },
            'exports': {
                'json': str(json_path),
                'html': str(html_path),
                'pdf': str(pdf_path)
            }
        })
        
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        # Always clean up uploaded file
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as cleanup_error:
            print(f"Warning: Failed to cleanup file: {cleanup_error}")

@app.route('/api/records', methods=['GET'])
def list_records():
    """List all analysis records with optional filtering"""
    try:
        # Get query parameters
        session_id = request.args.get('session_id')
        file_type = request.args.get('file_type')
        severity = request.args.get('severity')
        min_score = request.args.get('min_score', type=float)
        max_score = request.args.get('max_score', type=float)
        limit = request.args.get('limit', type=int, default=100)
        offset = request.args.get('offset', type=int, default=0)
        
        records = db.query_records(
            session_id=session_id,
            file_type=file_type,
            severity=severity,
            min_score=min_score,
            max_score=max_score,
            limit=limit,
            offset=offset
        )
        return jsonify({
            'success': True,
            'count': len(records),
            'records': records
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/records/<record_id>', methods=['GET'])
def get_record(record_id):
    """Get a specific analysis record"""
    try:
        record = db.get_record(record_id)
        if record is None:
            return jsonify({'error': 'Record not found'}), 404
        return jsonify({
            'success': True,
            'record': record
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/records/<record_id>/export/<format>', methods=['GET'])
def export_record(record_id, format):
    """Export a record in specified format"""
    try:
        if format not in ['json', 'html', 'pdf']:
            return jsonify({'error': 'Invalid format'}), 400
        
        record = db.get_record(record_id)
        if record is None:
            return jsonify({'error': 'Record not found'}), 404
        
        # Create temp file for export
        suffix = f'.{format}'
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        temp_file.close()
        
        # Export
        export_format = {
            'json': ExportFormat.JSON,
            'html': ExportFormat.HTML,
            'pdf': ExportFormat.PDF
        }[format]
        
        exporter.export_record(record_id, temp_file.name, export_format)
        
        # Send file
        mime_type = {
            'json': 'application/json',
            'html': 'text/html',
            'pdf': 'application/pdf'
        }[format]
        
        return send_file(
            temp_file.name,
            mimetype=mime_type,
            as_attachment=True,
            download_name=f"{record['file_name']}_analysis.{format}"
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cases', methods=['GET'])
def list_cases():
    """List all cases"""
    try:
        cases = db.list_cases()
        return jsonify({
            'success': True,
            'count': len(cases),
            'cases': cases
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cases/<case_id>', methods=['GET'])
def get_case(case_id):
    """Get a specific case"""
    try:
        case = db.get_case(case_id)
        if case is None:
            return jsonify({'error': 'Case not found'}), 404
        return jsonify({
            'success': True,
            'case': case
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    """List all sessions, optionally filtered by case_id"""
    try:
        case_id = request.args.get('case_id')
        sessions = db.list_sessions(case_id=case_id)
        return jsonify({
            'success': True,
            'count': len(sessions),
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>', methods=['GET'])
def get_session(session_id):
    """Get a specific session"""
    try:
        session = db.get_session(session_id)
        if session is None:
            return jsonify({'error': 'Session not found'}), 404
        return jsonify({
            'success': True,
            'session': session
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get database statistics"""
    try:
        stats = db.get_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def main():
    parser = argparse.ArgumentParser(description='File Analysis API Server')
    parser.add_argument('--port', type=int, default=5000, help='Port to run server on')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--db', help='Path to database file')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("FILE ANALYSIS API SERVER")
    print("="*70)
    print(f"\nStarting server on http://{args.host}:{args.port}")
    print("\nAPI Endpoints:")
    print(f"  GET  /api/health                       - Health check")
    print(f"  POST /api/analyze                      - Analyze file (upload)")
    print(f"  GET  /api/records                      - List all records")
    print(f"  GET  /api/records/<id>                 - Get specific record")
    print(f"  GET  /api/records/<id>/export/<format> - Export record (json/html/pdf)")
    print(f"  GET  /api/cases                        - List all cases")
    print(f"  GET  /api/cases/<id>                   - Get specific case")
    print(f"  GET  /api/sessions                     - List all sessions")
    print(f"  GET  /api/sessions?case_id=<id>        - List sessions for a case")
    print(f"  GET  /api/sessions/<id>                - Get specific session")
    print(f"  GET  /api/stats                        - Get statistics")
    print("\nPress Ctrl+C to stop\n")
    print("="*70 + "\n")
    
    init_app(args.db)
    
    try:
        app.run(host=args.host, port=args.port, debug=args.debug)
    finally:
        # Cleanup
        if upload_folder and upload_folder.exists():
            shutil.rmtree(upload_folder)
        if db:
            db.close()

if __name__ == '__main__':
    main()
