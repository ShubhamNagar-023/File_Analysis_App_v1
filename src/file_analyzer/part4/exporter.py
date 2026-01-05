"""
PART 4: Export & Reporting

This module exports real stored data to:
- JSON (lossless, canonical)
- PDF (human-readable)
- HTML (portable)

Reports include:
- Case/session identifiers
- Provenance (timestamps, versions)
- Explicit references to evidence IDs

No fabricated or reformatted data beyond presentation.
"""

import html
import json
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .persistence import AnalysisDatabase
from .schemas import SCHEMA_VERSION

# Try to import WeasyPrint, but make it optional
try:
    from weasyprint import HTML as WeasyprintHTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    # OSError can occur when system libraries are missing (e.g., libgobject on macOS)
    WEASYPRINT_AVAILABLE = False
    WeasyprintHTML = None


class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"
    PDF = "pdf"
    HTML = "html"


class Exporter:
    """
    Export handler for analysis data.
    
    Exports data from the database to various formats while maintaining
    data integrity and provenance information.
    """
    
    def __init__(self, db: AnalysisDatabase):
        """
        Initialize the exporter.
        
        Args:
            db: Database instance for data access.
        """
        self.db = db
    
    def export_record(
        self,
        record_id: str,
        output_path: str,
        format: ExportFormat = ExportFormat.JSON
    ) -> str:
        """
        Export a single analysis record.
        
        Args:
            record_id: Record ID to export.
            output_path: Output file path.
            format: Export format.
        
        Returns:
            Path to the exported file.
        """
        record = self.db.get_record(record_id)
        if not record:
            raise ValueError(f"Record not found: {record_id}")
        
        # Get associated data
        findings = self.db.get_findings(record_id=record_id)
        heuristics = self.db.get_heuristics(record_id=record_id)
        
        export_data = {
            "export_type": "record",
            "export_timestamp": datetime.utcnow().isoformat(),
            "schema_version": SCHEMA_VERSION,
            "record": record,
            "findings": findings,
            "heuristics": heuristics,
        }
        
        return self._write_export(export_data, output_path, format)
    
    def export_session(
        self,
        session_id: str,
        output_path: str,
        format: ExportFormat = ExportFormat.JSON
    ) -> str:
        """
        Export a complete session with all records.
        
        Args:
            session_id: Session ID to export.
            output_path: Output file path.
            format: Export format.
        
        Returns:
            Path to the exported file.
        """
        session = self.db.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        
        # Get all records in the session
        records = self.db.query_records(session_id=session_id, limit=10000)
        
        # Get detailed data for each record
        detailed_records = []
        for record_summary in records:
            record = self.db.get_record(record_summary['record_id'])
            if record:
                findings = self.db.get_findings(record_id=record_summary['record_id'])
                heuristics = self.db.get_heuristics(record_id=record_summary['record_id'])
                detailed_records.append({
                    "record": record,
                    "findings": findings,
                    "heuristics": heuristics,
                })
        
        # Get errors
        errors = self.db.get_errors(session_id=session_id)
        
        export_data = {
            "export_type": "session",
            "export_timestamp": datetime.utcnow().isoformat(),
            "schema_version": SCHEMA_VERSION,
            "session": session,
            "record_count": len(detailed_records),
            "records": detailed_records,
            "errors": errors,
        }
        
        return self._write_export(export_data, output_path, format)
    
    def export_case(
        self,
        case_id: str,
        output_path: str,
        format: ExportFormat = ExportFormat.JSON
    ) -> str:
        """
        Export a complete case with all sessions and records.
        
        Args:
            case_id: Case ID to export.
            output_path: Output file path.
            format: Export format.
        
        Returns:
            Path to the exported file.
        """
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Case not found: {case_id}")
        
        # Get all sessions in the case
        sessions = self.db.list_sessions(case_id=case_id, limit=1000)
        
        # Get detailed data for each session
        detailed_sessions = []
        total_records = 0
        
        for session in sessions:
            records = self.db.query_records(session_id=session['session_id'], limit=10000)
            detailed_records = []
            
            for record_summary in records:
                record = self.db.get_record(record_summary['record_id'])
                if record:
                    findings = self.db.get_findings(record_id=record_summary['record_id'])
                    heuristics = self.db.get_heuristics(record_id=record_summary['record_id'])
                    detailed_records.append({
                        "record": record,
                        "findings": findings,
                        "heuristics": heuristics,
                    })
            
            errors = self.db.get_errors(session_id=session['session_id'])
            
            detailed_sessions.append({
                "session": session,
                "record_count": len(detailed_records),
                "records": detailed_records,
                "errors": errors,
            })
            
            total_records += len(detailed_records)
        
        export_data = {
            "export_type": "case",
            "export_timestamp": datetime.utcnow().isoformat(),
            "schema_version": SCHEMA_VERSION,
            "case": case,
            "session_count": len(detailed_sessions),
            "total_record_count": total_records,
            "sessions": detailed_sessions,
        }
        
        return self._write_export(export_data, output_path, format)
    
    def _write_export(
        self,
        data: Dict[str, Any],
        output_path: str,
        format: ExportFormat
    ) -> str:
        """Write export data to file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == ExportFormat.JSON:
            return self._write_json(data, output_path)
        elif format == ExportFormat.PDF:
            return self._write_pdf(data, output_path)
        elif format == ExportFormat.HTML:
            return self._write_html(data, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _write_json(self, data: Dict[str, Any], output_path: Path) -> str:
        """Write data as canonical JSON."""
        # Ensure .json extension
        if output_path.suffix.lower() != '.json':
            output_path = output_path.with_suffix('.json')
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, sort_keys=True)
        
        return str(output_path)
    
    def _write_html(self, data: Dict[str, Any], output_path: Path) -> str:
        """Write data as HTML report."""
        # Ensure .html extension
        if output_path.suffix.lower() != '.html':
            output_path = output_path.with_suffix('.html')
        
        html_content = self._generate_html_report(data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _write_pdf(self, data: Dict[str, Any], output_path: Path) -> str:
        """Write data as PDF report."""
        # Ensure .pdf extension
        if output_path.suffix.lower() != '.pdf':
            output_path = output_path.with_suffix('.pdf')
        
        # Generate HTML first, then convert to PDF
        html_content = self._generate_html_report(data)
        
        if WEASYPRINT_AVAILABLE:
            # Use WeasyPrint to generate PDF from HTML
            try:
                WeasyprintHTML(string=html_content).write_pdf(str(output_path))
            except Exception as e:
                # If WeasyPrint fails for any reason, fallback to text
                print(f"Warning: WeasyPrint PDF generation failed ({e}), using text fallback")
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(self._generate_text_report(data))
        else:
            # Fallback: write a text-based report when WeasyPrint is not available
            print("Note: WeasyPrint not available. PDF will be in text format.")
            print("To generate HTML-based PDFs, install system dependencies and WeasyPrint:")
            print("  See: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self._generate_text_report(data))
        
        return str(output_path)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report content."""
        export_type = data.get('export_type', 'unknown')
        timestamp = data.get('export_timestamp', '')
        schema_version = data.get('schema_version', '')
        
        # Build HTML
        html_parts = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '  <meta charset="UTF-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f'  <title>File Analysis Report - {export_type.title()}</title>',
            '  <style>',
            '    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; line-height: 1.6; }',
            '    h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }',
            '    h2 { color: #555; margin-top: 30px; }',
            '    h3 { color: #666; }',
            '    .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }',
            '    .metadata p { margin: 5px 0; }',
            '    table { width: 100%; border-collapse: collapse; margin: 15px 0; }',
            '    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }',
            '    th { background: #f4f4f4; }',
            '    tr:nth-child(even) { background: #f9f9f9; }',
            '    .severity-critical { color: #dc3545; font-weight: bold; }',
            '    .severity-high { color: #fd7e14; font-weight: bold; }',
            '    .severity-medium { color: #ffc107; }',
            '    .severity-low { color: #28a745; }',
            '    .severity-informational { color: #6c757d; }',
            '    .score { font-size: 1.2em; font-weight: bold; }',
            '    .score-high { color: #dc3545; }',
            '    .score-medium { color: #ffc107; }',
            '    .score-low { color: #28a745; }',
            '    pre { background: #f8f9fa; padding: 10px; overflow-x: auto; border-radius: 3px; }',
            '    code { font-family: "Courier New", monospace; }',
            '    .section { margin-bottom: 30px; }',
            '    .finding { background: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }',
            '    .heuristic { background: #fff; border-left: 4px solid #007bff; padding: 15px; margin: 10px 0; }',
            '    .heuristic.triggered { border-left-color: #dc3545; }',
            '  </style>',
            '</head>',
            '<body>',
            f'  <h1>File Analysis Report</h1>',
            '  <div class="metadata">',
            f'    <p><strong>Export Type:</strong> {html.escape(export_type)}</p>',
            f'    <p><strong>Export Timestamp:</strong> {html.escape(timestamp)}</p>',
            f'    <p><strong>Schema Version:</strong> {html.escape(schema_version)}</p>',
            '  </div>',
        ]
        
        # Add content based on export type
        if export_type == 'record':
            html_parts.extend(self._generate_record_html(data))
        elif export_type == 'session':
            html_parts.extend(self._generate_session_html(data))
        elif export_type == 'case':
            html_parts.extend(self._generate_case_html(data))
        
        html_parts.extend([
            '</body>',
            '</html>',
        ])
        
        return '\n'.join(html_parts)
    
    def _generate_record_html(self, data: Dict[str, Any]) -> List[str]:
        """Generate HTML for a single record."""
        record = data.get('record', {})
        findings = data.get('findings', [])
        heuristics = data.get('heuristics', [])
        
        parts = []
        
        # Record info
        parts.append('  <div class="section">')
        parts.append('    <h2>File Information</h2>')
        parts.append('    <table>')
        parts.append(f'      <tr><th>Record ID</th><td><code>{html.escape(record.get("record_id", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>File Name</th><td>{html.escape(record.get("file_name", ""))}</td></tr>')
        parts.append(f'      <tr><th>File Path</th><td><code>{html.escape(record.get("file_path", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>File Size</th><td>{record.get("file_size", 0):,} bytes</td></tr>')
        parts.append(f'      <tr><th>SHA256</th><td><code>{html.escape(record.get("sha256_hash", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>File Type</th><td>{html.escape(record.get("semantic_file_type", ""))}</td></tr>')
        parts.append(f'      <tr><th>Analysis Date</th><td>{html.escape(record.get("created_at", ""))}</td></tr>')
        parts.append('    </table>')
        parts.append('  </div>')
        
        # Risk score
        risk_score = record.get('risk_score', 0)
        severity = record.get('severity', 'informational')
        score_class = 'score-high' if risk_score >= 60 else 'score-medium' if risk_score >= 30 else 'score-low'
        
        parts.append('  <div class="section">')
        parts.append('    <h2>Risk Assessment</h2>')
        parts.append(f'    <p class="score {score_class}">Risk Score: {risk_score:.1f}/100</p>')
        parts.append(f'    <p>Severity: <span class="severity-{severity}">{severity.upper()}</span></p>')
        parts.append('  </div>')
        
        # Detailed Heuristics Analysis
        if heuristics:
            triggered = [h for h in heuristics if h.get('triggered')]
            not_triggered = [h for h in heuristics if not h.get('triggered')]
            
            parts.append('  <div class="section">')
            parts.append(f'    <h2>Heuristics Analysis ({len(triggered)} triggered, {len(not_triggered)} not triggered)</h2>')
            
            if triggered:
                parts.append('    <h3>Triggered Heuristics (Complete Details)</h3>')
                for h in triggered:
                    parts.append(f'    <div class="heuristic triggered">')
                    parts.append(f'      <h4>{html.escape(h.get("name", ""))}</h4>')
                    
                    # Display ALL fields from the heuristic, just like JSON
                    parts.append('      <table>')
                    parts.append('        <tr><th style="width: 30%">Field</th><th>Value</th></tr>')
                    
                    # Sort keys for consistent display
                    for key in sorted(h.keys()):
                        value = h[key]
                        # Format value appropriately
                        if isinstance(value, dict):
                            value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                        elif isinstance(value, (list, tuple)):
                            value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                        elif key in ['heuristic_id', 'record_id']:
                            value_html = f'<code>{html.escape(str(value))}</code>'
                        elif key == 'severity':
                            sev = str(value)
                            value_html = f'<span class="severity-{sev}">{html.escape(sev)}</span>'
                        else:
                            value_html = html.escape(str(value))
                        
                        parts.append(f'        <tr><td><strong>{html.escape(key)}</strong></td><td>{value_html}</td></tr>')
                    
                    parts.append('      </table>')
                    parts.append('    </div>')
            
            if not_triggered:
                parts.append('    <h3>Evaluated But Not Triggered (Complete Details)</h3>')
                for h in not_triggered:
                    parts.append(f'    <div class="heuristic">')
                    parts.append(f'      <h4>{html.escape(h.get("name", ""))}</h4>')
                    
                    # Display ALL fields from the heuristic, just like JSON
                    parts.append('      <table>')
                    parts.append('        <tr><th style="width: 30%">Field</th><th>Value</th></tr>')
                    
                    # Sort keys for consistent display
                    for key in sorted(h.keys()):
                        value = h[key]
                        # Format value appropriately
                        if isinstance(value, dict):
                            value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                        elif isinstance(value, (list, tuple)):
                            value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                        elif key in ['heuristic_id', 'record_id']:
                            value_html = f'<code>{html.escape(str(value))}</code>'
                        elif key == 'severity':
                            sev = str(value)
                            value_html = f'<span class="severity-{sev}">{html.escape(sev)}</span>'
                        else:
                            value_html = html.escape(str(value))
                        
                        parts.append(f'        <tr><td><strong>{html.escape(key)}</strong></td><td>{value_html}</td></tr>')
                    
                    parts.append('      </table>')
                    parts.append('    </div>')
            
            parts.append('  </div>')
        
        # Detailed Findings
        if findings:
            parts.append('  <div class="section">')
            parts.append(f'    <h2>Detailed Findings ({len(findings)} total)</h2>')
            
            # Group by type for summary
            finding_types = {}
            for f in findings:
                ft = f.get('finding_type', 'unknown')
                finding_types[ft] = finding_types.get(ft, 0) + 1
            
            parts.append('    <h3>Summary by Type</h3>')
            parts.append('    <table>')
            parts.append('      <tr><th>Finding Type</th><th>Count</th></tr>')
            for ft, count in sorted(finding_types.items()):
                parts.append(f'      <tr><td>{html.escape(ft)}</td><td>{count}</td></tr>')
            parts.append('    </table>')
            
            # Individual findings - show ALL fields like JSON format
            parts.append('    <h3>Individual Findings (Complete Details)</h3>')
            for idx, f in enumerate(findings, 1):
                ft = f.get('finding_type', 'unknown')
                parts.append(f'    <div class="finding">')
                parts.append(f'      <h4>Finding #{idx}: {html.escape(ft)}</h4>')
                
                # Display ALL fields from the finding, just like JSON
                parts.append('      <table>')
                parts.append('        <tr><th style="width: 30%">Field</th><th>Value</th></tr>')
                
                # Sort keys for consistent display
                for key in sorted(f.keys()):
                    value = f[key]
                    # Format value appropriately
                    if isinstance(value, dict):
                        value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                    elif isinstance(value, (list, tuple)):
                        value_html = '<pre><code>' + html.escape(json.dumps(value, indent=2, default=str)) + '</code></pre>'
                    elif key in ['finding_id', 'record_id', 'heuristic_id']:
                        value_html = f'<code>{html.escape(str(value))}</code>'
                    else:
                        value_html = html.escape(str(value))
                    
                    parts.append(f'        <tr><td><strong>{html.escape(key)}</strong></td><td>{value_html}</td></tr>')
                
                parts.append('      </table>')
                parts.append('    </div>')
            
            parts.append('  </div>')
        
        # Complete Analysis Data
        parts.append('  <div class="section">')
        parts.append('    <h2>Complete Analysis Data</h2>')
        
        # PART 1 Data
        if record.get('part1'):
            parts.append('    <h3>PART 1: File Ingestion & Type Resolution</h3>')
            parts.append('    <pre><code>' + html.escape(json.dumps(record.get('part1'), indent=2, default=str)) + '</code></pre>')
        
        # PART 2 Data
        if record.get('part2'):
            parts.append('    <h3>PART 2: Deep File-Type-Aware Static Analysis</h3>')
            parts.append('    <pre><code>' + html.escape(json.dumps(record.get('part2'), indent=2, default=str)) + '</code></pre>')
        
        # PART 3 Data
        if record.get('part3'):
            parts.append('    <h3>PART 3: Rules, Correlation & Risk Scoring</h3>')
            parts.append('    <pre><code>' + html.escape(json.dumps(record.get('part3'), indent=2, default=str)) + '</code></pre>')
        
        parts.append('  </div>')
        
        # Provenance
        provenance = record.get('provenance', {})
        parts.append('  <div class="section">')
        parts.append('    <h2>Provenance & Metadata</h2>')
        parts.append('    <table>')
        parts.append(f'      <tr><th>Schema Version</th><td>{html.escape(record.get("schema_version", ""))}</td></tr>')
        parts.append(f'      <tr><th>Tool Version</th><td>{html.escape(record.get("tool_version", ""))}</td></tr>')
        parts.append(f'      <tr><th>Created At</th><td>{html.escape(provenance.get("created_at", ""))}</td></tr>')
        parts.append(f'      <tr><th>Session ID</th><td><code>{html.escape(record.get("session_id", ""))}</code></td></tr>')
        parts.append('    </table>')
        parts.append('  </div>')
        
        return parts
    
    def _generate_session_html(self, data: Dict[str, Any]) -> List[str]:
        """Generate HTML for a session."""
        session = data.get('session', {})
        records = data.get('records', [])
        errors = data.get('errors', [])
        
        parts = []
        
        # Session info
        parts.append('  <div class="section">')
        parts.append('    <h2>Session Information</h2>')
        parts.append('    <table>')
        parts.append(f'      <tr><th>Session ID</th><td><code>{html.escape(session.get("session_id", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>Case ID</th><td><code>{html.escape(session.get("case_id", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>Name</th><td>{html.escape(session.get("name", "") or "N/A")}</td></tr>')
        parts.append(f'      <tr><th>Status</th><td>{html.escape(session.get("status", ""))}</td></tr>')
        parts.append(f'      <tr><th>Created</th><td>{html.escape(session.get("created_at", ""))}</td></tr>')
        parts.append(f'      <tr><th>File Count</th><td>{len(records)}</td></tr>')
        parts.append('    </table>')
        parts.append('  </div>')
        
        # Records summary
        if records:
            parts.append('  <div class="section">')
            parts.append('    <h2>Analysis Records</h2>')
            parts.append('    <table>')
            parts.append('      <tr><th>File Name</th><th>Type</th><th>Score</th><th>Severity</th><th>Findings</th></tr>')
            
            for rec_data in records:
                record = rec_data.get('record', {})
                findings = rec_data.get('findings', [])
                heuristics = rec_data.get('heuristics', [])
                triggered = len([h for h in heuristics if h.get('triggered')])
                
                sev = record.get('severity', 'informational')
                score = record.get('risk_score', 0)
                
                parts.append('      <tr>')
                parts.append(f'        <td>{html.escape(record.get("file_name", ""))}</td>')
                parts.append(f'        <td>{html.escape(record.get("semantic_file_type", ""))}</td>')
                parts.append(f'        <td>{score:.1f}</td>')
                parts.append(f'        <td class="severity-{sev}">{sev}</td>')
                parts.append(f'        <td>{len(findings)} findings, {triggered} heuristics</td>')
                parts.append('      </tr>')
            
            parts.append('    </table>')
            parts.append('  </div>')
        
        # Errors
        if errors:
            parts.append('  <div class="section">')
            parts.append('    <h2>Errors</h2>')
            parts.append('    <table>')
            parts.append('      <tr><th>Type</th><th>Message</th><th>Timestamp</th></tr>')
            for err in errors:
                parts.append('      <tr>')
                parts.append(f'        <td>{html.escape(err.get("error_type", ""))}</td>')
                parts.append(f'        <td>{html.escape(err.get("message", ""))}</td>')
                parts.append(f'        <td>{html.escape(err.get("timestamp", ""))}</td>')
                parts.append('      </tr>')
            parts.append('    </table>')
            parts.append('  </div>')
        
        return parts
    
    def _generate_case_html(self, data: Dict[str, Any]) -> List[str]:
        """Generate HTML for a case."""
        case = data.get('case', {})
        sessions = data.get('sessions', [])
        
        parts = []
        
        # Case info
        parts.append('  <div class="section">')
        parts.append('    <h2>Case Information</h2>')
        parts.append('    <table>')
        parts.append(f'      <tr><th>Case ID</th><td><code>{html.escape(case.get("case_id", ""))}</code></td></tr>')
        parts.append(f'      <tr><th>Name</th><td>{html.escape(case.get("name", ""))}</td></tr>')
        parts.append(f'      <tr><th>Description</th><td>{html.escape(case.get("description", "") or "N/A")}</td></tr>')
        parts.append(f'      <tr><th>Status</th><td>{html.escape(case.get("status", ""))}</td></tr>')
        parts.append(f'      <tr><th>Created</th><td>{html.escape(case.get("created_at", ""))}</td></tr>')
        parts.append(f'      <tr><th>Session Count</th><td>{len(sessions)}</td></tr>')
        parts.append(f'      <tr><th>Total Records</th><td>{data.get("total_record_count", 0)}</td></tr>')
        parts.append('    </table>')
        parts.append('  </div>')
        
        # Sessions summary
        if sessions:
            parts.append('  <div class="section">')
            parts.append('    <h2>Sessions</h2>')
            
            for sess_data in sessions:
                session = sess_data.get('session', {})
                records = sess_data.get('records', [])
                
                parts.append(f'    <h3>{html.escape(session.get("name", "") or session.get("session_id", ""))}</h3>')
                parts.append('    <table>')
                parts.append(f'      <tr><th>Session ID</th><td><code>{html.escape(session.get("session_id", ""))}</code></td></tr>')
                parts.append(f'      <tr><th>Status</th><td>{html.escape(session.get("status", ""))}</td></tr>')
                parts.append(f'      <tr><th>Files Analyzed</th><td>{len(records)}</td></tr>')
                parts.append('    </table>')
            
            parts.append('  </div>')
        
        return parts
    
    def _generate_text_report(self, data: Dict[str, Any]) -> str:
        """Generate a detailed text-based report (fallback for PDF)."""
        lines = []
        lines.append("=" * 80)
        lines.append("FILE ANALYSIS REPORT - DETAILED")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Export Type: {data.get('export_type', 'unknown')}")
        lines.append(f"Export Timestamp: {data.get('export_timestamp', '')}")
        lines.append(f"Schema Version: {data.get('schema_version', '')}")
        lines.append("")
        lines.append("-" * 80)
        
        export_type = data.get('export_type', '')
        
        if export_type == 'record':
            record = data.get('record', {})
            findings = data.get('findings', [])
            heuristics = data.get('heuristics', [])
            
            lines.append("")
            lines.append("FILE INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Record ID: {record.get('record_id', '')}")
            lines.append(f"File Name: {record.get('file_name', '')}")
            lines.append(f"File Path: {record.get('file_path', '')}")
            lines.append(f"File Size: {record.get('file_size', 0):,} bytes")
            lines.append(f"SHA256: {record.get('sha256_hash', '')}")
            lines.append(f"File Type: {record.get('semantic_file_type', '')}")
            lines.append(f"Analysis Date: {record.get('created_at', '')}")
            
            lines.append("")
            lines.append("RISK ASSESSMENT")
            lines.append("-" * 80)
            lines.append(f"Risk Score: {record.get('risk_score', 0):.1f}/100")
            lines.append(f"Severity: {record.get('severity', 'informational').upper()}")
            
            # Heuristics
            if heuristics:
                triggered = [h for h in heuristics if h.get('triggered')]
                not_triggered = [h for h in heuristics if not h.get('triggered')]
                
                lines.append("")
                lines.append(f"HEURISTICS ANALYSIS ({len(triggered)} triggered, {len(not_triggered)} not triggered)")
                lines.append("-" * 80)
                
                if triggered:
                    lines.append("")
                    lines.append("Triggered Heuristics (Complete Details):")
                    for idx, h in enumerate(triggered, 1):
                        lines.append(f"\n  Triggered Heuristic #{idx}: {h.get('name', '')}")
                        # Show ALL fields
                        for key in sorted(h.keys()):
                            if key == 'name':
                                continue  # Already shown in header
                            value = h[key]
                            if isinstance(value, (dict, list)):
                                lines.append(f"    {key}: {json.dumps(value, indent=6, default=str)}")
                            else:
                                lines.append(f"    {key}: {value}")
                        lines.append("")
                
                if not_triggered:
                    lines.append("")
                    lines.append("Evaluated But Not Triggered (Complete Details):")
                    for idx, h in enumerate(not_triggered, 1):
                        lines.append(f"\n  Not Triggered Heuristic #{idx}: {h.get('name', '')}")
                        # Show ALL fields
                        for key in sorted(h.keys()):
                            if key == 'name':
                                continue  # Already shown in header
                            value = h[key]
                            if isinstance(value, (dict, list)):
                                lines.append(f"    {key}: {json.dumps(value, indent=6, default=str)}")
                            else:
                                lines.append(f"    {key}: {value}")
            
            # Findings
            if findings:
                lines.append("")
                lines.append(f"DETAILED FINDINGS ({len(findings)} total)")
                lines.append("-" * 80)
                
                # Group by type
                finding_types = {}
                for f in findings:
                    ft = f.get('finding_type', 'unknown')
                    finding_types[ft] = finding_types.get(ft, 0) + 1
                
                lines.append("")
                lines.append("Summary by Type:")
                for ft, count in sorted(finding_types.items()):
                    lines.append(f"  {ft}: {count}")
                
                lines.append("")
                lines.append("Individual Findings (Complete Details):")
                for idx, f in enumerate(findings, 1):
                    lines.append(f"\n  Finding #{idx}: {f.get('finding_type', 'unknown')}")
                    # Show ALL fields
                    for key in sorted(f.keys()):
                        if key == 'finding_type':
                            continue  # Already shown in header
                        value = f[key]
                        if isinstance(value, (dict, list)):
                            lines.append(f"    {key}: {json.dumps(value, indent=6, default=str)}")
                        else:
                            lines.append(f"    {key}: {value}")
            
            # Complete data sections
            lines.append("")
            lines.append("COMPLETE ANALYSIS DATA")
            lines.append("-" * 80)
            
            if record.get('part1'):
                lines.append("")
                lines.append("PART 1: File Ingestion & Type Resolution")
                lines.append(json.dumps(record.get('part1'), indent=2, default=str))
            
            if record.get('part2'):
                lines.append("")
                lines.append("PART 2: Deep File-Type-Aware Static Analysis")
                lines.append(json.dumps(record.get('part2'), indent=2, default=str))
            
            if record.get('part3'):
                lines.append("")
                lines.append("PART 3: Rules, Correlation & Risk Scoring")
                lines.append(json.dumps(record.get('part3'), indent=2, default=str))
            
            # Provenance
            lines.append("")
            lines.append("PROVENANCE & METADATA")
            lines.append("-" * 80)
            lines.append(f"Schema Version: {record.get('schema_version', '')}")
            lines.append(f"Tool Version: {record.get('tool_version', '')}")
            lines.append(f"Session ID: {record.get('session_id', '')}")
            provenance = record.get('provenance', {})
            lines.append(f"Created At: {provenance.get('created_at', '')}")
            
        elif export_type == 'session':
            session = data.get('session', {})
            records = data.get('records', [])
            
            lines.append("")
            lines.append("SESSION INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Session ID: {session.get('session_id', '')}")
            lines.append(f"Case ID: {session.get('case_id', '')}")
            lines.append(f"Name: {session.get('name', '') or 'N/A'}")
            lines.append(f"Status: {session.get('status', '')}")
            lines.append(f"Created: {session.get('created_at', '')}")
            lines.append(f"Files Analyzed: {len(records)}")
            
            if records:
                lines.append("")
                lines.append("ANALYSIS RECORDS")
                lines.append("-" * 80)
                for rec_data in records:
                    record = rec_data.get('record', {})
                    findings = rec_data.get('findings', [])
                    heuristics = rec_data.get('heuristics', [])
                    triggered = len([h for h in heuristics if h.get('triggered')])
                    
                    lines.append(f"\n  {record.get('file_name', '')}")
                    lines.append(f"    Type: {record.get('semantic_file_type', '')}")
                    lines.append(f"    Risk Score: {record.get('risk_score', 0):.1f}")
                    lines.append(f"    Severity: {record.get('severity', '')}")
                    lines.append(f"    Findings: {len(findings)}, Heuristics: {triggered}")
            
        elif export_type == 'case':
            case = data.get('case', {})
            sessions = data.get('sessions', [])
            
            lines.append("")
            lines.append("CASE INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Case ID: {case.get('case_id', '')}")
            lines.append(f"Name: {case.get('name', '')}")
            lines.append(f"Description: {case.get('description', '') or 'N/A'}")
            lines.append(f"Status: {case.get('status', '')}")
            lines.append(f"Created: {case.get('created_at', '')}")
            lines.append(f"Sessions: {len(sessions)}")
            lines.append(f"Total Records: {data.get('total_record_count', 0)}")
            
            if sessions:
                lines.append("")
                lines.append("SESSIONS")
                lines.append("-" * 80)
                for sess_data in sessions:
                    session = sess_data.get('session', {})
                    records = sess_data.get('records', [])
                    lines.append(f"\n  {session.get('name', '') or session.get('session_id', '')}")
                    lines.append(f"    Session ID: {session.get('session_id', '')}")
                    lines.append(f"    Status: {session.get('status', '')}")
                    lines.append(f"    Files Analyzed: {len(records)}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
