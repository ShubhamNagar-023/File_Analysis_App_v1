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
        # For simplicity, we'll write a basic PDF-like text file
        # In production, you would use a library like reportlab or weasyprint
        
        try:
            # Try to use weasyprint if available
            from weasyprint import HTML as WeasyprintHTML
            
            html_content = self._generate_html_report(data)
            WeasyprintHTML(string=html_content).write_pdf(str(output_path))
        except ImportError:
            # Fallback: write HTML with PDF extension note
            html_content = self._generate_html_report(data)
            # Write as HTML with a note about PDF
            html_path = output_path.with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Create a simple text-based PDF alternative
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
        
        # Triggered heuristics
        triggered = [h for h in heuristics if h.get('triggered')]
        if triggered:
            parts.append('  <div class="section">')
            parts.append('    <h2>Triggered Heuristics</h2>')
            for h in triggered:
                sev = h.get('severity', 'informational')
                parts.append(f'    <div class="heuristic triggered">')
                parts.append(f'      <h3>{html.escape(h.get("name", ""))}</h3>')
                parts.append(f'      <p><strong>ID:</strong> <code>{html.escape(h.get("heuristic_id", ""))}</code></p>')
                parts.append(f'      <p><strong>Severity:</strong> <span class="severity-{sev}">{sev}</span></p>')
                parts.append(f'      <p><strong>Weight:</strong> {h.get("weight", 0)}</p>')
                parts.append(f'      <p>{html.escape(h.get("explanation", ""))}</p>')
                parts.append('    </div>')
            parts.append('  </div>')
        
        # Findings summary
        if findings:
            parts.append('  <div class="section">')
            parts.append('    <h2>Findings Summary</h2>')
            parts.append(f'    <p>Total findings: {len(findings)}</p>')
            
            # Group by type
            finding_types = {}
            for f in findings:
                ft = f.get('finding_type', 'unknown')
                finding_types[ft] = finding_types.get(ft, 0) + 1
            
            parts.append('    <table>')
            parts.append('      <tr><th>Finding Type</th><th>Count</th></tr>')
            for ft, count in sorted(finding_types.items()):
                parts.append(f'      <tr><td>{html.escape(ft)}</td><td>{count}</td></tr>')
            parts.append('    </table>')
            parts.append('  </div>')
        
        # Provenance
        provenance = record.get('provenance', {})
        parts.append('  <div class="section">')
        parts.append('    <h2>Provenance</h2>')
        parts.append('    <table>')
        parts.append(f'      <tr><th>Schema Version</th><td>{html.escape(record.get("schema_version", ""))}</td></tr>')
        parts.append(f'      <tr><th>Tool Version</th><td>{html.escape(record.get("tool_version", ""))}</td></tr>')
        parts.append(f'      <tr><th>Created At</th><td>{html.escape(provenance.get("created_at", ""))}</td></tr>')
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
        """Generate a text-based report (fallback for PDF)."""
        lines = []
        lines.append("=" * 80)
        lines.append("FILE ANALYSIS REPORT")
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
            lines.append("FILE INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Record ID: {record.get('record_id', '')}")
            lines.append(f"File Name: {record.get('file_name', '')}")
            lines.append(f"File Path: {record.get('file_path', '')}")
            lines.append(f"File Size: {record.get('file_size', 0):,} bytes")
            lines.append(f"SHA256: {record.get('sha256_hash', '')}")
            lines.append(f"File Type: {record.get('semantic_file_type', '')}")
            lines.append("")
            lines.append("RISK ASSESSMENT")
            lines.append("-" * 80)
            lines.append(f"Risk Score: {record.get('risk_score', 0):.1f}/100")
            lines.append(f"Severity: {record.get('severity', 'informational').upper()}")
            
        elif export_type == 'session':
            session = data.get('session', {})
            lines.append("SESSION INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Session ID: {session.get('session_id', '')}")
            lines.append(f"Case ID: {session.get('case_id', '')}")
            lines.append(f"Status: {session.get('status', '')}")
            lines.append(f"Files Analyzed: {data.get('record_count', 0)}")
            
        elif export_type == 'case':
            case = data.get('case', {})
            lines.append("CASE INFORMATION")
            lines.append("-" * 80)
            lines.append(f"Case ID: {case.get('case_id', '')}")
            lines.append(f"Name: {case.get('name', '')}")
            lines.append(f"Status: {case.get('status', '')}")
            lines.append(f"Sessions: {data.get('session_count', 0)}")
            lines.append(f"Total Records: {data.get('total_record_count', 0)}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
