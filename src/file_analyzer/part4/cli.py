"""
PART 4: Command-Line Interface (CLI)

This module provides a CLI that can:
- Create and list cases/sessions
- Import analysis results (from PART 1-3 JSON)
- Query files, findings, and scores
- Filter by file type, severity, rule, time
- Export reports

Parity Rule: Anything retrievable via IPC must be retrievable via CLI with identical results.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .persistence import AnalysisDatabase, DatabaseError, IntegrityError
from .exporter import Exporter, ExportFormat


DEFAULT_DB_PATH = os.path.expanduser("~/.file_analyzer/analysis.db")


def get_db(db_path: Optional[str] = None) -> AnalysisDatabase:
    """Get database instance."""
    return AnalysisDatabase(db_path or DEFAULT_DB_PATH)


def format_output(data: Any, format_type: str = "json") -> str:
    """Format output data."""
    if format_type == "json":
        return json.dumps(data, indent=2, default=str)
    elif format_type == "table":
        # Simple table format for lists
        if isinstance(data, list) and len(data) > 0:
            if isinstance(data[0], dict):
                # Get all keys from all items
                keys = list(data[0].keys())[:8]  # Limit columns
                
                # Calculate column widths
                widths = {k: max(len(str(k)), max(len(str(item.get(k, ''))[:50]) for item in data)) for k in keys}
                
                # Build header
                header = " | ".join(str(k).ljust(widths[k])[:50] for k in keys)
                separator = "-+-".join("-" * widths[k] for k in keys)
                
                # Build rows
                rows = []
                for item in data:
                    row = " | ".join(str(item.get(k, ''))[:50].ljust(widths[k]) for k in keys)
                    rows.append(row)
                
                return f"{header}\n{separator}\n" + "\n".join(rows)
        return str(data)
    else:
        return str(data)


# ============================================================================
# CLI COMMANDS
# ============================================================================

def cmd_init(args: argparse.Namespace) -> int:
    """Initialize the database."""
    try:
        db = get_db(args.database)
        stats = db.get_statistics()
        print(f"Database initialized at: {args.database or DEFAULT_DB_PATH}")
        print(f"Schema version: {stats['schema_version']}")
        print(f"Tool version: {stats['tool_version']}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_case_create(args: argparse.Namespace) -> int:
    """Create a new case."""
    try:
        db = get_db(args.database)
        
        metadata = {}
        if args.metadata:
            metadata = json.loads(args.metadata)
        
        case_id = db.create_case(
            name=args.name,
            description=args.description or "",
            metadata=metadata
        )
        
        if args.json:
            print(json.dumps({"case_id": case_id, "name": args.name}, indent=2))
        else:
            print(f"Created case: {case_id}")
            print(f"Name: {args.name}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_case_list(args: argparse.Namespace) -> int:
    """List cases."""
    try:
        db = get_db(args.database)
        cases = db.list_cases(
            status=args.status,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(cases, indent=2, default=str))
        else:
            print(format_output(cases, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_case_get(args: argparse.Namespace) -> int:
    """Get case details."""
    try:
        db = get_db(args.database)
        case = db.get_case(args.case_id)
        
        if not case:
            print(f"Case not found: {args.case_id}", file=sys.stderr)
            return 1
        
        print(json.dumps(case, indent=2, default=str))
        return 0
    except IntegrityError as e:
        print(f"Integrity Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_session_create(args: argparse.Namespace) -> int:
    """Create a new session."""
    try:
        db = get_db(args.database)
        
        metadata = {}
        if args.metadata:
            metadata = json.loads(args.metadata)
        
        session_id = db.create_session(
            case_id=args.case_id,
            name=args.name or "",
            description=args.description or "",
            metadata=metadata
        )
        
        if args.json:
            print(json.dumps({"session_id": session_id, "case_id": args.case_id}, indent=2))
        else:
            print(f"Created session: {session_id}")
            print(f"Case: {args.case_id}")
        
        return 0
    except DatabaseError as e:
        print(f"Database Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_session_list(args: argparse.Namespace) -> int:
    """List sessions."""
    try:
        db = get_db(args.database)
        sessions = db.list_sessions(
            case_id=args.case_id,
            status=args.status,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(sessions, indent=2, default=str))
        else:
            print(format_output(sessions, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_session_get(args: argparse.Namespace) -> int:
    """Get session details."""
    try:
        db = get_db(args.database)
        session = db.get_session(args.session_id)
        
        if not session:
            print(f"Session not found: {args.session_id}", file=sys.stderr)
            return 1
        
        print(json.dumps(session, indent=2, default=str))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_import(args: argparse.Namespace) -> int:
    """Import analysis results from JSON file."""
    try:
        db = get_db(args.database)
        
        # Read input file
        with open(args.file, 'r') as f:
            data = json.load(f)
        
        # Extract PART 1, 2, 3 results
        if 'part1' in data and 'part2' in data and 'part3' in data:
            part1 = data['part1']
            part2 = data['part2']
            part3 = data['part3']
        else:
            # Assume it's a combined analysis output
            print("Error: Input file must contain 'part1', 'part2', and 'part3' keys", file=sys.stderr)
            return 1
        
        record_id = db.import_analysis(
            session_id=args.session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3
        )
        
        if args.json:
            print(json.dumps({"record_id": record_id, "session_id": args.session_id}, indent=2))
        else:
            print(f"Imported record: {record_id}")
            print(f"Session: {args.session_id}")
        
        return 0
    except json.JSONDecodeError as e:
        print(f"JSON Error: {e}", file=sys.stderr)
        return 1
    except DatabaseError as e:
        print(f"Database Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze a file and import results."""
    try:
        # Import analysis modules
        from ..analyzer import FileAnalyzer
        from ..deep_analyzer import DeepAnalyzer
        from ..part3_analyzer import Part3Analyzer
        
        db = get_db(args.database)
        
        # Run analysis
        file_path = os.path.abspath(args.file)
        
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}", file=sys.stderr)
            return 1
        
        # PART 1
        part1_analyzer = FileAnalyzer(file_path)
        part1_results = part1_analyzer.analyze()
        
        # PART 2
        part2_analyzer = DeepAnalyzer(file_path, part1_results)
        part2_results = part2_analyzer.analyze()
        
        # PART 3
        part3_analyzer = Part3Analyzer(file_path, part1_results, part2_results)
        part3_results = part3_analyzer.analyze()
        
        # Import to database
        record_id = db.import_analysis(
            session_id=args.session_id,
            part1_results=part1_results,
            part2_results=part2_results,
            part3_results=part3_results
        )
        
        if args.json:
            print(json.dumps({
                "record_id": record_id,
                "session_id": args.session_id,
                "file_path": file_path,
                "risk_score": part3_results.get('risk_score', {}).get('normalized_score', 0),
                "severity": part3_results.get('risk_score', {}).get('severity', 'informational'),
            }, indent=2))
        else:
            print(f"Analyzed and imported: {record_id}")
            print(f"File: {file_path}")
            print(f"Risk Score: {part3_results.get('risk_score', {}).get('normalized_score', 0):.1f}")
            print(f"Severity: {part3_results.get('risk_score', {}).get('severity', 'informational')}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_query_records(args: argparse.Namespace) -> int:
    """Query analysis records."""
    try:
        db = get_db(args.database)
        records = db.query_records(
            session_id=args.session_id,
            file_type=args.file_type,
            severity=args.severity,
            min_score=args.min_score,
            max_score=args.max_score,
            from_time=args.from_time,
            to_time=args.to_time,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(records, indent=2, default=str))
        else:
            print(format_output(records, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_record_get(args: argparse.Namespace) -> int:
    """Get full record details."""
    try:
        db = get_db(args.database)
        record = db.get_record(args.record_id)
        
        if not record:
            print(f"Record not found: {args.record_id}", file=sys.stderr)
            return 1
        
        print(json.dumps(record, indent=2, default=str))
        return 0
    except IntegrityError as e:
        print(f"Integrity Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_query_findings(args: argparse.Namespace) -> int:
    """Query findings."""
    try:
        db = get_db(args.database)
        findings = db.get_findings(
            record_id=args.record_id,
            finding_type=args.finding_type,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(findings, indent=2, default=str))
        else:
            print(format_output(findings, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_query_heuristics(args: argparse.Namespace) -> int:
    """Query heuristic results."""
    try:
        db = get_db(args.database)
        heuristics = db.get_heuristics(
            record_id=args.record_id,
            triggered_only=args.triggered,
            severity=args.severity,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(heuristics, indent=2, default=str))
        else:
            print(format_output(heuristics, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_export(args: argparse.Namespace) -> int:
    """Export records to file."""
    try:
        db = get_db(args.database)
        
        # Determine format
        format_map = {
            'json': ExportFormat.JSON,
            'pdf': ExportFormat.PDF,
            'html': ExportFormat.HTML,
        }
        
        export_format = format_map.get(args.format.lower())
        if not export_format:
            print(f"Unsupported format: {args.format}", file=sys.stderr)
            return 1
        
        exporter = Exporter(db)
        
        if args.record_id:
            # Export single record
            output_path = exporter.export_record(
                record_id=args.record_id,
                output_path=args.output,
                format=export_format
            )
        elif args.session_id:
            # Export session
            output_path = exporter.export_session(
                session_id=args.session_id,
                output_path=args.output,
                format=export_format
            )
        elif args.case_id:
            # Export case
            output_path = exporter.export_case(
                case_id=args.case_id,
                output_path=args.output,
                format=export_format
            )
        else:
            print("Error: Must specify --record-id, --session-id, or --case-id", file=sys.stderr)
            return 1
        
        print(f"Exported to: {output_path}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_errors(args: argparse.Namespace) -> int:
    """Query errors."""
    try:
        db = get_db(args.database)
        errors = db.get_errors(
            session_id=args.session_id,
            error_type=args.error_type,
            limit=args.limit,
            offset=args.offset
        )
        
        if args.json:
            print(json.dumps(errors, indent=2, default=str))
        else:
            print(format_output(errors, "table"))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_stats(args: argparse.Namespace) -> int:
    """Show database statistics."""
    try:
        db = get_db(args.database)
        stats = db.get_statistics()
        
        print(json.dumps(stats, indent=2, default=str))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


# ============================================================================
# CLI PARSER
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='file-analyzer',
        description='File Analysis Application - PART 4: Persistence, CLI & IPC'
    )
    
    parser.add_argument(
        '--database', '-d',
        default=DEFAULT_DB_PATH,
        help=f'Path to database file (default: {DEFAULT_DB_PATH})'
    )
    
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output in JSON format'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # init command
    init_parser = subparsers.add_parser('init', help='Initialize the database')
    init_parser.set_defaults(func=cmd_init)
    
    # case commands
    case_parser = subparsers.add_parser('case', help='Case management')
    case_subparsers = case_parser.add_subparsers(dest='case_command')
    
    case_create = case_subparsers.add_parser('create', help='Create a new case')
    case_create.add_argument('name', help='Case name')
    case_create.add_argument('--description', '-desc', help='Case description')
    case_create.add_argument('--metadata', '-m', help='JSON metadata')
    case_create.set_defaults(func=cmd_case_create)
    
    case_list = case_subparsers.add_parser('list', help='List cases')
    case_list.add_argument('--status', choices=['open', 'closed', 'archived'])
    case_list.add_argument('--limit', type=int, default=100)
    case_list.add_argument('--offset', type=int, default=0)
    case_list.set_defaults(func=cmd_case_list)
    
    case_get = case_subparsers.add_parser('get', help='Get case details')
    case_get.add_argument('case_id', help='Case ID')
    case_get.set_defaults(func=cmd_case_get)
    
    # session commands
    session_parser = subparsers.add_parser('session', help='Session management')
    session_subparsers = session_parser.add_subparsers(dest='session_command')
    
    session_create = session_subparsers.add_parser('create', help='Create a new session')
    session_create.add_argument('case_id', help='Parent case ID')
    session_create.add_argument('--name', '-n', help='Session name')
    session_create.add_argument('--description', '-desc', help='Session description')
    session_create.add_argument('--metadata', '-m', help='JSON metadata')
    session_create.set_defaults(func=cmd_session_create)
    
    session_list = session_subparsers.add_parser('list', help='List sessions')
    session_list.add_argument('--case-id', help='Filter by case ID')
    session_list.add_argument('--status', choices=['active', 'completed', 'archived'])
    session_list.add_argument('--limit', type=int, default=100)
    session_list.add_argument('--offset', type=int, default=0)
    session_list.set_defaults(func=cmd_session_list)
    
    session_get = session_subparsers.add_parser('get', help='Get session details')
    session_get.add_argument('session_id', help='Session ID')
    session_get.set_defaults(func=cmd_session_get)
    
    # import command
    import_parser = subparsers.add_parser('import', help='Import analysis results')
    import_parser.add_argument('session_id', help='Session ID to import into')
    import_parser.add_argument('file', help='JSON file containing analysis results')
    import_parser.set_defaults(func=cmd_import)
    
    # analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a file and import results')
    analyze_parser.add_argument('session_id', help='Session ID to import into')
    analyze_parser.add_argument('file', help='File to analyze')
    analyze_parser.set_defaults(func=cmd_analyze)
    
    # query commands
    query_parser = subparsers.add_parser('query', help='Query data')
    query_subparsers = query_parser.add_subparsers(dest='query_command')
    
    query_records = query_subparsers.add_parser('records', help='Query analysis records')
    query_records.add_argument('--session-id', help='Filter by session ID')
    query_records.add_argument('--file-type', help='Filter by file type')
    query_records.add_argument('--severity', choices=['informational', 'low', 'medium', 'high', 'critical'])
    query_records.add_argument('--min-score', type=float, help='Minimum risk score')
    query_records.add_argument('--max-score', type=float, help='Maximum risk score')
    query_records.add_argument('--from-time', help='From timestamp (ISO 8601)')
    query_records.add_argument('--to-time', help='To timestamp (ISO 8601)')
    query_records.add_argument('--limit', type=int, default=100)
    query_records.add_argument('--offset', type=int, default=0)
    query_records.set_defaults(func=cmd_query_records)
    
    query_findings = query_subparsers.add_parser('findings', help='Query findings')
    query_findings.add_argument('--record-id', help='Filter by record ID')
    query_findings.add_argument('--finding-type', help='Filter by finding type')
    query_findings.add_argument('--limit', type=int, default=1000)
    query_findings.add_argument('--offset', type=int, default=0)
    query_findings.set_defaults(func=cmd_query_findings)
    
    query_heuristics = query_subparsers.add_parser('heuristics', help='Query heuristic results')
    query_heuristics.add_argument('--record-id', help='Filter by record ID')
    query_heuristics.add_argument('--triggered', action='store_true', help='Only show triggered heuristics')
    query_heuristics.add_argument('--severity', choices=['informational', 'low', 'medium', 'high', 'critical'])
    query_heuristics.add_argument('--limit', type=int, default=1000)
    query_heuristics.add_argument('--offset', type=int, default=0)
    query_heuristics.set_defaults(func=cmd_query_heuristics)
    
    # record get command
    record_parser = subparsers.add_parser('record', help='Get full record details')
    record_parser.add_argument('record_id', help='Record ID')
    record_parser.set_defaults(func=cmd_record_get)
    
    # export command
    export_parser = subparsers.add_parser('export', help='Export data to file')
    export_parser.add_argument('--format', '-f', choices=['json', 'pdf', 'html'], default='json')
    export_parser.add_argument('--output', '-o', required=True, help='Output file path')
    export_parser.add_argument('--record-id', help='Export single record')
    export_parser.add_argument('--session-id', help='Export session')
    export_parser.add_argument('--case-id', help='Export case')
    export_parser.set_defaults(func=cmd_export)
    
    # errors command
    errors_parser = subparsers.add_parser('errors', help='Query errors')
    errors_parser.add_argument('--session-id', help='Filter by session ID')
    errors_parser.add_argument('--error-type', help='Filter by error type')
    errors_parser.add_argument('--limit', type=int, default=100)
    errors_parser.add_argument('--offset', type=int, default=0)
    errors_parser.set_defaults(func=cmd_errors)
    
    # stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.set_defaults(func=cmd_stats)
    
    return parser


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for CLI."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    if not parsed_args.command:
        parser.print_help()
        return 0
    
    if hasattr(parsed_args, 'func'):
        return parsed_args.func(parsed_args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
