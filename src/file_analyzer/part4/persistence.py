"""
PART 4: Persistence Layer (SQLite)

This module implements:
- Local SQLite database for storing analysis records
- Append-only record storage (immutable)
- Case and session organization
- Referential integrity between entities
- Provenance tracking (timestamps, versions)
- Corruption/partial write detection
"""

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from .schemas import (
    SCHEMA_VERSION,
    ValidationError,
    validate_schema,
)


class DatabaseError(Exception):
    """Base exception for database operations."""
    pass


class IntegrityError(DatabaseError):
    """Raised when data integrity is compromised."""
    pass


class PartialWriteError(DatabaseError):
    """Raised when a partial write is detected."""
    pass


# Tool version for provenance
TOOL_VERSION = "1.0.0"


def generate_case_id() -> str:
    """Generate a unique case ID."""
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return f"SES-{uuid.uuid4().hex[:8].upper()}"


def generate_record_id() -> str:
    """Generate a unique record ID."""
    return f"REC-{uuid.uuid4().hex[:12].upper()}"


def generate_error_id() -> str:
    """Generate a unique error ID."""
    return f"ERR-{uuid.uuid4().hex[:8].upper()}"


def compute_checksum(data: str) -> str:
    """Compute SHA-256 checksum of data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


class AnalysisDatabase:
    """
    SQLite-based persistence layer for file analysis records.
    
    Features:
    - Append-only record storage (immutable)
    - Case and session organization
    - Referential integrity
    - Provenance tracking
    - Corruption detection
    """
    
    # SQL for creating database schema
    SCHEMA_SQL = """
    -- Cases table
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        metadata_json TEXT,
        checksum TEXT NOT NULL
    );
    
    -- Sessions table
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        name TEXT,
        description TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        metadata_json TEXT,
        checksum TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
    );
    
    -- Analysis records table (immutable, append-only)
    CREATE TABLE IF NOT EXISTS analysis_records (
        record_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        sha256_hash TEXT NOT NULL,
        semantic_file_type TEXT NOT NULL,
        part1_json TEXT NOT NULL,
        part2_json TEXT NOT NULL,
        part3_json TEXT NOT NULL,
        risk_score REAL NOT NULL,
        severity TEXT NOT NULL,
        created_at TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        checksum TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    );
    
    -- Findings table (derived from PART 2)
    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        semantic_file_type TEXT NOT NULL,
        byte_offset_start INTEGER,
        byte_offset_end INTEGER,
        confidence TEXT NOT NULL,
        extracted_value_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (record_id) REFERENCES analysis_records(record_id)
    );
    
    -- Heuristic results table (derived from PART 3)
    CREATE TABLE IF NOT EXISTS heuristic_results (
        heuristic_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        heuristic_key TEXT NOT NULL,
        name TEXT NOT NULL,
        triggered INTEGER NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        weight REAL NOT NULL,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (record_id) REFERENCES analysis_records(record_id)
    );
    
    -- Rule detections table (derived from PART 3)
    CREATE TABLE IF NOT EXISTS rule_detections (
        detection_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        matched_strings_json TEXT,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (record_id) REFERENCES analysis_records(record_id)
    );
    
    -- Correlations table (session-level)
    CREATE TABLE IF NOT EXISTS correlations (
        correlation_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        correlation_type TEXT NOT NULL,
        file_ids_json TEXT NOT NULL,
        similarity_score REAL,
        confidence TEXT NOT NULL,
        severity TEXT NOT NULL,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    );
    
    -- Errors table
    CREATE TABLE IF NOT EXISTS errors (
        error_id TEXT PRIMARY KEY,
        error_type TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        file_id TEXT,
        session_id TEXT,
        case_id TEXT,
        context_json TEXT,
        stack_trace TEXT,
        recoverable INTEGER NOT NULL DEFAULT 1
    );
    
    -- Provenance table (tracks schema/tool versions)
    CREATE TABLE IF NOT EXISTS provenance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        library_versions_json TEXT,
        checksum TEXT NOT NULL
    );
    
    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_sessions_case_id ON sessions(case_id);
    CREATE INDEX IF NOT EXISTS idx_records_session_id ON analysis_records(session_id);
    CREATE INDEX IF NOT EXISTS idx_records_sha256 ON analysis_records(sha256_hash);
    CREATE INDEX IF NOT EXISTS idx_records_severity ON analysis_records(severity);
    CREATE INDEX IF NOT EXISTS idx_records_file_type ON analysis_records(semantic_file_type);
    CREATE INDEX IF NOT EXISTS idx_records_created_at ON analysis_records(created_at);
    CREATE INDEX IF NOT EXISTS idx_findings_record_id ON findings(record_id);
    CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
    CREATE INDEX IF NOT EXISTS idx_heuristics_record_id ON heuristic_results(record_id);
    CREATE INDEX IF NOT EXISTS idx_heuristics_triggered ON heuristic_results(triggered);
    CREATE INDEX IF NOT EXISTS idx_detections_record_id ON rule_detections(record_id);
    CREATE INDEX IF NOT EXISTS idx_correlations_session_id ON correlations(session_id);
    CREATE INDEX IF NOT EXISTS idx_errors_session_id ON errors(session_id);
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path).absolute()
        self._local = threading.local()
        self._initialized = False
        
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._local.connection.row_factory = sqlite3.Row
            # Enable foreign keys
            self._local.connection.execute("PRAGMA foreign_keys = ON")
        return self._local.connection
    
    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for database transactions."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Transaction failed: {e}") from e
    
    def _init_database(self) -> None:
        """Initialize database schema."""
        if self._initialized:
            return
        
        with self._transaction() as cursor:
            cursor.executescript(self.SCHEMA_SQL)
        
        self._initialized = True
    
    def _verify_checksum(self, data_json: str, stored_checksum: str) -> bool:
        """Verify data integrity using checksum."""
        computed = compute_checksum(data_json)
        return computed == stored_checksum
    
    def _build_where_clause(
        self,
        conditions: List[Tuple[str, Any]]
    ) -> Tuple[str, List[Any]]:
        """
        Build a WHERE clause safely from conditions.
        
        This method ensures SQL injection safety by:
        1. Only allowing predefined column names
        2. Using parameterized queries for all values
        
        Args:
            conditions: List of (column_name, value) tuples.
                       If value is None, the condition is skipped.
        
        Returns:
            Tuple of (where_clause_string, params_list)
        """
        # Define allowed column names to prevent SQL injection
        allowed_columns = frozenset({
            'case_id', 'session_id', 'record_id', 'status', 'severity',
            'semantic_file_type', 'finding_type', 'error_type', 'triggered',
            'heuristic_key', 'rule_id', 'file_type', 'created_at'
        })
        
        where_parts = []
        params = []
        
        for column, value in conditions:
            if value is None:
                continue
            
            # Validate column name
            if column not in allowed_columns:
                raise DatabaseError(f"Invalid column name: {column}")
            
            where_parts.append(f"{column} = ?")
            params.append(value)
        
        if where_parts:
            return "WHERE " + " AND ".join(where_parts), params
        return "", []
    
    # ========================================================================
    # CASE OPERATIONS
    # ========================================================================
    
    def create_case(
        self,
        name: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new investigation case.
        
        Args:
            name: Case name.
            description: Case description.
            metadata: Additional metadata.
        
        Returns:
            The generated case_id.
        """
        case_id = generate_case_id()
        now = datetime.utcnow().isoformat()
        metadata_json = json.dumps(metadata or {})
        
        # Compute checksum
        checksum_data = json.dumps({
            "case_id": case_id,
            "name": name,
            "description": description,
            "metadata": metadata or {},
        }, sort_keys=True)
        checksum = compute_checksum(checksum_data)
        
        with self._transaction() as cursor:
            cursor.execute("""
                INSERT INTO cases (case_id, name, description, created_at, updated_at, status, metadata_json, checksum)
                VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
            """, (case_id, name, description, now, now, metadata_json, checksum))
            
            # Record provenance
            cursor.execute("""
                INSERT INTO provenance (entity_type, entity_id, created_at, schema_version, tool_version, checksum)
                VALUES ('case', ?, ?, ?, ?, ?)
            """, (case_id, now, SCHEMA_VERSION, TOOL_VERSION, checksum))
        
        return case_id
    
    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a case by ID."""
        with self._transaction() as cursor:
            cursor.execute("""
                SELECT case_id, name, description, created_at, updated_at, status, metadata_json, checksum
                FROM cases WHERE case_id = ?
            """, (case_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Verify integrity
            stored_checksum = row['checksum']
            checksum_data = json.dumps({
                "case_id": row['case_id'],
                "name": row['name'],
                "description": row['description'] or "",
                "metadata": json.loads(row['metadata_json'] or '{}'),
            }, sort_keys=True)
            
            if not self._verify_checksum(checksum_data, stored_checksum):
                raise IntegrityError(f"Case {case_id} data integrity check failed")
            
            return {
                "case_id": row['case_id'],
                "name": row['name'],
                "description": row['description'],
                "created_at": row['created_at'],
                "updated_at": row['updated_at'],
                "status": row['status'],
                "metadata": json.loads(row['metadata_json'] or '{}'),
            }
    
    def list_cases(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List cases with optional filtering."""
        with self._transaction() as cursor:
            if status:
                cursor.execute("""
                    SELECT case_id, name, description, created_at, updated_at, status, metadata_json
                    FROM cases WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (status, limit, offset))
            else:
                cursor.execute("""
                    SELECT case_id, name, description, created_at, updated_at, status, metadata_json
                    FROM cases
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            
            return [
                {
                    "case_id": row['case_id'],
                    "name": row['name'],
                    "description": row['description'],
                    "created_at": row['created_at'],
                    "updated_at": row['updated_at'],
                    "status": row['status'],
                    "metadata": json.loads(row['metadata_json'] or '{}'),
                }
                for row in cursor.fetchall()
            ]
    
    # ========================================================================
    # SESSION OPERATIONS
    # ========================================================================
    
    def create_session(
        self,
        case_id: str,
        name: str = "",
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new analysis session within a case.
        
        Args:
            case_id: Parent case ID.
            name: Session name.
            description: Session description.
            metadata: Additional metadata.
        
        Returns:
            The generated session_id.
        """
        # Verify case exists
        if not self.get_case(case_id):
            raise DatabaseError(f"Case {case_id} not found")
        
        session_id = generate_session_id()
        now = datetime.utcnow().isoformat()
        metadata_json = json.dumps(metadata or {})
        
        # Compute checksum
        checksum_data = json.dumps({
            "session_id": session_id,
            "case_id": case_id,
            "name": name,
            "description": description,
            "metadata": metadata or {},
        }, sort_keys=True)
        checksum = compute_checksum(checksum_data)
        
        with self._transaction() as cursor:
            cursor.execute("""
                INSERT INTO sessions (session_id, case_id, name, description, created_at, updated_at, status, metadata_json, checksum)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """, (session_id, case_id, name, description, now, now, metadata_json, checksum))
            
            # Update case updated_at
            cursor.execute("""
                UPDATE cases SET updated_at = ? WHERE case_id = ?
            """, (now, case_id))
            
            # Record provenance
            cursor.execute("""
                INSERT INTO provenance (entity_type, entity_id, created_at, schema_version, tool_version, checksum)
                VALUES ('session', ?, ?, ?, ?, ?)
            """, (session_id, now, SCHEMA_VERSION, TOOL_VERSION, checksum))
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get a session by ID."""
        with self._transaction() as cursor:
            cursor.execute("""
                SELECT session_id, case_id, name, description, created_at, updated_at, status, metadata_json, checksum
                FROM sessions WHERE session_id = ?
            """, (session_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return {
                "session_id": row['session_id'],
                "case_id": row['case_id'],
                "name": row['name'],
                "description": row['description'],
                "created_at": row['created_at'],
                "updated_at": row['updated_at'],
                "status": row['status'],
                "metadata": json.loads(row['metadata_json'] or '{}'),
            }
    
    def list_sessions(
        self,
        case_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List sessions with optional filtering."""
        with self._transaction() as cursor:
            conditions = []
            params = []
            
            if case_id:
                conditions.append("case_id = ?")
                params.append(case_id)
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            cursor.execute(f"""
                SELECT session_id, case_id, name, description, created_at, updated_at, status, metadata_json
                FROM sessions {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            return [
                {
                    "session_id": row['session_id'],
                    "case_id": row['case_id'],
                    "name": row['name'],
                    "description": row['description'],
                    "created_at": row['created_at'],
                    "updated_at": row['updated_at'],
                    "status": row['status'],
                    "metadata": json.loads(row['metadata_json'] or '{}'),
                }
                for row in cursor.fetchall()
            ]
    
    # ========================================================================
    # ANALYSIS RECORD OPERATIONS (APPEND-ONLY)
    # ========================================================================
    
    def import_analysis(
        self,
        session_id: str,
        part1_results: Dict[str, Any],
        part2_results: Dict[str, Any],
        part3_results: Dict[str, Any]
    ) -> str:
        """
        Import analysis results from PART 1, 2, and 3.
        
        This is an append-only operation. Records cannot be modified or deleted.
        
        Args:
            session_id: Session to add the record to.
            part1_results: PART 1 analysis output.
            part2_results: PART 2 analysis output.
            part3_results: PART 3 analysis output.
        
        Returns:
            The generated record_id.
        """
        # Verify session exists
        if not self.get_session(session_id):
            raise DatabaseError(f"Session {session_id} not found")
        
        record_id = generate_record_id()
        now = datetime.utcnow().isoformat()
        
        # Extract key data from PART 1
        file_info = part1_results.get('file_info', {})
        file_path = file_info.get('file_path', '')
        file_name = file_info.get('file_name', '')
        file_size = file_info.get('file_size', 0)
        
        crypto = part1_results.get('cryptographic_identity', {})
        hashes = crypto.get('hashes', [])
        sha256_hash = ''
        for h in hashes:
            if h.get('evidence', {}).get('algorithm') == 'SHA256':
                sha256_hash = h.get('output_value', '')
                break
        
        semantic = part1_results.get('semantic_file_type', {}).get('output_value', {})
        semantic_file_type = semantic.get('semantic_file_type', 'UNKNOWN')
        
        # Extract key data from PART 3
        risk_score = part3_results.get('risk_score', {}).get('normalized_score', 0.0)
        severity = part3_results.get('risk_score', {}).get('severity', 'informational')
        
        # Serialize JSON data
        part1_json = json.dumps(part1_results, default=str, sort_keys=True)
        part2_json = json.dumps(part2_results, default=str, sort_keys=True)
        part3_json = json.dumps(part3_results, default=str, sort_keys=True)
        
        # Create provenance data
        provenance = {
            "created_at": now,
            "schema_version": SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "analyzer_versions": {
                "part1": "1.0.0",
                "part2": "1.0.0",
                "part3": "1.0.0",
            },
        }
        provenance_json = json.dumps(provenance, sort_keys=True)
        
        # Compute checksum for integrity verification
        checksum_data = json.dumps({
            "record_id": record_id,
            "part1": part1_results,
            "part2": part2_results,
            "part3": part3_results,
        }, default=str, sort_keys=True)
        checksum = compute_checksum(checksum_data)
        
        with self._transaction() as cursor:
            # Insert main record
            cursor.execute("""
                INSERT INTO analysis_records (
                    record_id, session_id, file_path, file_name, file_size,
                    sha256_hash, semantic_file_type, part1_json, part2_json, part3_json,
                    risk_score, severity, created_at, schema_version, tool_version,
                    provenance_json, checksum
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record_id, session_id, file_path, file_name, file_size,
                sha256_hash, semantic_file_type, part1_json, part2_json, part3_json,
                risk_score, severity, now, SCHEMA_VERSION, TOOL_VERSION,
                provenance_json, checksum
            ))
            
            # Insert findings from PART 2
            for category in ['universal', 'container_level', 'file_type_specific']:
                findings = part2_results.get(category, [])
                for finding in findings:
                    if isinstance(finding, dict) and 'finding_id' in finding:
                        cursor.execute("""
                            INSERT INTO findings (
                                finding_id, record_id, finding_type, semantic_file_type,
                                byte_offset_start, byte_offset_end, confidence,
                                extracted_value_json, created_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            finding.get('finding_id'),
                            record_id,
                            finding.get('finding_type', ''),
                            finding.get('semantic_file_type', ''),
                            finding.get('byte_offset_start'),
                            finding.get('byte_offset_end'),
                            finding.get('confidence', 'LOW'),
                            json.dumps(finding.get('extracted_value'), default=str),
                            now
                        ))
            
            # Insert heuristic results from PART 3
            heuristics = part3_results.get('heuristics', {})
            for h in heuristics.get('triggered_heuristics', []):
                if isinstance(h, dict) and 'id' in h:
                    cursor.execute("""
                        INSERT INTO heuristic_results (
                            heuristic_id, record_id, heuristic_key, name,
                            triggered, severity, confidence, weight,
                            explanation, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        h.get('id'),
                        record_id,
                        h.get('heuristic_key', ''),
                        h.get('name', ''),
                        1,
                        h.get('severity', 'informational'),
                        h.get('confidence', 'LOW'),
                        h.get('weight', 0),
                        h.get('explanation', ''),
                        now
                    ))
            
            for h in heuristics.get('failed_heuristics', []):
                if isinstance(h, dict) and 'id' in h:
                    cursor.execute("""
                        INSERT INTO heuristic_results (
                            heuristic_id, record_id, heuristic_key, name,
                            triggered, severity, confidence, weight,
                            explanation, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        h.get('id'),
                        record_id,
                        h.get('heuristic_key', ''),
                        h.get('name', ''),
                        0,
                        h.get('severity', 'informational'),
                        h.get('confidence', 'LOW'),
                        0,
                        h.get('failure_reason', ''),
                        now
                    ))
            
            # Insert rule detections from PART 3
            rule_engine = part3_results.get('rule_engine', {})
            for detection in rule_engine.get('yara_detections', []):
                if isinstance(detection, dict) and 'id' in detection:
                    cursor.execute("""
                        INSERT INTO rule_detections (
                            detection_id, record_id, rule_id, rule_type,
                            severity, confidence, matched_strings_json,
                            explanation, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        detection.get('id'),
                        record_id,
                        detection.get('rule_id', ''),
                        detection.get('type', 'rule'),
                        detection.get('severity', 'informational'),
                        detection.get('confidence', 'LOW'),
                        json.dumps(detection.get('matched_strings', [])),
                        detection.get('explanation', ''),
                        now
                    ))
            
            # Update session updated_at
            cursor.execute("""
                UPDATE sessions SET updated_at = ? WHERE session_id = ?
            """, (now, session_id))
            
            # Record provenance
            cursor.execute("""
                INSERT INTO provenance (
                    entity_type, entity_id, created_at, schema_version,
                    tool_version, checksum
                )
                VALUES ('record', ?, ?, ?, ?, ?)
            """, (record_id, now, SCHEMA_VERSION, TOOL_VERSION, checksum))
        
        return record_id
    
    def get_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Get an analysis record by ID with full data."""
        with self._transaction() as cursor:
            cursor.execute("""
                SELECT record_id, session_id, file_path, file_name, file_size,
                       sha256_hash, semantic_file_type, part1_json, part2_json, part3_json,
                       risk_score, severity, created_at, schema_version, tool_version,
                       provenance_json, checksum
                FROM analysis_records WHERE record_id = ?
            """, (record_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Verify integrity
            checksum_data = json.dumps({
                "record_id": row['record_id'],
                "part1": json.loads(row['part1_json']),
                "part2": json.loads(row['part2_json']),
                "part3": json.loads(row['part3_json']),
            }, default=str, sort_keys=True)
            
            if not self._verify_checksum(checksum_data, row['checksum']):
                raise IntegrityError(f"Record {record_id} data integrity check failed")
            
            return {
                "record_id": row['record_id'],
                "session_id": row['session_id'],
                "file_path": row['file_path'],
                "file_name": row['file_name'],
                "file_size": row['file_size'],
                "sha256_hash": row['sha256_hash'],
                "semantic_file_type": row['semantic_file_type'],
                "part1": json.loads(row['part1_json']),
                "part2": json.loads(row['part2_json']),
                "part3": json.loads(row['part3_json']),
                "risk_score": row['risk_score'],
                "severity": row['severity'],
                "created_at": row['created_at'],
                "schema_version": row['schema_version'],
                "tool_version": row['tool_version'],
                "provenance": json.loads(row['provenance_json']),
            }
    
    def query_records(
        self,
        session_id: Optional[str] = None,
        file_type: Optional[str] = None,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query analysis records with filtering."""
        with self._transaction() as cursor:
            conditions = []
            params = []
            
            if session_id:
                conditions.append("session_id = ?")
                params.append(session_id)
            if file_type:
                conditions.append("semantic_file_type = ?")
                params.append(file_type)
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            if min_score is not None:
                conditions.append("risk_score >= ?")
                params.append(min_score)
            if max_score is not None:
                conditions.append("risk_score <= ?")
                params.append(max_score)
            if from_time:
                conditions.append("created_at >= ?")
                params.append(from_time)
            if to_time:
                conditions.append("created_at <= ?")
                params.append(to_time)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            cursor.execute(f"""
                SELECT record_id, session_id, file_path, file_name, file_size,
                       sha256_hash, semantic_file_type, risk_score, severity,
                       created_at, schema_version
                FROM analysis_records {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            return [
                {
                    "record_id": row['record_id'],
                    "session_id": row['session_id'],
                    "file_path": row['file_path'],
                    "file_name": row['file_name'],
                    "file_size": row['file_size'],
                    "sha256_hash": row['sha256_hash'],
                    "semantic_file_type": row['semantic_file_type'],
                    "risk_score": row['risk_score'],
                    "severity": row['severity'],
                    "created_at": row['created_at'],
                    "schema_version": row['schema_version'],
                }
                for row in cursor.fetchall()
            ]
    
    def get_findings(
        self,
        record_id: Optional[str] = None,
        finding_type: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query findings with optional filtering."""
        with self._transaction() as cursor:
            conditions = []
            params = []
            
            if record_id:
                conditions.append("record_id = ?")
                params.append(record_id)
            if finding_type:
                conditions.append("finding_type = ?")
                params.append(finding_type)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            cursor.execute(f"""
                SELECT finding_id, record_id, finding_type, semantic_file_type,
                       byte_offset_start, byte_offset_end, confidence,
                       extracted_value_json, created_at
                FROM findings {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            return [
                {
                    "finding_id": row['finding_id'],
                    "record_id": row['record_id'],
                    "finding_type": row['finding_type'],
                    "semantic_file_type": row['semantic_file_type'],
                    "byte_offset_start": row['byte_offset_start'],
                    "byte_offset_end": row['byte_offset_end'],
                    "confidence": row['confidence'],
                    "extracted_value": json.loads(row['extracted_value_json']) if row['extracted_value_json'] else None,
                    "created_at": row['created_at'],
                }
                for row in cursor.fetchall()
            ]
    
    def get_heuristics(
        self,
        record_id: Optional[str] = None,
        triggered_only: bool = False,
        severity: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query heuristic results with optional filtering."""
        with self._transaction() as cursor:
            conditions = []
            params = []
            
            if record_id:
                conditions.append("record_id = ?")
                params.append(record_id)
            if triggered_only:
                conditions.append("triggered = 1")
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            cursor.execute(f"""
                SELECT heuristic_id, record_id, heuristic_key, name,
                       triggered, severity, confidence, weight,
                       explanation, created_at
                FROM heuristic_results {where_clause}
                ORDER BY weight DESC, created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            return [
                {
                    "heuristic_id": row['heuristic_id'],
                    "record_id": row['record_id'],
                    "heuristic_key": row['heuristic_key'],
                    "name": row['name'],
                    "triggered": bool(row['triggered']),
                    "severity": row['severity'],
                    "confidence": row['confidence'],
                    "weight": row['weight'],
                    "explanation": row['explanation'],
                    "created_at": row['created_at'],
                }
                for row in cursor.fetchall()
            ]
    
    # ========================================================================
    # ERROR LOGGING
    # ========================================================================
    
    def log_error(
        self,
        error_type: str,
        message: str,
        file_id: Optional[str] = None,
        session_id: Optional[str] = None,
        case_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
        recoverable: bool = True
    ) -> str:
        """Log an error or failure."""
        error_id = generate_error_id()
        now = datetime.utcnow().isoformat()
        
        with self._transaction() as cursor:
            cursor.execute("""
                INSERT INTO errors (
                    error_id, error_type, message, timestamp,
                    file_id, session_id, case_id, context_json,
                    stack_trace, recoverable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                error_id, error_type, message, now,
                file_id, session_id, case_id,
                json.dumps(context or {}),
                stack_trace,
                1 if recoverable else 0
            ))
        
        return error_id
    
    def get_errors(
        self,
        session_id: Optional[str] = None,
        error_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query errors with optional filtering."""
        with self._transaction() as cursor:
            conditions = []
            params = []
            
            if session_id:
                conditions.append("session_id = ?")
                params.append(session_id)
            if error_type:
                conditions.append("error_type = ?")
                params.append(error_type)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            cursor.execute(f"""
                SELECT error_id, error_type, message, timestamp,
                       file_id, session_id, case_id, context_json,
                       stack_trace, recoverable
                FROM errors {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            return [
                {
                    "error_id": row['error_id'],
                    "error_type": row['error_type'],
                    "message": row['message'],
                    "timestamp": row['timestamp'],
                    "file_id": row['file_id'],
                    "session_id": row['session_id'],
                    "case_id": row['case_id'],
                    "context": json.loads(row['context_json']) if row['context_json'] else {},
                    "stack_trace": row['stack_trace'],
                    "recoverable": bool(row['recoverable']),
                }
                for row in cursor.fetchall()
            ]
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self._transaction() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM cases")
            case_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM sessions")
            session_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM analysis_records")
            record_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM findings")
            finding_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM heuristic_results WHERE triggered = 1")
            triggered_heuristics = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM errors")
            error_count = cursor.fetchone()['count']
            
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM analysis_records 
                GROUP BY severity
            """)
            severity_dist = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            return {
                "case_count": case_count,
                "session_count": session_count,
                "record_count": record_count,
                "finding_count": finding_count,
                "triggered_heuristics": triggered_heuristics,
                "error_count": error_count,
                "severity_distribution": severity_dist,
                "schema_version": SCHEMA_VERSION,
                "tool_version": TOOL_VERSION,
            }
    
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
