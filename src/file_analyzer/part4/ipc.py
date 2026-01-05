"""
PART 4: IPC Contracts (Python ↔ Electron)

This module defines explicit IPC request/response schemas for communication
between Python backend and Electron frontend.

Features:
- Explicit request/response schemas
- Read-only operations
- Schema validation on every message
- Error propagation without suppression
"""

import json
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .persistence import AnalysisDatabase, DatabaseError, IntegrityError
from .schemas import validate_schema, ValidationError, SCHEMA_VERSION


class IPCMethod(str, Enum):
    """Available IPC methods."""
    # Case operations
    LIST_CASES = "list_cases"
    GET_CASE = "get_case"
    
    # Session operations
    LIST_SESSIONS = "list_sessions"
    GET_SESSION = "get_session"
    
    # Record operations
    LIST_RECORDS = "list_records"
    GET_RECORD = "get_record"
    GET_RECORD_SUMMARY = "get_record_summary"
    
    # Finding operations
    LIST_FINDINGS = "list_findings"
    GET_FINDING = "get_finding"
    
    # Heuristic operations
    LIST_HEURISTICS = "list_heuristics"
    
    # Correlation operations
    GET_CORRELATIONS = "get_correlations"
    
    # Timeline operations
    GET_TIMELINE = "get_timeline"
    
    # Statistics
    GET_STATISTICS = "get_statistics"
    
    # Error operations
    LIST_ERRORS = "list_errors"
    
    # Health check
    PING = "ping"


class IPCErrorCode(str, Enum):
    """IPC error codes."""
    SUCCESS = "success"
    INVALID_REQUEST = "invalid_request"
    VALIDATION_ERROR = "validation_error"
    NOT_FOUND = "not_found"
    DATABASE_ERROR = "database_error"
    INTEGRITY_ERROR = "integrity_error"
    INTERNAL_ERROR = "internal_error"


# ============================================================================
# REQUEST/RESPONSE SCHEMAS
# ============================================================================

IPC_REQUEST_SCHEMA = {
    "type": "object",
    "required": ["id", "method"],
    "properties": {
        "id": {"type": "string", "description": "Unique request identifier"},
        "method": {"type": "string", "description": "IPC method to invoke"},
        "params": {"type": "object", "description": "Method parameters"},
        "timestamp": {"type": "string", "format": "date-time"},
    },
}


IPC_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["id", "success"],
    "properties": {
        "id": {"type": "string", "description": "Request identifier (echoed)"},
        "success": {"type": "boolean", "description": "Whether the request succeeded"},
        "data": {"type": ["object", "array", "null"], "description": "Response data"},
        "error": {
            "type": ["object", "null"],
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "details": {"type": ["object", "null"]},
            },
        },
        "timestamp": {"type": "string", "format": "date-time"},
        "schema_version": {"type": "string"},
    },
}


# Parameter schemas for each method
METHOD_PARAMS_SCHEMAS = {
    IPCMethod.LIST_CASES: {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["open", "closed", "archived"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.GET_CASE: {
        "type": "object",
        "required": ["case_id"],
        "properties": {
            "case_id": {"type": "string", "pattern": "^CASE-[A-Z0-9]{8}$"},
        },
    },
    IPCMethod.LIST_SESSIONS: {
        "type": "object",
        "properties": {
            "case_id": {"type": "string"},
            "status": {"type": "string", "enum": ["active", "completed", "archived"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.GET_SESSION: {
        "type": "object",
        "required": ["session_id"],
        "properties": {
            "session_id": {"type": "string", "pattern": "^SES-[A-Z0-9]{8}$"},
        },
    },
    IPCMethod.LIST_RECORDS: {
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "file_type": {"type": "string"},
            "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
            "min_score": {"type": "number", "minimum": 0, "maximum": 100},
            "max_score": {"type": "number", "minimum": 0, "maximum": 100},
            "from_time": {"type": "string", "format": "date-time"},
            "to_time": {"type": "string", "format": "date-time"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.GET_RECORD: {
        "type": "object",
        "required": ["record_id"],
        "properties": {
            "record_id": {"type": "string", "pattern": "^REC-[A-Z0-9]{12}$"},
        },
    },
    IPCMethod.GET_RECORD_SUMMARY: {
        "type": "object",
        "required": ["record_id"],
        "properties": {
            "record_id": {"type": "string", "pattern": "^REC-[A-Z0-9]{12}$"},
        },
    },
    IPCMethod.LIST_FINDINGS: {
        "type": "object",
        "properties": {
            "record_id": {"type": "string"},
            "finding_type": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.GET_FINDING: {
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": {"type": "string"},
        },
    },
    IPCMethod.LIST_HEURISTICS: {
        "type": "object",
        "properties": {
            "record_id": {"type": "string"},
            "triggered_only": {"type": "boolean"},
            "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.GET_CORRELATIONS: {
        "type": "object",
        "required": ["session_id"],
        "properties": {
            "session_id": {"type": "string"},
        },
    },
    IPCMethod.GET_TIMELINE: {
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "case_id": {"type": "string"},
            "from_time": {"type": "string", "format": "date-time"},
            "to_time": {"type": "string", "format": "date-time"},
        },
    },
    IPCMethod.GET_STATISTICS: {
        "type": "object",
        "properties": {},
    },
    IPCMethod.LIST_ERRORS: {
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "error_type": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    IPCMethod.PING: {
        "type": "object",
        "properties": {},
    },
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class IPCRequest:
    """IPC request message."""
    id: str
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPCRequest':
        return cls(
            id=data.get('id', ''),
            method=data.get('method', ''),
            params=data.get('params', {}),
            timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'IPCRequest':
        return cls.from_dict(json.loads(json_str))


@dataclass
class IPCError:
    """IPC error details."""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IPCResponse:
    """IPC response message."""
    id: str
    success: bool
    data: Optional[Union[Dict[str, Any], List[Any]]] = None
    error: Optional[IPCError] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    schema_version: str = SCHEMA_VERSION
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'id': self.id,
            'success': self.success,
            'data': self.data,
            'error': self.error.to_dict() if self.error else None,
            'timestamp': self.timestamp,
            'schema_version': self.schema_version,
        }
        return result
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def success_response(cls, request_id: str, data: Any) -> 'IPCResponse':
        return cls(id=request_id, success=True, data=data)
    
    @classmethod
    def error_response(
        cls,
        request_id: str,
        code: IPCErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> 'IPCResponse':
        return cls(
            id=request_id,
            success=False,
            error=IPCError(code=code.value, message=message, details=details)
        )


# ============================================================================
# IPC HANDLER
# ============================================================================

class IPCHandler:
    """
    IPC message handler for Python ↔ Electron communication.
    
    All operations are read-only. Schema validation is performed on
    every message. Errors are propagated without suppression.
    """
    
    def __init__(self, db: AnalysisDatabase):
        """
        Initialize the IPC handler.
        
        Args:
            db: Database instance for data access.
        """
        self.db = db
        
        # Method dispatch table
        self._handlers = {
            IPCMethod.LIST_CASES: self._handle_list_cases,
            IPCMethod.GET_CASE: self._handle_get_case,
            IPCMethod.LIST_SESSIONS: self._handle_list_sessions,
            IPCMethod.GET_SESSION: self._handle_get_session,
            IPCMethod.LIST_RECORDS: self._handle_list_records,
            IPCMethod.GET_RECORD: self._handle_get_record,
            IPCMethod.GET_RECORD_SUMMARY: self._handle_get_record_summary,
            IPCMethod.LIST_FINDINGS: self._handle_list_findings,
            IPCMethod.LIST_HEURISTICS: self._handle_list_heuristics,
            IPCMethod.GET_CORRELATIONS: self._handle_get_correlations,
            IPCMethod.GET_TIMELINE: self._handle_get_timeline,
            IPCMethod.GET_STATISTICS: self._handle_get_statistics,
            IPCMethod.LIST_ERRORS: self._handle_list_errors,
            IPCMethod.PING: self._handle_ping,
        }
    
    def handle_request(self, request: Union[IPCRequest, Dict[str, Any], str]) -> IPCResponse:
        """
        Handle an IPC request.
        
        Args:
            request: Request as IPCRequest, dict, or JSON string.
        
        Returns:
            IPCResponse with result or error.
        """
        # Parse request
        if isinstance(request, str):
            try:
                request = IPCRequest.from_json(request)
            except json.JSONDecodeError as e:
                return IPCResponse.error_response(
                    request_id="unknown",
                    code=IPCErrorCode.INVALID_REQUEST,
                    message=f"Invalid JSON: {e}",
                )
        elif isinstance(request, dict):
            request = IPCRequest.from_dict(request)
        
        # Validate request structure
        if not request.id:
            return IPCResponse.error_response(
                request_id="unknown",
                code=IPCErrorCode.INVALID_REQUEST,
                message="Request ID is required",
            )
        
        if not request.method:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.INVALID_REQUEST,
                message="Method is required",
            )
        
        # Find method
        try:
            method = IPCMethod(request.method)
        except ValueError:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.INVALID_REQUEST,
                message=f"Unknown method: {request.method}",
            )
        
        # Validate parameters
        if method in METHOD_PARAMS_SCHEMAS:
            try:
                from .schemas import validate_with_schema
                validate_with_schema(request.params, METHOD_PARAMS_SCHEMAS[method], "params")
            except ValidationError as e:
                return IPCResponse.error_response(
                    request_id=request.id,
                    code=IPCErrorCode.VALIDATION_ERROR,
                    message=str(e),
                    details={"path": e.path, "value": str(e.value)[:100]},
                )
        
        # Dispatch to handler
        handler = self._handlers.get(method)
        if not handler:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.INVALID_REQUEST,
                message=f"No handler for method: {method}",
            )
        
        try:
            result = handler(request.params)
            return IPCResponse.success_response(request.id, result)
        except IntegrityError as e:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.INTEGRITY_ERROR,
                message=str(e),
            )
        except DatabaseError as e:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.DATABASE_ERROR,
                message=str(e),
            )
        except Exception as e:
            return IPCResponse.error_response(
                request_id=request.id,
                code=IPCErrorCode.INTERNAL_ERROR,
                message=str(e),
                details={"traceback": traceback.format_exc()},
            )
    
    def handle_json(self, json_request: str) -> str:
        """
        Handle a JSON-encoded request and return JSON response.
        
        Args:
            json_request: JSON-encoded request string.
        
        Returns:
            JSON-encoded response string.
        """
        response = self.handle_request(json_request)
        return response.to_json()
    
    # ========================================================================
    # HANDLERS
    # ========================================================================
    
    def _handle_list_cases(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_cases request."""
        return self.db.list_cases(
            status=params.get('status'),
            limit=params.get('limit', 100),
            offset=params.get('offset', 0),
        )
    
    def _handle_get_case(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle get_case request."""
        case = self.db.get_case(params['case_id'])
        if not case:
            raise DatabaseError(f"Case not found: {params['case_id']}")
        return case
    
    def _handle_list_sessions(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_sessions request."""
        return self.db.list_sessions(
            case_id=params.get('case_id'),
            status=params.get('status'),
            limit=params.get('limit', 100),
            offset=params.get('offset', 0),
        )
    
    def _handle_get_session(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle get_session request."""
        session = self.db.get_session(params['session_id'])
        if not session:
            raise DatabaseError(f"Session not found: {params['session_id']}")
        return session
    
    def _handle_list_records(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_records request."""
        return self.db.query_records(
            session_id=params.get('session_id'),
            file_type=params.get('file_type'),
            severity=params.get('severity'),
            min_score=params.get('min_score'),
            max_score=params.get('max_score'),
            from_time=params.get('from_time'),
            to_time=params.get('to_time'),
            limit=params.get('limit', 100),
            offset=params.get('offset', 0),
        )
    
    def _handle_get_record(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle get_record request."""
        record = self.db.get_record(params['record_id'])
        if not record:
            raise DatabaseError(f"Record not found: {params['record_id']}")
        return record
    
    def _handle_get_record_summary(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle get_record_summary request (lightweight version)."""
        record = self.db.get_record(params['record_id'])
        if not record:
            raise DatabaseError(f"Record not found: {params['record_id']}")
        
        # Return summary without full JSON data
        return {
            "record_id": record['record_id'],
            "session_id": record['session_id'],
            "file_path": record['file_path'],
            "file_name": record['file_name'],
            "file_size": record['file_size'],
            "sha256_hash": record['sha256_hash'],
            "semantic_file_type": record['semantic_file_type'],
            "risk_score": record['risk_score'],
            "severity": record['severity'],
            "created_at": record['created_at'],
            "schema_version": record['schema_version'],
            "summary": record['part3'].get('summary', {}) if 'part3' in record else {},
        }
    
    def _handle_list_findings(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_findings request."""
        return self.db.get_findings(
            record_id=params.get('record_id'),
            finding_type=params.get('finding_type'),
            limit=params.get('limit', 1000),
            offset=params.get('offset', 0),
        )
    
    def _handle_list_heuristics(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_heuristics request."""
        return self.db.get_heuristics(
            record_id=params.get('record_id'),
            triggered_only=params.get('triggered_only', False),
            severity=params.get('severity'),
            limit=params.get('limit', 1000),
            offset=params.get('offset', 0),
        )
    
    def _handle_get_correlations(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_correlations request."""
        # Get all records in the session
        records = self.db.query_records(
            session_id=params['session_id'],
            limit=1000,
        )
        
        # Return correlation data from PART 3 for each record
        correlations = []
        for record in records:
            full_record = self.db.get_record(record['record_id'])
            if full_record and 'part3' in full_record:
                part3 = full_record['part3']
                if 'correlations' in part3:
                    correlations.extend(part3['correlations'])
        
        return {
            "session_id": params['session_id'],
            "record_count": len(records),
            "correlations": correlations,
        }
    
    def _handle_get_timeline(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle get_timeline request."""
        # Build timeline of analysis events
        records = self.db.query_records(
            session_id=params.get('session_id'),
            from_time=params.get('from_time'),
            to_time=params.get('to_time'),
            limit=1000,
        )
        
        timeline = []
        for record in records:
            timeline.append({
                "timestamp": record['created_at'],
                "event_type": "analysis",
                "record_id": record['record_id'],
                "file_name": record['file_name'],
                "severity": record['severity'],
                "risk_score": record['risk_score'],
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _handle_get_statistics(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_statistics request."""
        return self.db.get_statistics()
    
    def _handle_list_errors(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle list_errors request."""
        return self.db.get_errors(
            session_id=params.get('session_id'),
            error_type=params.get('error_type'),
            limit=params.get('limit', 100),
            offset=params.get('offset', 0),
        )
    
    def _handle_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping request."""
        return {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "schema_version": SCHEMA_VERSION,
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_ipc_handler(db_path: str) -> IPCHandler:
    """Create an IPC handler with database connection."""
    db = AnalysisDatabase(db_path)
    return IPCHandler(db)


def handle_ipc_message(db_path: str, json_message: str) -> str:
    """
    Handle a single IPC message.
    
    Args:
        db_path: Path to the database.
        json_message: JSON-encoded request.
    
    Returns:
        JSON-encoded response.
    """
    handler = create_ipc_handler(db_path)
    return handler.handle_json(json_message)
