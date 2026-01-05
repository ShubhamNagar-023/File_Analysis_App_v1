"""
PART 4: Canonical JSON Schemas

This module defines and enforces JSON schemas for all entities:
- File identity (PART 1)
- Findings (PART 2)
- Rules & scores (PART 3)
- Sessions & cases
- Errors & failures

All stored and transmitted data MUST validate against these schemas.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


class ValidationError(Exception):
    """Raised when data fails schema validation."""
    
    def __init__(self, message: str, path: str = "", value: Any = None):
        self.message = message
        self.path = path
        self.value = value
        super().__init__(f"{path}: {message}" if path else message)


# Schema version for provenance tracking
SCHEMA_VERSION = "1.0.0"


# ============================================================================
# SCHEMA DEFINITIONS
# ============================================================================

FILE_IDENTITY_SCHEMA = {
    "type": "object",
    "description": "File identity from PART 1 analysis",
    "required": ["file_path", "file_name", "file_size", "hashes", "semantic_file_type"],
    "properties": {
        "file_path": {"type": "string", "description": "Absolute path to the file"},
        "file_name": {"type": "string", "description": "File name with extension"},
        "file_size": {"type": "integer", "minimum": 0, "description": "File size in bytes"},
        "hashes": {
            "type": "object",
            "description": "Cryptographic hashes",
            "required": ["md5", "sha1", "sha256"],
            "properties": {
                "md5": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
                "sha1": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
                "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                "sha512": {"type": "string", "pattern": "^[a-f0-9]{128}$"},
            },
        },
        "semantic_file_type": {"type": "string", "description": "Detected semantic file type"},
        "container_type": {"type": ["string", "null"], "description": "Container type if applicable"},
        "classification_confidence": {
            "type": "string",
            "enum": ["HIGH", "MEDIUM", "LOW", "AMBIGUOUS"],
        },
        "extension_chain": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Chain of file extensions",
        },
        "deception_flags": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Detected deception indicators",
        },
    },
}


FINDING_SCHEMA = {
    "type": "object",
    "description": "Finding from PART 2 analysis",
    "required": ["finding_id", "finding_type", "semantic_file_type", "confidence"],
    "properties": {
        "finding_id": {"type": "string", "pattern": "^F\\d{4}_.*$"},
        "finding_type": {"type": "string"},
        "semantic_file_type": {"type": "string"},
        "source_library_or_method": {"type": "string"},
        "byte_offset_start": {"type": ["integer", "null"]},
        "byte_offset_end": {"type": ["integer", "null"]},
        "extracted_value": {"type": ["object", "array", "string", "number", "null"]},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "verification_reference": {"type": "string"},
        "failure_reason": {"type": ["string", "null"]},
    },
}


RULE_DETECTION_SCHEMA = {
    "type": "object",
    "description": "Rule detection from PART 3 analysis",
    "required": ["id", "type", "rule_id", "confidence", "severity"],
    "properties": {
        "id": {"type": "string"},
        "type": {"type": "string", "enum": ["rule"]},
        "semantic_file_type": {"type": "string"},
        "rule_id": {"type": "string"},
        "namespace": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "meta": {"type": "object"},
        "matched_strings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "identifier": {"type": "string"},
                    "offset": {"type": "integer"},
                    "data_hex": {"type": "string"},
                    "data_length": {"type": "integer"},
                },
            },
        },
        "score_contribution": {"type": "number"},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "explanation": {"type": "string"},
        "verification_reference": {"type": "string"},
        "failure_reason": {"type": ["string", "null"]},
    },
}


HEURISTIC_RESULT_SCHEMA = {
    "type": "object",
    "description": "Heuristic result from PART 3 analysis",
    "required": ["id", "type", "heuristic_key", "triggered", "severity", "confidence"],
    "properties": {
        "id": {"type": "string", "pattern": "^H\\d{4}_.*$"},
        "type": {"type": "string", "enum": ["heuristic"]},
        "heuristic_key": {"type": "string"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "semantic_file_type": {"type": "string"},
        "triggered": {"type": "boolean"},
        "trigger_conditions": {"type": "array", "items": {"type": "string"}},
        "trigger_details": {"type": "object"},
        "evidence_references": {"type": "array", "items": {"type": "string"}},
        "weight": {"type": "number"},
        "score_contribution": {"type": "number"},
        "severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "logic_applied": {"type": "string"},
        "explanation": {"type": "string"},
        "reproducibility_notes": {"type": "string"},
        "failure_reason": {"type": ["string", "null"]},
    },
}


RISK_SCORE_SCHEMA = {
    "type": "object",
    "description": "Risk score from PART 3 analysis",
    "required": ["id", "type", "raw_score", "normalized_score", "severity", "confidence"],
    "properties": {
        "id": {"type": "string", "pattern": "^S\\d{4}_.*$"},
        "type": {"type": "string", "enum": ["score"]},
        "semantic_file_type": {"type": "string"},
        "raw_score": {"type": "number"},
        "normalized_score": {"type": "number", "minimum": 0, "maximum": 100},
        "severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "score_contributions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["source_id", "source_type", "weighted_score"],
                "properties": {
                    "source_id": {"type": "string"},
                    "source_type": {"type": "string"},
                    "source_name": {"type": "string"},
                    "base_score": {"type": "number"},
                    "weight": {"type": "number"},
                    "severity_multiplier": {"type": "number"},
                    "weighted_score": {"type": "number"},
                    "confidence": {"type": "string"},
                    "evidence_reference": {"type": "string"},
                    "explanation": {"type": "string"},
                },
            },
        },
        "contribution_count": {"type": "integer", "minimum": 0},
        "scoring_method": {"type": "string"},
        "logic_applied": {"type": "string"},
        "explanation": {"type": "string"},
        "reproducibility_notes": {"type": "string"},
        "failure_reason": {"type": ["string", "null"]},
    },
}


CORRELATION_SCHEMA = {
    "type": "object",
    "description": "Correlation from PART 3 session analysis",
    "required": ["id", "type", "correlation_type", "file_ids", "confidence"],
    "properties": {
        "id": {"type": "string", "pattern": "^C\\d{4}_.*$"},
        "type": {"type": "string", "enum": ["correlation"]},
        "correlation_type": {"type": "string"},
        "algorithm": {"type": "string"},
        "file_ids": {"type": "array", "items": {"type": "string"}},
        "file_paths": {"type": "array", "items": {"type": "string"}},
        "similarity_score": {"type": "number"},
        "hashes": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "explanation": {"type": "string"},
        "evidence_references": {"type": "array", "items": {"type": "string"}},
        "logic_applied": {"type": "string"},
        "failure_reason": {"type": ["string", "null"]},
    },
}


SESSION_SCHEMA = {
    "type": "object",
    "description": "Analysis session",
    "required": ["session_id", "case_id", "created_at", "status"],
    "properties": {
        "session_id": {"type": "string", "pattern": "^SES-[A-Z0-9]{8}$"},
        "case_id": {"type": "string", "pattern": "^CASE-[A-Z0-9]{8}$"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "status": {
            "type": "string",
            "enum": ["active", "completed", "archived"],
        },
        "file_count": {"type": "integer", "minimum": 0},
        "metadata": {"type": "object"},
    },
}


CASE_SCHEMA = {
    "type": "object",
    "description": "Investigation case",
    "required": ["case_id", "name", "created_at", "status"],
    "properties": {
        "case_id": {"type": "string", "pattern": "^CASE-[A-Z0-9]{8}$"},
        "name": {"type": "string", "minLength": 1, "maxLength": 255},
        "description": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "status": {
            "type": "string",
            "enum": ["open", "closed", "archived"],
        },
        "session_count": {"type": "integer", "minimum": 0},
        "metadata": {"type": "object"},
    },
}


ERROR_SCHEMA = {
    "type": "object",
    "description": "Error or failure record",
    "required": ["error_id", "error_type", "message", "timestamp"],
    "properties": {
        "error_id": {"type": "string"},
        "error_type": {"type": "string"},
        "message": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "file_id": {"type": ["string", "null"]},
        "session_id": {"type": ["string", "null"]},
        "case_id": {"type": ["string", "null"]},
        "context": {"type": "object"},
        "stack_trace": {"type": ["string", "null"]},
        "recoverable": {"type": "boolean"},
    },
}


ANALYSIS_RECORD_SCHEMA = {
    "type": "object",
    "description": "Complete analysis record combining PART 1, 2, and 3 outputs",
    "required": ["record_id", "session_id", "file_identity", "created_at", "schema_version"],
    "properties": {
        "record_id": {"type": "string", "pattern": "^REC-[A-Z0-9]{12}$"},
        "session_id": {"type": "string", "pattern": "^SES-[A-Z0-9]{8}$"},
        "file_identity": {"$ref": "#/definitions/file_identity"},
        "findings": {
            "type": "array",
            "items": {"$ref": "#/definitions/finding"},
        },
        "rule_detections": {
            "type": "array",
            "items": {"$ref": "#/definitions/rule_detection"},
        },
        "heuristic_results": {
            "type": "array",
            "items": {"$ref": "#/definitions/heuristic_result"},
        },
        "risk_score": {"$ref": "#/definitions/risk_score"},
        "correlations": {
            "type": "array",
            "items": {"$ref": "#/definitions/correlation"},
        },
        "created_at": {"type": "string", "format": "date-time"},
        "schema_version": {"type": "string"},
        "tool_version": {"type": "string"},
        "provenance": {
            "type": "object",
            "properties": {
                "analyzer_version": {"type": "string"},
                "part1_version": {"type": "string"},
                "part2_version": {"type": "string"},
                "part3_version": {"type": "string"},
                "libraries": {"type": "object"},
            },
        },
    },
    "definitions": {
        "file_identity": FILE_IDENTITY_SCHEMA,
        "finding": FINDING_SCHEMA,
        "rule_detection": RULE_DETECTION_SCHEMA,
        "heuristic_result": HEURISTIC_RESULT_SCHEMA,
        "risk_score": RISK_SCORE_SCHEMA,
        "correlation": CORRELATION_SCHEMA,
    },
}


PROVENANCE_SCHEMA = {
    "type": "object",
    "description": "Provenance information for data records",
    "required": ["created_at", "schema_version"],
    "properties": {
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "schema_version": {"type": "string"},
        "tool_version": {"type": "string"},
        "analyzer_versions": {
            "type": "object",
            "properties": {
                "part1": {"type": "string"},
                "part2": {"type": "string"},
                "part3": {"type": "string"},
                "part4": {"type": "string"},
            },
        },
        "library_versions": {"type": "object"},
        "checksum": {"type": "string", "description": "SHA-256 checksum of the data"},
    },
}


# Aggregate all schemas
SCHEMAS = {
    "file_identity": FILE_IDENTITY_SCHEMA,
    "finding": FINDING_SCHEMA,
    "rule_detection": RULE_DETECTION_SCHEMA,
    "heuristic_result": HEURISTIC_RESULT_SCHEMA,
    "risk_score": RISK_SCORE_SCHEMA,
    "correlation": CORRELATION_SCHEMA,
    "session": SESSION_SCHEMA,
    "case": CASE_SCHEMA,
    "error": ERROR_SCHEMA,
    "analysis_record": ANALYSIS_RECORD_SCHEMA,
    "provenance": PROVENANCE_SCHEMA,
}


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def _validate_type(value: Any, expected_type: Union[str, List[str]], path: str) -> None:
    """Validate that a value matches the expected type(s)."""
    if isinstance(expected_type, list):
        # Union type
        type_names = expected_type
    else:
        type_names = [expected_type]
    
    valid = False
    for type_name in type_names:
        if type_name == "string" and isinstance(value, str):
            valid = True
        elif type_name == "integer" and isinstance(value, int) and not isinstance(value, bool):
            valid = True
        elif type_name == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            valid = True
        elif type_name == "boolean" and isinstance(value, bool):
            valid = True
        elif type_name == "array" and isinstance(value, list):
            valid = True
        elif type_name == "object" and isinstance(value, dict):
            valid = True
        elif type_name == "null" and value is None:
            valid = True
    
    if not valid:
        raise ValidationError(
            f"Expected type {expected_type}, got {type(value).__name__}",
            path,
            value
        )


def _validate_string(value: str, schema: Dict[str, Any], path: str) -> None:
    """Validate string value against schema constraints."""
    if "minLength" in schema and len(value) < schema["minLength"]:
        raise ValidationError(
            f"String length {len(value)} is less than minimum {schema['minLength']}",
            path,
            value
        )
    
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        raise ValidationError(
            f"String length {len(value)} exceeds maximum {schema['maxLength']}",
            path,
            value
        )
    
    if "pattern" in schema:
        if not re.match(schema["pattern"], value):
            raise ValidationError(
                f"String does not match pattern {schema['pattern']}",
                path,
                value
            )
    
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(
            f"Value must be one of {schema['enum']}",
            path,
            value
        )
    
    if "format" in schema:
        if schema["format"] == "date-time":
            try:
                # Try to parse ISO 8601 datetime
                datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                raise ValidationError(
                    f"Invalid date-time format",
                    path,
                    value
                )


def _validate_number(value: Union[int, float], schema: Dict[str, Any], path: str) -> None:
    """Validate numeric value against schema constraints."""
    if "minimum" in schema and value < schema["minimum"]:
        raise ValidationError(
            f"Value {value} is less than minimum {schema['minimum']}",
            path,
            value
        )
    
    if "maximum" in schema and value > schema["maximum"]:
        raise ValidationError(
            f"Value {value} exceeds maximum {schema['maximum']}",
            path,
            value
        )


def _validate_array(value: List, schema: Dict[str, Any], path: str) -> None:
    """Validate array value against schema constraints."""
    if "items" in schema:
        item_schema = schema["items"]
        for i, item in enumerate(value):
            _validate_value(item, item_schema, f"{path}[{i}]")
    
    if "minItems" in schema and len(value) < schema["minItems"]:
        raise ValidationError(
            f"Array length {len(value)} is less than minimum {schema['minItems']}",
            path,
            value
        )
    
    if "maxItems" in schema and len(value) > schema["maxItems"]:
        raise ValidationError(
            f"Array length {len(value)} exceeds maximum {schema['maxItems']}",
            path,
            value
        )


def _validate_object(value: Dict, schema: Dict[str, Any], path: str) -> None:
    """Validate object value against schema constraints."""
    # Check required properties
    if "required" in schema:
        for required_prop in schema["required"]:
            if required_prop not in value:
                raise ValidationError(
                    f"Missing required property '{required_prop}'",
                    path,
                    value
                )
    
    # Validate properties
    if "properties" in schema:
        for prop_name, prop_value in value.items():
            if prop_name in schema["properties"]:
                prop_schema = schema["properties"][prop_name]
                _validate_value(prop_value, prop_schema, f"{path}.{prop_name}")


def _validate_value(value: Any, schema: Dict[str, Any], path: str = "") -> None:
    """Validate a value against a schema."""
    if "$ref" in schema:
        # Reference to another schema - skip for now (handled at top level)
        return
    
    if "type" not in schema:
        return  # No type constraint
    
    expected_type = schema["type"]
    
    # Handle null type
    if value is None:
        if expected_type == "null" or (isinstance(expected_type, list) and "null" in expected_type):
            return
        raise ValidationError("Value cannot be null", path, value)
    
    # Validate type
    _validate_type(value, expected_type, path)
    
    # Type-specific validation
    if isinstance(value, str):
        _validate_string(value, schema, path)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        _validate_number(value, schema, path)
    elif isinstance(value, list):
        _validate_array(value, schema, path)
    elif isinstance(value, dict):
        _validate_object(value, schema, path)


def validate_schema(data: Any, schema_name: str) -> None:
    """
    Validate data against a named schema.
    
    Args:
        data: Data to validate.
        schema_name: Name of the schema to validate against.
    
    Raises:
        ValidationError: If validation fails.
        KeyError: If schema_name is not found.
    """
    if schema_name not in SCHEMAS:
        raise KeyError(f"Unknown schema: {schema_name}")
    
    schema = SCHEMAS[schema_name]
    _validate_value(data, schema, schema_name)


def validate_with_schema(data: Any, schema: Dict[str, Any], path: str = "") -> None:
    """
    Validate data against an inline schema.
    
    Args:
        data: Data to validate.
        schema: Schema definition.
        path: Current path for error messages.
    
    Raises:
        ValidationError: If validation fails.
    """
    _validate_value(data, schema, path)


def get_schema_version() -> str:
    """Return the current schema version."""
    return SCHEMA_VERSION
