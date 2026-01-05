# PART 4: Persistence, CLI & IPC (Data Durability Layer)
#
# This module provides:
# - JSON schemas for all entities
# - SQLite persistence layer with append-only storage
# - CLI with full query parity
# - IPC contracts for Python ↔ Electron communication
# - Export/reporting capabilities

from .schemas import (
    SCHEMAS,
    validate_schema,
    ValidationError,
)
from .persistence import (
    AnalysisDatabase,
    DatabaseError,
    IntegrityError,
)
from .cli import main as cli_main
from .ipc import (
    IPCHandler,
    IPCRequest,
    IPCResponse,
)
from .exporter import (
    Exporter,
    ExportFormat,
)

__all__ = [
    # Schemas
    'SCHEMAS',
    'validate_schema',
    'ValidationError',
    # Persistence
    'AnalysisDatabase',
    'DatabaseError',
    'IntegrityError',
    # CLI
    'cli_main',
    # IPC
    'IPCHandler',
    'IPCRequest',
    'IPCResponse',
    # Export
    'Exporter',
    'ExportFormat',
]
