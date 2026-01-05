# File Analyzer Module
from .analyzer import FileAnalyzer
from .deep_analyzer import DeepAnalyzer, deep_analyze_file
from .rule_engine import RuleEngine, apply_yara_rules, compute_fuzzy_hashes
from .heuristic_engine import HeuristicEngine, evaluate_heuristics, HEURISTIC_DEFINITIONS
from .risk_scorer import RiskScorer, compute_risk_score, explain_score
from .correlator import SessionCorrelator, correlate_session
from .part3_analyzer import Part3Analyzer, analyze_part3, full_analysis

# PART 4: Persistence, CLI & IPC
from .part4 import (
    SCHEMAS,
    validate_schema,
    ValidationError,
    AnalysisDatabase,
    DatabaseError,
    IntegrityError,
    cli_main,
    IPCHandler,
    IPCRequest,
    IPCResponse,
    Exporter,
    ExportFormat,
)

__all__ = [
    # PART 1
    'FileAnalyzer',
    # PART 2
    'DeepAnalyzer',
    'deep_analyze_file',
    # PART 3
    'RuleEngine',
    'apply_yara_rules',
    'compute_fuzzy_hashes',
    'HeuristicEngine',
    'evaluate_heuristics',
    'HEURISTIC_DEFINITIONS',
    'RiskScorer',
    'compute_risk_score',
    'explain_score',
    'SessionCorrelator',
    'correlate_session',
    'Part3Analyzer',
    'analyze_part3',
    'full_analysis',
    # PART 4
    'SCHEMAS',
    'validate_schema',
    'ValidationError',
    'AnalysisDatabase',
    'DatabaseError',
    'IntegrityError',
    'cli_main',
    'IPCHandler',
    'IPCRequest',
    'IPCResponse',
    'Exporter',
    'ExportFormat',
]
