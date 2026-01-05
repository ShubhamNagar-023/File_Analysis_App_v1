# File Analysis Application

A professional-grade file analysis and forensic inspection application for security analysis, malware triage, digital forensics, and file integrity verification.

## Features

### PART 1: File Ingestion & Exact File-Type Resolution

### Secure File Ingestion
- Opens files in binary, read-only mode
- Verifies bytes read match filesystem size
- Detects truncation, sparse files, symlinks, and hard links

### Cryptographic File Identity
- Computes MD5, SHA-1, SHA-256, SHA-512 hashes
- Includes algorithm, byte range, value, and verification method

### Magic-Byte & Signature Detection
- Identifies magic headers with byte offsets
- Detects overlapping/misplaced signatures
- Detects polyglot indicators

### Container Type Identification
- Detects base containers (ZIP, OLE, PDF, PE/ELF/Mach-O, TAR/7Z/RAR)

### Exact Semantic File-Type Resolution (CRITICAL)
- Resolves true semantic file type using internal structure
- Distinguishes DOCX/XLSX/PPTX from ZIP containers
- Distinguishes DOC/XLS/PPT from OLE containers
- Provides container_type, semantic_file_type, classification_confidence, classification_evidence

### Extension Chain & Filename Deception Analysis
- Extracts full extension chain
- Detects double/hidden extensions
- Detects Unicode filename deception (RTL overrides, homoglyphs, invisible characters)
- Provides raw and normalized filenames

### Filesystem Metadata Extraction
- Extracts timestamps (created, modified, accessed)
- Extracts permissions and ownership

### Advanced Checks
- Correct extension but wrong magic detection
- OOXML containers missing required components
- Extra undocumented components in OOXML
- Trailing data beyond logical EOF
- Multiple valid format signatures (polyglot)

### PART 2: Deep File-Type-Aware Static Analysis

#### Universal Static Analysis (All File Types)
- Global Shannon entropy calculation
- Section-wise entropy with anomaly detection
- Entropy variance and anomaly region identification
- Trailing data detection beyond logical EOF
- Padding abuse and slack space detection
- Structural corruption indicators
- Printable string extraction with encoding detection
- String classification (URLs, IPs, emails, file paths, commands)

#### Container-Level Analysis
**ZIP/OOXML Containers:**
- Entry enumeration with offsets and compression methods
- Central directory validation
- ZIP bomb detection (abnormal compression ratios)
- Extra data fields and undocumented entries
- OOXML structure correlation

**OLE Compound Files:**
- FAT, MiniFAT, and directory stream validation
- Orphaned and hidden stream detection
- Stream name manipulation detection

#### File-Type-Specific Deep Analysis

**Plain Text:**
- Encoding and BOM detection
- Line ending consistency
- Non-printable character ratio
- Binary blob detection

**Image Files (JPEG/PNG/GIF):**
- Image dimensions and color depth
- Compression artifact detection
- EXIF/XMP/ICC metadata presence
- Thumbnail mismatch detection
- Steganography indicators

**PDF Files:**
- PDF version and header integrity
- Object count and cross-reference validation
- Embedded file detection
- JavaScript presence
- Incremental update chains
- Encryption and permission flags

**Office Legacy (DOC/XLS/PPT):**
- OLE stream enumeration
- Macro stream detection
- Auto-execution indicators
- Embedded object detection

**Office OOXML (DOCX/XLSX/PPTX):**
- Required OOXML parts validation
- Relationships (.rels) integrity
- Macro presence (VBA project)
- External relationship references
- Custom XML analysis

**Archives:**
- File tree reconstruction with offsets
- Nested archive detection
- Encrypted entry detection
- Per-file entropy and size anomalies

**Executables (PE/ELF/Mach-O):**
- Header sanity checks
- Section table validation
- Section entropy and permissions
- Import/export tables
- Entry point analysis
- Packing indicators

## Supported File Types

- Plain text
- Images (JPEG / PNG / GIF)
- PDF
- Office legacy (DOC / XLS / PPT)
- Office OOXML (DOCX / XLSX / PPTX)
- Archives (ZIP / TAR / 7Z / RAR)
- Executables (PE / ELF / Mach-O)
- Unknown / Unsupported

## Installation

### Minimal Installation (Recommended)

```bash
pip install -r requirements.txt
```

This installs only the core dependencies:
- `python-magic` (0.4.27+) - Magic byte detection
- `olefile` (0.46+) - OLE Compound Binary format parsing
- `weasyprint` (60.0+) - **NEW**: PDF generation for export reports

**Total:** 3 packages + dependencies (~15MB), works on all platforms

### Optional Enhancements

For enhanced capabilities, install optional libraries:

```bash
# YARA rule support
pip install yara-python

# Fuzzy hashing (similarity analysis)
pip install ssdeep python-tlsh

# Image metadata extraction
pip install Pillow piexif

# PDF deep analysis
pip install pdfminer.six PyPDF2

# Binary analysis (PE/ELF)
pip install pefile pyelftools

# Office macro analysis
pip install oletools
```

**Note:** The application works fully with just the core dependencies. Optional libraries enable additional features but are not required.

See [LIBRARY_RATIONALE.md](LIBRARY_RATIONALE.md) for detailed explanation of library choices.

## Usage

### Quick Start: Universal Analyzer

For quick analysis of any file type, use the universal analyzer script:

```bash
# Analyze any file with complete PART 1-4 pipeline
python analyze_file.py <file_path>

# Examples
python analyze_file.py test_files/sample.pdf
python analyze_file.py test_files/sample.docx
python analyze_file.py /path/to/any/file
```

**Features:**
- Auto-detects file type
- Runs complete PART 1-4 analysis pipeline
- Displays summary with risk assessment
- **⭐ NEW**: Persists results to permanent `exports/` directory
- **⭐ NEW**: Exports to **JSON, HTML, and PDF** formats automatically
- Returns exit code based on severity (0=safe, 1=medium, 2=high, 3=error)

**Output includes:**
- File type and container information
- Total findings from deep analysis
- Risk score and severity
- Heuristics triggered
- **⭐ NEW**: Export paths for all three formats (JSON, HTML, PDF)
- Database persistence confirmation

**Export Directory Structure:**
```
exports/
└── 20260105_193116/
    ├── analysis.db                    # SQLite database
    ├── filename_analysis.json         # Complete analysis data
    ├── filename_analysis.html         # Human-readable report
    └── filename_analysis.pdf          # Professional PDF report
```

📚 **See [EXPORT_GUIDE.md](EXPORT_GUIDE.md) for complete export documentation**

### PART 1: File Ingestion & Type Resolution

#### Command Line

```bash
python -m src.file_analyzer.analyzer <file_path>
```

#### Python API

```python
from src.file_analyzer import FileAnalyzer

analyzer = FileAnalyzer('/path/to/file')
results = analyzer.analyze()
print(analyzer.to_json())
```

#### Convenience Function

```python
from src.file_analyzer.analyzer import analyze_file

results = analyze_file('/path/to/file')
```

### PART 2: Deep Static Analysis

#### Python API

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file

# Run PART 1 first
part1_results = analyze_file('/path/to/file')

# Run PART 2 using PART 1 results
part2_results = deep_analyze_file('/path/to/file', part1_results)
```

#### Convenience Function

```python
from src.file_analyzer.deep_analyzer import DeepAnalyzer

analyzer = DeepAnalyzer('/path/to/file', part1_results)
findings = analyzer.analyze()
```

### PART 3: Rules, Correlation & Risk Scoring

#### Python API

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import Part3Analyzer

# Run PART 1 and PART 2 first
part1_results = analyze_file('/path/to/file')
part2_results = deep_analyze_file('/path/to/file', part1_results)

# Run PART 3 analysis
analyzer = Part3Analyzer('/path/to/file', part1_results, part2_results)
part3_results = analyzer.analyze()
```

#### Convenience Functions

```python
from src.file_analyzer.part3_analyzer import analyze_part3, full_analysis

# Analyze with PART 3 only (requires PART 1 & 2 results)
part3_results = analyze_part3('/path/to/file', part1_results, part2_results)

# Complete analysis (PART 1 + PART 2 + PART 3)
complete_results = full_analysis('/path/to/file')
```

#### Features

- **Rule-Based Detection**: YARA rules (optional, graceful fallback)
- **Fuzzy Hashing**: ssdeep and TLSH similarity (optional)
- **Heuristic Evaluation**: Deterministic heuristics with evidence
- **Risk Scoring**: Evidence-based, explainable scoring
- **Session Correlation**: Multi-file correlation within session

### PART 4: Persistence, CLI & IPC

#### Python API

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat

# Run PART 1, 2, 3
part1 = analyze_file('/path/to/file')
part2 = deep_analyze_file('/path/to/file', part1)
part3 = analyze_part3('/path/to/file', part1, part2)

# Initialize database
db = AnalysisDatabase('/path/to/analysis.db')

# Create case and session
case_id = db.create_case(
    name="Investigation Name",
    description="Case description"
)

session_id = db.create_session(
    case_id=case_id,
    name="Analysis Session"
)

# Import analysis results
record_id = db.import_analysis(
    session_id=session_id,
    part1_results=part1,
    part2_results=part2,
    part3_results=part3
)

# Retrieve record
record = db.get_record(record_id)

# Query records
high_risk_files = db.query_records(
    severity="high",
    min_score=75.0
)

# Export results
exporter = Exporter(db)
exporter.export_record(record_id, '/path/to/export.json', ExportFormat.JSON)
exporter.export_session(session_id, '/path/to/session.json')
exporter.export_case(case_id, '/path/to/case.json')

db.close()
```

#### Convenience Test Scripts

**Universal Analyzer (recommended):**
```bash
# Analyze any file type with auto-detection
python analyze_file.py <file_path>

# Examples
python analyze_file.py test_files/sample.pdf
python analyze_file.py /path/to/document.docx
python analyze_file.py /home/user/photo.jpg
```

**File-Type Specific Scripts:**
```bash
# Test specific file types (runs all 4 parts with detailed output)
python text_test.py test_files/sample.txt
python docx_test.py test_files/sample.docx
python pdf_test.py test_files/sample.pdf
python image_test.py test_files/sample.jpg
```

The universal `analyze_file.py` script provides a clean, production-ready interface while the file-type specific scripts show detailed JSON output for each part.

#### Features

- **SQLite Persistence**: Durable storage of all analysis results
- **Case Management**: Organize analyses into cases and sessions
- **Data Integrity**: Cryptographic checksums verify immutability
- **Schema Validation**: All data validated against JSON schemas
- **Export Functionality**: Export to JSON and HTML formats
- **Query Interface**: Filter records by file type, severity, score, time range
- **IPC Contracts**: Structured request/response for UI integration

## Output Format

### PART 1 Output

### PART 1 Output

Results are provided in structured JSON format with each analysis including:
- `analysis_name`
- `library_or_method`
- `input_byte_range`
- `output_value`
- `evidence`
- `verification_method`
- `failure_reason` (if applicable)

Summary block includes:
- `container_type`
- `semantic_file_type`
- `classification_confidence`
- `classification_notes`
- `detected_deception_flags`

### PART 2 Output

PART 2 findings are grouped into three categories:
- `universal` - Universal static analysis findings (entropy, strings, anomalies)
- `container_level` - Container-specific findings (ZIP, OLE structure)
- `file_type_specific` - File-type-specific deep analysis findings

Each finding includes:
- `finding_id` - Unique identifier
- `finding_type` - Type of finding
- `semantic_file_type` - File type being analyzed
- `source_library_or_method` - Analysis method/library used
- `byte_offset_start` - Start offset in file
- `byte_offset_end` - End offset in file (if applicable)
- `extracted_value` - Finding-specific data
- `confidence` - Confidence level (HIGH/MEDIUM/LOW)
- `verification_reference` - How to verify the finding
- `failure_reason` - Reason for failure (if applicable)

Summary includes:
- `total_findings` - Total number of findings
- `semantic_file_type` - File type analyzed
- `container_type` - Container type (if applicable)
- `universal_findings` - Count of universal findings
- `container_findings` - Count of container-level findings
- `file_type_specific_findings` - Count of file-type-specific findings

### PART 3 Output

PART 3 produces deterministic, evidence-based detections and scoring:

**Rule Engine:**
- `yara_detections` - YARA rule matches (if YARA available)
- `fuzzy_hashes` - ssdeep and TLSH hashes (if libraries available)
- `library_status` - Availability of optional libraries

**Heuristics:**
- `triggered_heuristics` - List of triggered heuristics
- Each heuristic includes:
  - `heuristic_id` - Unique identifier
  - `name` - Heuristic name
  - `description` - What it detects
  - `trigger_conditions` - What triggered it
  - `evidence_references` - PART 1/2 evidence IDs
  - `weight` - Score contribution
  - `severity` - Risk level (INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL)

**Risk Score:**
- `raw_score` - Unweighted total
- `normalized_score` - 0-100 scale
- `severity` - Overall severity classification
- `confidence` - Confidence in assessment
- `score_breakdown` - Contribution by category
- `explanation` - Human-readable explanation

**Summary:**
- Evidence-based decisions only
- All scores traceable to specific findings
- Deterministic and reproducible
- No threat naming or guessing

### PART 4 Output

PART 4 provides persistence and export capabilities:

**Database Schema:**
- `cases` - Investigation cases with metadata
- `sessions` - Analysis sessions within cases
- `analysis_records` - Complete PART 1-3 results with integrity checks
- `findings` - Extracted findings from PART 2
- `heuristic_results` - Heuristic evaluations from PART 3
- `provenance` - Audit trail and schema versioning

**Record Structure:**
```json
{
  "record_id": "REC-ABC123DEF456",
  "session_id": "SES-12345678",
  "case_id": "CASE-ABCD1234",
  "file_path": "/path/to/file",
  "file_name": "document.pdf",
  "file_size": 12345,
  "sha256_hash": "abcd1234...",
  "semantic_file_type": "PDF",
  "risk_score": 45.5,
  "severity": "medium",
  "created_at": "2026-01-05T12:00:00",
  "part1": { /* complete PART 1 results */ },
  "part2": { /* complete PART 2 results */ },
  "part3": { /* complete PART 3 results */ },
  "provenance": {
    "schema_version": "1.0.0",
    "tool_version": "1.0.0",
    "checksum": "integrity_hash"
  }
}
```

**Query Results:**
- Filter by session_id, file_type, severity, score range, time range
- Results include summary fields for quick review
- Full PART 1-3 data available on demand

**Export Formats:**
- **JSON**: Complete structured data with provenance
- **HTML**: Human-readable report with risk summary
- **Session/Case Exports**: Multiple records with metadata

**IPC Messages:**
- Structured request/response for UI integration
- Schema-validated payloads
- Error handling with specific error codes


## Running Tests

### Run All Tests (Parts 1, 2, 3, and 4)

```bash
pip install pytest
python -m pytest tests/ -v
```

**Expected:** 121 tests passed (42 PART 1 + 19 PART 2 + 26 PART 3 + 34 PART 4)

### Run Tests by Part

```bash
# PART 1 Tests (42 tests)
python -m pytest tests/test_analyzer.py -v

# PART 2 Tests (19 tests)
python -m pytest tests/test_deep_analyzer.py -v

# PART 3 Tests (26 tests)
python -m pytest tests/test_part3_analyzer.py -v

# PART 4 Tests (34 tests)
python -m pytest tests/test_part4.py -v
```

### Test Coverage

- **PART 1:** 42 tests covering all file ingestion and type resolution features
- **PART 2:** 19 tests covering universal, container, and file-type-specific analysis
- **PART 3:** 26 tests covering rules, heuristics, scoring, and correlation
- **PART 4:** 34 tests covering persistence, schemas, IPC, and export functionality
- **Total:** 121 tests with 100% pass rate

## Documentation

- **[README.md](README.md)** - Main documentation (this file)
- **[EXPORT_GUIDE.md](EXPORT_GUIDE.md)** - ⭐ **NEW**: Multi-format export and reporting guide
- **[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)** - ⭐ **NEW**: Production deployment guide
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Comprehensive testing instructions
- **[LIBRARY_RATIONALE.md](LIBRARY_RATIONALE.md)** - Library usage and architecture decisions
- **[CODE_VS_DOC_VERIFICATION.md](CODE_VS_DOC_VERIFICATION.md)** - Implementation verification report
- **[File_analysis_app_plan](File_analysis_app_plan)** - Original requirements specification

## License

This project is for security analysis and forensic inspection purposes.