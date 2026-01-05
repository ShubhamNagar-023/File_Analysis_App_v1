# File Analysis Application

A professional-grade file analysis and forensic inspection application for security analysis, malware triage, digital forensics, and file integrity verification.

## 🚀 Quick Start

**New to this application?** See **[QUICKSTART.md](QUICKSTART.md)** for step-by-step setup instructions for both backend (Python) and frontend (Electron UI).

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze a file
python analyze_file.py test_files/sample.pdf
```

That's it! For detailed setup, see the [Quick Start Guide](QUICKSTART.md).

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

```bash
pip install -r requirements.txt
```

**Core dependencies:**
- `python-magic` - File type detection
- `olefile` - OLE Compound Binary format parsing

For complete installation instructions and optional enhancements, see:
- **[QUICKSTART.md](QUICKSTART.md)** - Step-by-step setup guide
- **[LIBRARY_RATIONALE.md](LIBRARY_RATIONALE.md)** - Optional libraries and why we use them

## Usage

### Quick Analysis

```bash
# Analyze any file
python analyze_file.py <file_path>

# Examples
python analyze_file.py test_files/sample.pdf
python analyze_file.py test_files/sample.docx
```

**Output:** Results are automatically exported to `exports/` directory in JSON, HTML, and PDF formats.

For detailed usage instructions, API examples, and advanced usage, see **[QUICKSTART.md](QUICKSTART.md)**.

### Python API

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3

# Complete analysis pipeline
part1 = analyze_file('/path/to/file')
part2 = deep_analyze_file('/path/to/file', part1)
part3 = analyze_part3('/path/to/file', part1, part2)
```

For more examples, see the [Quick Start Guide](QUICKSTART.md#common-use-cases).

## Testing

```bash
# Run all tests
python -m pytest tests/ -v
```

**Expected:** 121 tests passed (42 PART 1 + 19 PART 2 + 26 PART 3 + 34 PART 4)

For comprehensive testing instructions, see **[TESTING_GUIDE.md](TESTING_GUIDE.md)**.

## Output Format

Results are provided in structured JSON format and exported in multiple formats:

- **JSON**: Complete structured data with all findings
- **HTML**: Human-readable report with risk summary
- **PDF**: Professional report for documentation

**Export Directory:**
```
exports/
└── 20260105_193116/
    ├── analysis.db                    # SQLite database
    ├── filename_analysis.json         # Complete analysis data
    ├── filename_analysis.html         # Human-readable report
    └── filename_analysis.pdf          # Professional PDF report
```

For detailed output format specifications, see **[EXPORT_GUIDE.md](EXPORT_GUIDE.md)**.

## Documentation

### Essential Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - ⭐ **START HERE** - Quick setup guide for backend and frontend
- **[README.md](README.md)** - Main documentation (this file)
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Comprehensive testing instructions
- **[EXPORT_GUIDE.md](EXPORT_GUIDE.md)** - Multi-format export and reporting guide
- **[LIBRARY_RATIONALE.md](LIBRARY_RATIONALE.md)** - Library usage and architecture decisions

### Additional Documentation

- **[PDF_EXPORT_GUIDE.md](PDF_EXPORT_GUIDE.md)** - PDF export options and WeasyPrint setup
- **[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)** - Production deployment guide
- **[electron/README.md](electron/README.md)** - Desktop UI documentation
- **[File_analysis_app_plan](File_analysis_app_plan)** - Original requirements specification
- **[docs/](docs/)** - Development notes and verification reports

## License

This project is for security analysis and forensic inspection purposes.