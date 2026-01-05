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

```bash
pip install -r requirements.txt
```

## Usage

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

## Running Tests

### Run All Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

### Run PART 1 Tests Only

```bash
python -m pytest tests/test_analyzer.py -v
```

### Run PART 2 Tests Only

```bash
python -m pytest tests/test_deep_analyzer.py -v
```

### Test Coverage

- **PART 1:** 42 tests covering all file ingestion and type resolution features
- **PART 2:** 19 tests covering universal, container, and file-type-specific analysis

## License

This project is for security analysis and forensic inspection purposes.