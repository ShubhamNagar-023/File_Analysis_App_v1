# File Analysis Application - PART 1

A professional-grade file analysis and forensic inspection application for security analysis, malware triage, digital forensics, and file integrity verification.

## Features (PART 1)

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

### Command Line

```bash
python -m src.file_analyzer.analyzer <file_path>
```

### Python API

```python
from src.file_analyzer import FileAnalyzer

analyzer = FileAnalyzer('/path/to/file')
results = analyzer.analyze()
print(analyzer.to_json())
```

### Convenience Function

```python
from src.file_analyzer.analyzer import analyze_file

results = analyze_file('/path/to/file')
```

## Output Format

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

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## License

This project is for security analysis and forensic inspection purposes.