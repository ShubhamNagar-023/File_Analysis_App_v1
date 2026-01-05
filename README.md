# File Analysis Application

Professional file analysis tool for security analysis, malware triage, digital forensics, and file integrity verification.

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Analyze files (CLI)
python analyze_file.py suspicious-file.exe

# 3. Start with UI (optional)
python start.py
```

## Features

- **File Type Detection** - Identifies file types using magic bytes and content analysis
- **Security Analysis** - Detects suspicious patterns, embedded code, anomalies
- **Risk Scoring** - Evidence-based risk assessment (0-100 scale)
- **Deep Inspection** - Analyzes containers (ZIP, OLE), executables, documents, images
- **Export Reports** - JSON, HTML, and PDF reports with complete findings

## Supported Files

Plain text, Images (JPEG/PNG/GIF), PDF, Office (DOC/DOCX/XLS/XLSX/PPT/PPTX), Archives (ZIP/TAR/7Z/RAR), Executables (PE/ELF/Mach-O)

## Usage

### Analyze a File

```bash
python analyze_file.py <file>
```

Results are automatically saved to `exports/` directory in JSON, HTML, and PDF formats.

### Start Desktop UI

```bash
# Integrated mode (backend + frontend)
python start.py

# Analyze file and open in UI
python start.py --analyze suspicious.exe

# CLI only (no UI)
python start.py --cli
```

### Programmatic Use

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3

# Complete analysis
part1 = analyze_file('/path/to/file')
part2 = deep_analyze_file('/path/to/file', part1)
part3 = analyze_part3('/path/to/file', part1, part2)

print(f"Risk Score: {part3['risk_score']['normalized_score']}/100")
print(f"Severity: {part3['risk_score']['severity']}")
```

## Output

### Terminal Summary

```
Analyzing: suspicious.exe
File size: 524,288 bytes

✅ PART 1: File Ingestion Complete
   Semantic Type: PE_EXECUTABLE
   
✅ PART 2: Deep Analysis Complete
   Total Findings: 15
   
✅ PART 3: Risk Scoring Complete
   Risk Score: 75.5/100
   Severity: HIGH
```

### Export Files

```
exports/20260105_210406/
├── analysis.db                # SQLite database
├── suspicious_analysis.json   # Machine-readable data
├── suspicious_analysis.html   # Web report
└── suspicious_analysis.pdf    # Printable report
```

## Testing

```bash
# Run all tests (121 tests)
pip install pytest
python -m pytest tests/ -v
```

See [TESTING.md](TESTING.md) for details.

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Detailed setup and usage guide
- **[TESTING.md](TESTING.md)** - Testing instructions
- **[docs/](docs/)** - Additional technical documentation

## Architecture

The application has 4 main components:

1. **PART 1** - File Ingestion & Type Resolution
   - Secure file reading, hashing, magic byte detection, semantic type resolution

2. **PART 2** - Deep Static Analysis
   - Entropy analysis, string extraction, container inspection, file-type-specific analysis

3. **PART 3** - Risk Scoring & Heuristics
   - Rule-based detection, heuristic evaluation, explainable risk scores

4. **PART 4** - Persistence & Export
   - SQLite storage, multi-format export (JSON/HTML/PDF), case management

5. **PART 5** - Desktop UI (Optional)
   - Electron-based dashboard for visual inspection

## Requirements

- **Python 3.8+** (backend)
- **Node.js 18+** (optional, for desktop UI)

### Core Dependencies

- `python-magic` - File type detection
- `olefile` - OLE format parsing

### Optional Enhancements

```bash
pip install yara-python    # YARA rule support
pip install ssdeep         # Fuzzy hashing
pip install Pillow piexif  # Image metadata
pip install pdfminer.six   # PDF analysis
pip install pefile         # PE executable analysis
```

## Production Use

The application is production-ready for:

✅ Security research labs  
✅ Malware triage  
✅ Digital forensics  
✅ CI/CD security scanning  
✅ File integrity verification  

For enterprise deployment, see [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md).

## License

For security analysis and forensic inspection purposes.

---

**Need help?** See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.
