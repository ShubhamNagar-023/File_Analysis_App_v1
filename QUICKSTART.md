# Quick Start Guide

Get started with the File Analysis Application in minutes.

---

## Prerequisites

- **Python 3.8+** for core functionality
- **PyQt6** for GUI (optional - only needed for desktop interface)

---

## 🚀 Quick Start

### Option 1: Integrated Mode (Recommended)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the application (auto-detects GUI or CLI mode)
python start.py
```

The launcher will:
- Check dependencies
- Start GUI if PyQt6 is available
- Fall back to CLI mode if GUI not available

### Option 2: Direct GUI Launch

```bash
# 1. Install dependencies (including PyQt6)
pip install -r requirements.txt

# 2. Launch GUI directly
python app.py
```

### Option 3: CLI Only

```bash
# 1. Install core dependencies only
pip install python-magic olefile Flask flask-cors

# 2. Analyze files via command line
python analyze_file.py test_files/sample.pdf
```

### Option 4: Analyze Then View in GUI

```bash
# Analyze a file and open results in GUI
python start.py --analyze suspicious-file.exe
```

---

## 📋 Manual Setup

### Backend (Python)

#### Step 1: Install Dependencies

```bash
# Clone the repository (if not already done)
git clone https://github.com/ShubhamNagar-023/File_Analysis_App_v1.git
cd File_Analysis_App_v1

# Install core dependencies
pip install -r requirements.txt
```

**Core dependencies installed:**
- `python-magic` - File type detection
- `olefile` - OLE Compound Binary format parsing
- `PyQt6` - Desktop GUI (optional)
- `Flask` - REST API (optional)

#### Step 2: Verify Installation

```bash
# Run tests to verify everything works
python -m pytest tests/ -v
```

Expected: 121 tests passed

#### Step 3: Choose Your Interface

**GUI Mode (PyQt6):**
```bash
python start.py
# Or directly:
python app.py
```

**CLI Mode:**
```bash
python start.py --cli
# Or analyze directly:
python analyze_file.py <path-to-your-file>
```

**API Server:**
```bash
python start.py --api
# Or directly:
python api_server.py
```

#### Step 4: View Results

The analyzer automatically:
- Displays results in GUI (if using GUI mode)
- Prints summary in terminal (if using CLI mode)
- Saves complete results to `exports/` directory in JSON, HTML, and PDF formats
- Persists data to SQLite database

**Export directory structure:**
```
exports/
└── 20260105_193116/
    ├── analysis.db                    # SQLite database
    ├── filename_analysis.json         # Complete analysis data
    ├── filename_analysis.html         # Human-readable report
    └── filename_analysis.pdf          # Professional PDF report
```

---

## 🎯 Common Use Cases

### Analyze a Single File

```bash
python analyze_file.py /path/to/suspicious-file.exe
```

### Analyze Multiple Files

```bash
# Create a script or use a loop
for file in test_files/*; do
    python analyze_file.py "$file"
done
```

### Run File-Type Specific Tests

```bash
# Test specific file types with detailed output
python text_test.py test_files/sample.txt
python docx_test.py test_files/sample.docx
python pdf_test.py test_files/sample.pdf
python image_test.py test_files/sample.jpg
```

### Access Results Programmatically

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3

# Complete analysis pipeline
part1 = analyze_file('/path/to/file')
part2 = deep_analyze_file('/path/to/file', part1)
part3 = analyze_part3('/path/to/file', part1, part2)

# Access results
print(f"File type: {part1['semantic_file_type']['output_value']['semantic_file_type']}")
print(f"Risk score: {part3['risk_score']['normalized_score']}")
print(f"Severity: {part3['risk_score']['severity']}")
```

---

## 📚 Next Steps

### Learn More

- **[README.md](README.md)** - Full documentation and features
- **[API.md](API.md)** - REST API documentation  
- **[TESTING.md](TESTING.md)** - Testing instructions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture

### Optional Enhancements

Install optional libraries for enhanced features:

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

See [ARCHITECTURE.md](ARCHITECTURE.md) for details on optional libraries.

---

## 🐛 Troubleshooting

### Python ImportError

**Issue:** `ModuleNotFoundError: No module named 'magic'`

**Solution:**
```bash
pip install python-magic
```

### PyQt6 Not Available

**Issue:** `ERROR: PyQt6 not installed`

**Solution:**
```bash
# For GUI support:
pip install PyQt6

# Or use CLI mode:
python start.py --cli
```

### PDF Export Not Working

**Issue:** PDF export errors

**Solution:** The app uses a fallback text-based PDF format if WeasyPrint is not available. For better PDF export:
```bash
pip install weasyprint
```

### GUI Won't Start

**Issue:** GUI fails to launch

**Solution:**
```bash
# Ensure PyQt6 is installed
pip install PyQt6

# Try launching directly
python app.py

# Or use CLI mode
python start.py --cli
```

### Tests Failing

**Issue:** Some tests fail when running

**Solution:**
```bash
# Ensure you're in the project root directory
cd /path/to/File_Analysis_App_v1

# Reinstall dependencies
pip install -r requirements.txt

# Run tests again
python -m pytest tests/ -v
```

---

## 🎓 Understanding the Application

### Architecture Overview

The application has 4 main analysis parts plus presentation layers:

**Analysis Pipeline:**
1. **PART 1** - File Ingestion & Type Resolution
   - Secure file reading
   - Hash computation
   - Magic byte detection
   - Semantic file type resolution

2. **PART 2** - Deep Static Analysis
   - Entropy analysis
   - String extraction
   - Container-level inspection
   - File-type-specific analysis

3. **PART 3** - Risk Scoring & Heuristics
   - Rule-based detection
   - Heuristic evaluation
   - Risk score calculation
   - Evidence-based assessment

4. **PART 4** - Persistence & Export
   - SQLite database storage
   - JSON/HTML/PDF export
   - Case management
   - API integration

**Presentation Layers:**
- **GUI** (PyQt6) - Native desktop interface
- **CLI** (analyze_file.py) - Command-line interface  
- **API** (Flask) - REST API for integration

### Supported File Types

- Plain text
- Images (JPEG, PNG, GIF)
- PDF documents
- Office documents (DOC, XLS, PPT, DOCX, XLSX, PPTX)
- Archives (ZIP, TAR, 7Z, RAR)
- Executables (PE, ELF, Mach-O)

---

## 📞 Support

For issues or questions:
- Check the [README.md](README.md) for detailed documentation
- Review [TESTING.md](TESTING.md) for testing help
- See [API.md](API.md) for API integration
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for technical details

---

**Last Updated:** 2026-01-05
