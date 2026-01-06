# Quick Start Guide

Get started with the File Analysis Application in minutes.

---

## Prerequisites

- **Python 3.8+** for backend
- **Node.js 18+** for frontend (optional - only needed for desktop UI)

---

## 🚀 Quick Start

### Option 1: Integrated Mode (Backend + UI)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the application
python start.py
```

The integrated launcher will:
- Check dependencies
- Install Electron UI (first run only)
- Start the desktop application

### Option 2: CLI Only

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Analyze files
python analyze_file.py test_files/sample.pdf
```

### Option 3: Analyze Then View in UI

```bash
# Analyze a file and open results in UI
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

#### Step 2: Verify Installation

```bash
# Run tests to verify everything works
python -m pytest tests/ -v
```

Expected: 121 tests passed

#### Step 3: Analyze Your First File

```bash
# Use the universal analyzer
python analyze_file.py <path-to-your-file>

# Examples
python analyze_file.py test_files/sample.pdf
python analyze_file.py test_files/sample.docx
python analyze_file.py /path/to/any/file
```

#### Step 4: View Results

The analyzer automatically:
- Displays a summary in the terminal
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

### Frontend (Electron Desktop UI)

The Electron frontend provides a graphical dashboard for viewing analysis results.

#### Step 1: Navigate to Electron Directory

```bash
cd electron
```

#### Step 2: Install Dependencies

```bash
# Install Node.js dependencies
npm install
```

#### Step 3: Start the Application

```bash
# Start the desktop application
npm start

# Or with developer tools enabled
npm run dev
```

#### Step 4: Use the UI

The Electron app will launch with:
- File overview panel (hashes, file type, metadata)
- Risk assessment panel (score, severity, heuristics)
- Findings explorer (detailed analysis results)
- Hex viewer, strings viewer, and more

**Note:** The UI displays analysis results from the Python backend via IPC. Run Python analyses first to see data in the UI.

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
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Comprehensive testing instructions
- **[EXPORT_GUIDE.md](EXPORT_GUIDE.md)** - Export formats and reporting
- **[docs/](docs/)** - Additional documentation

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

See [LIBRARY_RATIONALE.md](LIBRARY_RATIONALE.md) for details on optional libraries.

---

## 🐛 Troubleshooting

### Python ImportError

**Issue:** `ModuleNotFoundError: No module named 'magic'`

**Solution:**
```bash
pip install python-magic
```

### PDF Export Not Working

**Issue:** `OSError: cannot load library 'libgobject-2.0-0'`

**Solution:** WeasyPrint requires system libraries. See [PDF_EXPORT_GUIDE.md](PDF_EXPORT_GUIDE.md) for installation instructions, or the app will use text-based PDF format automatically.

### Electron Won't Start

**Issue:** `Error: Cannot find module 'electron'`

**Solution:**
```bash
cd electron
npm install
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

The application has 4 main parts:

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
   - IPC for UI integration

5. **PART 5** - Desktop UI (Optional)
   - Electron-based dashboard
   - Visual file inspection
   - Interactive hex viewer
   - Theme support (dark/light/high-contrast)

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
- Review [TESTING_GUIDE.md](TESTING_GUIDE.md) for testing help
- See [docs/](docs/) for additional resources

---

**Last Updated:** 2026-01-05
