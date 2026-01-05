# PDF Export Guide

## Overview

The File Analysis Application can export analysis reports in three formats:
- **JSON**: Complete, lossless data export (always available)
- **HTML**: Rich, styled web-based report (always available)
- **PDF**: Portable document format (two modes available)

## PDF Export Modes

### 1. Text-Based PDF (Default - Always Available)

By default, PDF exports use a detailed text-based format. This mode:
- ✅ Works on all systems without additional dependencies
- ✅ Includes all analysis data (PART 1, 2, 3)
- ✅ Shows detailed findings and heuristics
- ✅ Provides complete provenance information
- ℹ️ Uses plain text formatting (no HTML styling)

### 2. HTML-Based PDF (Optional - Requires WeasyPrint)

For beautifully formatted PDF reports with HTML styling, you can optionally install WeasyPrint.

#### Benefits:
- 📊 Professional HTML-styled layout
- 🎨 Color-coded severity levels
- 📋 Formatted tables and sections
- 🔗 Better readability

#### Installation:

**System Dependencies Required:**

WeasyPrint requires several system libraries to be installed first:

**macOS:**
```bash
brew install cairo pango gdk-pixbuf glib gobject-introspection
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
                     libgdk-pixbuf2.0-0 libffi-dev libgobject-2.0-0
```

**Fedora/RHEL:**
```bash
sudo dnf install cairo pango gdk-pixbuf2
```

**Windows:**
- Download and install GTK3 runtime from https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
- Or use conda: `conda install -c conda-forge weasyprint`

**Python Package:**

After installing system dependencies:
```bash
pip install weasyprint>=60.0
```

#### Troubleshooting:

If you see errors like:
```
cannot load library 'libgobject-2.0-0'
```

This means the system libraries are not installed. Follow the installation steps above for your operating system.

**For detailed installation instructions, see:**
https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation

## Report Contents

All export formats (JSON, HTML, PDF) now include:

### 📋 File Information
- Record ID, file path, file name
- File size and SHA256 hash
- Semantic file type
- Analysis timestamp

### ⚖️ Risk Assessment
- Risk score (0-100)
- Severity level (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)

### 🎯 Heuristics Analysis
- **Triggered heuristics**: Full details with evidence
  - Heuristic name and ID
  - Severity and weight
  - Explanation
  - Evidence data
- **Evaluated but not triggered**: Summary table
  - Shows all heuristics that were checked
  - Helps understand what was evaluated

### 🔍 Detailed Findings
- **Summary by type**: Count of each finding type
- **Individual findings**: Complete details for each
  - Finding ID and type
  - Confidence level
  - Description
  - Evidence data (JSON formatted)

### 📊 Complete Analysis Data
- **PART 1**: File Ingestion & Type Resolution (full JSON)
- **PART 2**: Deep File-Type-Aware Static Analysis (full JSON)
- **PART 3**: Rules, Correlation & Risk Scoring (full JSON)

### 🔖 Provenance & Metadata
- Schema version
- Tool version
- Session ID
- Creation timestamp

## Usage Examples

### Basic Usage (Default Text PDF)
```bash
python analyze_file.py path/to/file.ext
```

This will create exports in `exports/YYYYMMDD_HHMMSS/`:
- `filename_analysis.json` (33KB+)
- `filename_analysis.html` (38KB+)
- `filename_analysis.pdf` (26KB+ text format)

### With WeasyPrint Installed
After installing WeasyPrint and dependencies:
```bash
python analyze_file.py path/to/file.ext
```

The PDF will now be in HTML-styled format instead of text format.

### Programmatic Export
```python
from file_analyzer.part4.persistence import AnalysisDatabase
from file_analyzer.part4.exporter import Exporter, ExportFormat

db = AnalysisDatabase("analysis.db")
exporter = Exporter(db)

# Export a record
exporter.export_record(record_id, "output.pdf", ExportFormat.PDF)
exporter.export_record(record_id, "output.html", ExportFormat.HTML)
exporter.export_record(record_id, "output.json", ExportFormat.JSON)

# Export a session (all records)
exporter.export_session(session_id, "session.pdf", ExportFormat.PDF)

# Export a case (all sessions and records)
exporter.export_case(case_id, "case.pdf", ExportFormat.PDF)
```

## File Size Reference

Typical export file sizes (varies by content):
- **JSON**: 30-50 KB (complete data, no redundancy)
- **HTML**: 35-60 KB (includes styling and formatting)
- **PDF (text)**: 25-45 KB (plain text, comprehensive)
- **PDF (WeasyPrint)**: 40-80 KB (styled HTML rendering)

## Choosing the Right Format

### Use JSON when:
- You need machine-readable output
- Integrating with other tools
- Archiving for programmatic access
- Need exact data representation

### Use HTML when:
- Viewing in a web browser
- Sharing via web/email with formatting
- Need clickable links and interactive content
- Want styled, readable reports

### Use PDF when:
- Need portable, shareable documents
- Printing reports
- Long-term archival (both formats are text-based)
- Professional report delivery

## Notes

1. **Both PDF modes are fully functional** - the text-based PDF contains all the same information as the HTML-based PDF, just with different formatting.

2. **No data loss** - All three formats contain the complete analysis data from PART 1, 2, and 3.

3. **Cross-platform compatibility** - Text-based PDFs work everywhere without dependencies.

4. **Optional enhancement** - WeasyPrint is purely optional for enhanced formatting, not required functionality.

5. **Automatic fallback** - If WeasyPrint installation fails or system libraries are missing, the application automatically uses text-based PDF without errors.
