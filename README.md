# File Analysis Application

**Production-Grade File Security Analysis Tool** for malware triage, digital forensics, and file integrity verification.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch application (automatically selects GUI or CLI)
python start.py

# Or launch GUI directly
python app.py

# Or use CLI mode
python start.py --cli
```

## For Law Enforcement, SOC Teams & Enterprises

This is a **production-ready application** designed for:

- ✅ Law Enforcement Agencies - Digital evidence analysis
- ✅ Security Operations Centers (SOC) - Malware triage and threat analysis  
- ✅ Enterprise Security Teams - File integrity and security verification
- ✅ Digital Forensics - Comprehensive file examination
- ✅ Incident Response - Rapid file analysis and risk assessment

## Features

### Desktop GUI Application (PyQt6)

- **File Selection** - Easy file browser for analysis
- **Real-Time Progress** - Live updates during analysis
- **Visual Risk Assessment** - Color-coded severity indicators
- **Analysis History** - Complete record of all analyzed files
- **Multi-Format Export** - JSON, HTML, and PDF reports
- **Case Management** - Organize analyses by cases and sessions
- **Professional Interface** - Native desktop UI with menus and toolbars

### Analysis Capabilities

- **File Type Detection** - Magic bytes and deep content analysis
- **Security Analysis** - Detect suspicious patterns, embedded code, anomalies
- **Risk Scoring** - Evidence-based risk assessment (0-100 scale)
- **Deep Inspection** - Containers (ZIP, OLE), executables, documents, images
- **Heuristic Detection** - Multiple security heuristics with explanations

### Supported File Types

Plain text, Images (JPEG/PNG/GIF), PDF, Office (DOC/DOCX/XLS/XLSX/PPT/PPTX), Archives (ZIP/TAR/7Z/RAR), Executables (PE/ELF/Mach-O)

## Installation

### Prerequisites

- **Python 3.8+** (Python 3.12 recommended)
- **Operating System**: Windows, macOS, or Linux

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Core dependencies:**
- `python-magic` - File type detection
- `olefile` - OLE format parsing
- `PyQt6` - Desktop GUI framework (optional, for GUI mode)
- `Flask` - REST API server (optional, for API mode)

## Usage

### Option 1: Integrated Launcher (Recommended)

```bash
# Automatically starts GUI (if PyQt6 installed) or CLI mode
python start.py

# Analyze a file then view in GUI
python start.py --analyze suspicious.exe

# Force CLI mode
python start.py --cli

# Start API server
python start.py --api --port 5000
```

### Option 2: Direct GUI Launch

```bash
python app.py
```

**Features:**
1. Click "Select File" button
2. Click "Analyze" button
3. View results in real-time
4. Export to JSON/HTML/PDF
5. Browse analysis history

### Option 3: API Server (For Integration)

```bash
# Start REST API server
python api_server.py

# Or via start.py
python start.py --api --port 8080
```

See [API.md](API.md) for complete API documentation.

### Option 4: Command Line (For Automation)

```bash
# Analyze individual files
python analyze_file.py suspicious.exe

# Results saved to exports/ directory
```

## Output & Reports

### Export Formats

All analyses are automatically saved and can be exported in multiple formats:

- **JSON** - Machine-readable, complete data
- **HTML** - Web-viewable, formatted report  
- **PDF** - Professional, printable document

### Export Location

```
exports/20260105_210406/
├── analysis.db                # SQLite database
├── suspicious_analysis.json   # Complete data
├── suspicious_analysis.html   # Web report
└── suspicious_analysis.pdf    # PDF report
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
- **[API.md](API.md)** - REST API documentation
- **[TESTING.md](TESTING.md)** - Testing instructions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture overview

## Architecture

The application consists of four main analysis parts plus presentation layers:

1. **PART 1** - File Ingestion & Type Resolution
2. **PART 2** - Deep Static Analysis  
3. **PART 3** - Risk Scoring & Heuristics
4. **PART 4** - Persistence & Export

**Presentation Layers:**
- **GUI** (PyQt6) - Native desktop interface
- **CLI** (analyze_file.py) - Command-line interface
- **API** (Flask) - REST API for integration

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

## Production Deployment

### Desktop Application

```bash
# Install for users
pip install -r requirements.txt

# Launch application
python start.py
```

### API Server Deployment

```bash
# Run as service
python api_server.py --host 0.0.0.0 --port 8080

# Or via start.py
python start.py --api --port 8080
```

## Security & Privacy

- ✅ All analysis performed locally
- ✅ No data sent to external servers
- ✅ Complete audit trail
- ✅ Encrypted database storage (optional)
- ✅ Export with provenance tracking

## Requirements

- **Python 3.8+**
- **PyQt6** - For GUI
- **Flask** - For API (optional)
- **2GB RAM minimum** (4GB+ recommended)
- **100MB disk space**

## Support

For issues or questions:
- Check [QUICKSTART.md](QUICKSTART.md) for setup help
- Review [API.md](API.md) for API integration
- See [TESTING.md](TESTING.md) for testing
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for technical details

## License

For security analysis and forensic inspection purposes.

---

**Production-Ready** | **Enterprise-Grade** | **Open Source**
