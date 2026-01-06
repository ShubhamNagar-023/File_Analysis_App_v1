# File Analysis Application

**Production-Grade Desktop Application** for security analysis, malware triage, digital forensics, and file integrity verification.

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Launch GUI Application
python app.py
```

## For Law Enforcement, SOC Teams & Enterprises

This is a **production-ready desktop application** designed for:

- ✅ Law Enforcement Agencies - Digital evidence analysis
- ✅ Security Operations Centers (SOC) - Malware triage and threat analysis  
- ✅ Enterprise Security Teams - File integrity and security verification
- ✅ Digital Forensics - Comprehensive file examination
- ✅ Incident Response - Rapid file analysis and risk assessment

## Features

### Desktop GUI Application

- **Drag & Drop File Analysis** - Easy file selection and analysis
- **Real-Time Progress** - Live updates during analysis
- **Visual Risk Assessment** - Color-coded severity indicators
- **Analysis History** - Complete record of all analyzed files
- **Multi-Format Export** - JSON, HTML, and PDF reports
- **Case Management** - Organize analyses by cases and sessions
- **Professional Interface** - Production-ready UI with menus and toolbars

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
- `PyQt6` - Desktop GUI framework
- `Flask` - REST API (for API mode)

## Usage

### Production GUI (Recommended)

```bash
python app.py
```

**Features:**
1. Click "Select File" or drag & drop
2. Click "Analyze" button
3. View results in real-time
4. Export to JSON/HTML/PDF
5. Browse analysis history

### API Server (For Integration)

```bash
# Start REST API server
python api_server.py

# Custom port
python api_server.py --port 8080
```

See [API.md](API.md) for complete API documentation.

### Command Line (For Automation)

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

- **[QUICKSTART.md](QUICKSTART.md)** - Detailed setup guide
- **[API.md](API.md)** - REST API documentation
- **[TESTING.md](TESTING.md)** - Testing instructions
- **[docs/](docs/)** - Technical documentation

## Architecture

1. **GUI Layer** (PyQt6) - Production desktop interface
2. **PART 1** - File Ingestion & Type Resolution
3. **PART 2** - Deep Static Analysis  
4. **PART 3** - Risk Scoring & Heuristics
5. **PART 4** - Persistence & Export
6. **API Layer** (Flask) - REST API for integration

## Production Deployment

### Desktop Application

```bash
# Install for users
pip install -r requirements.txt

# Create desktop shortcut
python app.py
```

### API Server Deployment

```bash
# Run as service
python api_server.py --host 0.0.0.0 --port 8080
```

### Docker Deployment

```bash
docker build -t file-analysis .
docker run -p 5000:5000 file-analysis
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
- Review [API.md](API.md) for integration
- See [docs/](docs/) for technical details

## License

For security analysis and forensic inspection purposes.

---

**Production-Ready** | **Enterprise-Grade** | **Open Source**
