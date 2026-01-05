# Export and Reporting Guide

## Overview

The File Analysis Application now supports **persistent multi-format exports** for all analysis results. Every analysis automatically generates three comprehensive report formats:

- **JSON** - Machine-readable, lossless data format for integration and automation
- **HTML** - Human-readable web format for viewing in browsers
- **PDF** - Professional, portable document format for archival and sharing

## Features

### Persistent Storage

All analysis results are now permanently stored in the `exports/` directory:

- **Location**: `exports/` in the project root directory
- **Organization**: Each analysis creates a timestamped subdirectory (format: `YYYYMMDD_HHMMSS`)
- **Persistence**: Exports are permanent and survive application restarts
- **Database**: SQLite database included for structured querying and retrieval

### Export Directory Structure

```
exports/
├── 20260105_193116/
│   ├── analysis.db                          # SQLite database with full analysis data
│   ├── <filename>_analysis.json             # JSON export
│   ├── <filename>_analysis.html             # HTML export
│   └── <filename>_analysis.pdf              # PDF export
├── 20260105_193200/
│   ├── analysis.db
│   ├── <filename>_analysis.json
│   ├── <filename>_analysis.html
│   └── <filename>_analysis.pdf
└── ...
```

## Usage

### Basic Analysis

Simply run the analyzer on any file:

```bash
python analyze_file.py <file_path>
```

The script will:
1. Perform complete 4-part analysis
2. Create a timestamped export directory
3. Generate all three report formats
4. Display export paths in the output

### Example Output

```
================================================================================
Running PART 4: Persistence, CLI & IPC...
📁 Export Directory: /path/to/exports/20260105_193116
✅ Analysis persisted to database
   Case ID: CASE-B72DF055
   Session ID: SES-78730054
   Record ID: REC-1CBB78674F91

✅ Analysis exported to all formats
   JSON: /path/to/exports/20260105_193116/myfile_analysis.json
   JSON Size: 32,855 bytes
   HTML: /path/to/exports/20260105_193116/myfile_analysis.html
   HTML Size: 3,439 bytes
   PDF: /path/to/exports/20260105_193116/myfile_analysis.pdf
   PDF Size: 17,038 bytes
```

## Report Contents

### JSON Export

The JSON export contains the complete, lossless analysis data:

- **Export metadata**: timestamp, schema version, export type
- **File information**: path, size, hashes, file type
- **Analysis results**: all findings from Parts 1-3
- **Risk assessment**: scores, severity, triggered heuristics
- **Provenance**: tool version, timestamps, evidence IDs

**Use cases**:
- Automated processing and integration
- Data analysis and correlation
- Long-term archival
- API consumption

### HTML Export

The HTML export provides a formatted, human-readable report:

- **Styled presentation**: Professional formatting with CSS
- **Tabular data**: Easy-to-read tables for findings and metadata
- **Risk visualization**: Color-coded severity indicators
- **File information**: Complete file identity and provenance
- **Browser-viewable**: Open directly in any web browser

**Use cases**:
- Quick review and analysis
- Sharing with non-technical stakeholders
- Web-based dashboards
- Internal documentation

### PDF Export

The PDF export creates a portable, professional document:

- **Portable format**: View on any device without special software
- **Print-ready**: Professional formatting suitable for reports
- **Self-contained**: All data embedded in single file
- **Archival quality**: Standard format for long-term storage

**Use cases**:
- Official reports and documentation
- Compliance and audit trails
- Email distribution
- Long-term archival

## Advanced Features

### Database Access

Each export directory contains a SQLite database (`analysis.db`) with structured data:

```python
from src.file_analyzer.part4.persistence import AnalysisDatabase

# Open database
db = AnalysisDatabase('exports/20260105_193116/analysis.db')

# Query records
records = db.query_records(limit=100)

# Get specific record
record = db.get_record('REC-1CBB78674F91')

# Get findings
findings = db.get_findings(record_id='REC-1CBB78674F91')

# Close database
db.close()
```

### Custom Export Paths

To customize the export location, modify the `create_export_directory()` function in `analyze_file.py`:

```python
# Example: Export to a specific directory
export_dir = create_export_directory(base_path=Path("/custom/export/path"))
```

### Programmatic Export

Use the `Exporter` class for programmatic access:

```python
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat

# Open database
db = AnalysisDatabase('exports/20260105_193116/analysis.db')

# Create exporter
exporter = Exporter(db)

# Export specific formats
exporter.export_record(
    record_id='REC-1CBB78674F91',
    output_path='/path/to/export.json',
    format=ExportFormat.JSON
)

exporter.export_record(
    record_id='REC-1CBB78674F91',
    output_path='/path/to/export.html',
    format=ExportFormat.HTML
)

exporter.export_record(
    record_id='REC-1CBB78674F91',
    output_path='/path/to/export.pdf',
    format=ExportFormat.PDF
)

db.close()
```

### Bulk Export

Export entire sessions or cases:

```python
# Export entire session
exporter.export_session(
    session_id='SES-78730054',
    output_path='/path/to/session_export.json',
    format=ExportFormat.JSON
)

# Export entire case
exporter.export_case(
    case_id='CASE-B72DF055',
    output_path='/path/to/case_export.json',
    format=ExportFormat.JSON
)
```

## Requirements

### Dependencies

The multi-format export feature requires:

- **python-magic** (≥0.4.27) - Already included in core requirements
- **olefile** (≥0.46) - Already included in core requirements
- **weasyprint** (≥60.0) - **New requirement** for PDF generation

### Installation

Install all dependencies:

```bash
pip install -r requirements.txt
```

This will automatically install weasyprint and its dependencies for PDF generation.

## Production Considerations

### Storage Management

- **Disk space**: Each analysis generates ~50-70 KB of data (varies by file type)
- **Retention policy**: Implement automatic cleanup of old exports if needed
- **Backup**: The `exports/` directory should be included in backup strategies

### Performance

- **Export speed**: All three formats are generated in parallel during analysis
- **Typical times**: 
  - JSON: < 100ms
  - HTML: < 200ms
  - PDF: < 500ms (depends on weasyprint)

### Security

- **Sensitive data**: Exports may contain file hashes and metadata
- **Access control**: Protect the `exports/` directory with appropriate file permissions
- **Network sharing**: Be cautious when sharing exports containing sensitive file information

### Integration

The export system is designed for:

- **CI/CD pipelines**: Automated file scanning in build processes
- **SIEM integration**: JSON exports for security information systems
- **Reporting tools**: HTML/PDF exports for executive dashboards
- **Forensic analysis**: Complete data preservation for investigations

## Troubleshooting

### PDF Generation Issues

If PDF generation fails, the system will fall back to creating a text-based report. To resolve:

1. Ensure weasyprint is installed: `pip install weasyprint`
2. On Linux, install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0
   
   # CentOS/RHEL
   sudo yum install pango
   ```

### Disk Space Issues

If you're running low on disk space:

1. Clean up old exports:
   ```bash
   # Remove exports older than 30 days
   find exports/ -type d -mtime +30 -exec rm -rf {} +
   ```

2. Archive exports to compressed storage:
   ```bash
   # Create compressed archive
   tar -czf exports_archive_$(date +%Y%m%d).tar.gz exports/
   ```

### Permission Issues

If you encounter permission errors:

```bash
# Ensure proper permissions on exports directory
chmod 755 exports/
chmod 644 exports/*/*.json
chmod 644 exports/*/*.html
chmod 644 exports/*/*.pdf
```

## Migration from Temporary Storage

The previous version stored exports in temporary directories that were deleted on system cleanup. All new analyses now use persistent storage.

**Key differences**:
- ✅ Exports are now permanent
- ✅ All three formats are generated automatically
- ✅ Timestamped directories for organization
- ✅ Includes SQLite database for querying
- ✅ Production-ready for real-world use

## Support

For issues or questions about the export feature:

1. Check this guide for common solutions
2. Review the `TESTING_GUIDE.md` for validation procedures
3. Examine the source code in `src/file_analyzer/part4/exporter.py`
4. Open an issue on the project repository

## Future Enhancements

Planned improvements to the export system:

- [ ] Export to additional formats (SARIF, STIX/TAXII)
- [ ] Customizable report templates
- [ ] Export compression options
- [ ] Cloud storage integration (S3, Azure Blob)
- [ ] Automatic cleanup policies
- [ ] Export encryption for sensitive data
