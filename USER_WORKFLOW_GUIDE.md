# User Workflow Guide - File Analysis Application

## Table of Contents
1. [Getting Started](#getting-started)
2. [Basic Workflow](#basic-workflow)
3. [Advanced Workflows](#advanced-workflows)
4. [Use Case Examples](#use-case-examples)
5. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites
- Python 3.8+ installed
- Node.js 18+ installed (for desktop UI)
- 2GB RAM minimum
- 100MB disk space

### Installation

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/ShubhamNagar-023/File_Analysis_App_v1.git
   cd File_Analysis_App_v1
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python -m pytest tests/ -v
   ```

---

## Basic Workflow

### Workflow 1: Quick File Analysis (Recommended for Beginners)

**Goal**: Analyze a single suspicious file and view results

#### Step 1: Start the Application
```bash
python start.py
```

**What happens:**
- ✅ API server starts on port 5000
- ✅ Electron desktop UI launches
- ✅ Backend connection established (green indicator)

![Expected: Desktop window opens with green "Connected" status]

#### Step 2: Analyze Your First File

1. **Click the "Analyze" button** (or press Ctrl+A)
   - A file selection dialog opens

2. **Select a file to analyze**
   - Choose any file (document, image, executable, archive, etc.)
   - Click "Open"

3. **Wait for analysis**
   - Progress indicator shows "Analyzing file..."
   - Typically takes 2-10 seconds depending on file size

4. **View Results**
   - Results appear automatically in the "File Overview" tab
   - Risk score and severity are prominently displayed

#### Step 3: Explore Analysis Results

**File Overview Tab** (Ctrl+1):
- File name, size, type
- SHA256, MD5, SHA1 hashes
- File type detection results
- Container information (if applicable)

**Risk & Findings Tab** (Ctrl+2):
- Risk score (0-100)
- Severity level (Informational, Low, Medium, High, Critical)
- Security heuristics detected
- List of findings with descriptions

**Metadata Tab** (Ctrl+3):
- Extracted metadata
- File properties
- Timestamps

**Hex Viewer Tab** (Ctrl+4):
- Raw file content in hexadecimal
- Click on findings to jump to that offset

**Strings Tab** (Ctrl+5):
- Extracted text strings
- URLs, file paths, potential secrets

**Timeline Tab** (Ctrl+6):
- Analysis timeline
- File creation/modification times

#### Step 4: Export Results

1. **Select Export Format**
   - Go to File → Export (or press Ctrl+E)

2. **Choose format**:
   - **JSON**: Machine-readable, complete data
   - **HTML**: Web-viewable, formatted report
   - **PDF**: Professional, printable document

3. **Save the report**
   - Choose location
   - Results saved automatically

**Export Location**: `exports/[timestamp]/[filename]_analysis.[format]`

---

### Workflow 2: Using Command Line (For Automation)

**Goal**: Analyze files without the GUI for scripting/automation

#### Step 1: Analyze a Single File
```bash
python analyze_file.py path/to/suspicious-file.exe
```

**Output:**
- Terminal shows summary (file type, risk score, severity)
- Full results saved to `exports/[timestamp]/`

#### Step 2: View Results
```bash
# Results are in the exports directory
cd exports/[latest-timestamp]/
ls -la

# View JSON report
cat suspicious-file_analysis.json

# Open HTML report in browser
open suspicious-file_analysis.html   # macOS
xdg-open suspicious-file_analysis.html   # Linux
start suspicious-file_analysis.html  # Windows
```

#### Step 3: Batch Analysis
```bash
# Analyze multiple files
for file in test_files/*; do
    python analyze_file.py "$file"
done

# Or analyze all files in a directory
python analyze_file.py test_files/*.pdf
```

---

### Workflow 3: Using REST API (For Integration)

**Goal**: Integrate file analysis into your own application

#### Step 1: Start API Server
```bash
python api_server.py --port 5000
```

Or for network access:
```bash
python api_server.py --host 0.0.0.0 --port 8080
```

#### Step 2: Send Files for Analysis

**Using curl:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@suspicious.exe" \
  -F "case_name=Investigation 2026-01" \
  -F "session_name=Malware Analysis"
```

**Using Python:**
```python
import requests

with open('suspicious.exe', 'rb') as f:
    files = {'file': f}
    data = {
        'case_name': 'Investigation 2026-01',
        'session_name': 'Malware Analysis'
    }
    response = requests.post(
        'http://localhost:5000/api/analyze',
        files=files,
        data=data
    )
    result = response.json()
    print(f"Risk Score: {result['results']['risk_score']}")
    print(f"Severity: {result['results']['severity']}")
```

**Using JavaScript:**
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('case_name', 'Investigation 2026-01');

const response = await fetch('http://localhost:5000/api/analyze', {
    method: 'POST',
    body: formData
});

const result = await response.json();
console.log('Risk Score:', result.results.risk_score);
```

#### Step 3: Retrieve Results
```bash
# List all records
curl http://localhost:5000/api/records

# Get specific record
curl http://localhost:5000/api/records/REC-XXXXX

# Get statistics
curl http://localhost:5000/api/stats
```

---

## Advanced Workflows

### Workflow 4: Case-Based Investigation

**Goal**: Organize multiple file analyses into cases and sessions

**Scenario**: You're investigating a potential malware campaign and need to analyze multiple related files.

#### Step 1: Start the Application
```bash
python start.py
```

#### Step 2: View Existing Cases
1. Look at the **Case Selector** dropdown in the toolbar
2. All existing cases are listed there
3. Each case has a unique ID and name

#### Step 3: Select a Case
1. Click the **Case Selector** dropdown
2. Choose a case (e.g., "Investigation 2026-01")
3. Sessions for that case load automatically in the **Session Selector**

#### Step 4: Select a Session
1. Click the **Session Selector** dropdown
2. Choose a session (e.g., "Malware Analysis Session")
3. All records for that session appear in the left panel

#### Step 5: Analyze Multiple Files
1. Click "Analyze" for each file
2. Files are automatically added to the current case/session
3. View all related analyses together

#### Step 6: Navigate Between Records
1. Click any record in the left panel
2. Details appear in the main area
3. Compare findings across multiple files
4. Correlate patterns and behaviors

**Benefits:**
- ✅ Keep related analyses organized
- ✅ Track investigation progress
- ✅ Generate case-wide reports
- ✅ Collaborate with team members

---

### Workflow 5: Forensic Analysis Deep Dive

**Goal**: Perform detailed analysis of a suspicious file

**Scenario**: You have a potentially malicious document and need to investigate thoroughly.

#### Step 1: Analyze the File
```bash
python start.py
# Click Analyze → Select file → Wait for results
```

#### Step 2: Check Risk Assessment
1. Go to **Risk & Findings** tab (Ctrl+2)
2. Review the risk score (0-100)
3. Check severity level
4. Read security heuristics

**Risk Score Interpretation:**
- **0-20**: Informational - Likely safe
- **21-40**: Low - Minor concerns
- **41-60**: Medium - Investigate further
- **61-80**: High - Suspicious activity detected
- **81-100**: Critical - Strong malware indicators

#### Step 3: Examine File Properties
1. Go to **File Overview** tab (Ctrl+1)
2. Verify file type matches extension
3. Check for mismatched magic bytes
4. Review hashes for searching databases

**Red Flags:**
- ❌ Extension doesn't match file type (e.g., .txt is actually .exe)
- ❌ Multiple file types detected (polyglot)
- ❌ Trailing data after file end

#### Step 4: Investigate Metadata
1. Go to **Metadata** tab (Ctrl+3)
2. Look for embedded metadata
3. Check for anomalies

**Suspicious Indicators:**
- ❌ Missing or fake metadata
- ❌ Unusual authors or creation tools
- ❌ Suspicious timestamps (dates in future)
- ❌ Hidden macros or scripts

#### Step 5: Analyze Findings
1. Go to **Risk & Findings** tab
2. Click on each finding for details
3. Note the offset and description

**Common Findings:**
- Suspicious strings (URLs, IP addresses)
- Encoded data (Base64, hex)
- Executable code in documents
- Obfuscated scripts
- Known malware signatures

#### Step 6: Examine Raw Content
1. Go to **Hex Viewer** tab (Ctrl+H)
2. Review raw bytes
3. Click findings to jump to specific offsets
4. Look for embedded executables or scripts

#### Step 7: Extract Strings
1. Go to **Strings** tab (Ctrl+S)
2. Review extracted text
3. Look for:
   - URLs and domains
   - File paths
   - Registry keys
   - Command-line arguments
   - IP addresses
   - Email addresses

#### Step 8: Document and Export
1. Take notes on findings
2. Export full report (File → Export → PDF)
3. Share with team or incident response

---

### Workflow 6: Comparing Multiple Files

**Goal**: Compare analysis results across multiple files

#### Step 1: Analyze Files
```bash
# Analyze all files
python analyze_file.py file1.exe
python analyze_file.py file2.exe
python analyze_file.py file3.exe
```

Or use the GUI to analyze multiple files to the same case/session.

#### Step 2: View in Dashboard
1. Select the case containing all files
2. Select the session
3. All records appear in the left panel

#### Step 3: Compare Results
1. Click first file → Note risk score and findings
2. Click second file → Compare with first
3. Look for patterns:
   - Similar risk scores
   - Common strings
   - Same file types
   - Related metadata

#### Step 4: Identify Patterns
**Look for:**
- Files with same hashes (duplicates)
- Files from same author/creator
- Similar suspicious patterns
- Common URLs or domains
- Related timestamps

---

## Use Case Examples

### Use Case 1: SOC Analyst - Triage Suspicious Email Attachment

**Scenario**: You received a phishing report with an attached PDF.

**Workflow:**
1. Save attachment as `suspicious_invoice.pdf`
2. Start application: `python start.py`
3. Click "Analyze" → Select the PDF
4. Check risk score:
   - **High/Critical**: Immediate escalation, block hash
   - **Medium**: Further investigation needed
   - **Low**: Likely false positive, verify sender
5. Review findings for:
   - Embedded JavaScript
   - External URLs
   - Suspicious metadata
6. Export report for incident ticket
7. Share hash with threat intel team

**Time**: 2-5 minutes

---

### Use Case 2: Incident Responder - Analyze Malware Sample

**Scenario**: Endpoint detected suspicious executable, need quick assessment.

**Workflow:**
1. Isolate sample to safe environment
2. Calculate hash: `sha256sum malware.exe`
3. Start analysis: `python analyze_file.py malware.exe`
4. Review terminal output for quick summary
5. Open desktop UI for detailed analysis
6. Check for:
   - Known malware signatures
   - Packing/obfuscation
   - Suspicious imports
   - Network indicators (IPs, domains)
7. Extract IOCs (Indicators of Compromise)
8. Update SIEM/EDR with findings

**Time**: 5-10 minutes

---

### Use Case 3: Forensic Investigator - Evidence Analysis

**Scenario**: Analyzing files from suspect's computer during investigation.

**Workflow:**
1. Create case: Uploads analyzed to "Investigation Case-2026-001"
2. Create sessions by evidence type:
   - Session 1: Documents
   - Session 2: Images
   - Session 3: Archives
   - Session 4: Executables
3. Batch analyze files:
   ```bash
   for file in evidence/*; do
       python analyze_file.py "$file"
   done
   ```
4. Review in desktop UI organized by session
5. Flag high-risk items for detailed analysis
6. Generate case report with all findings
7. Export PDFs for court proceedings

**Time**: Varies by evidence volume

---

### Use Case 4: Security Researcher - Analyze Unknown File Type

**Scenario**: Received unknown file format, need to understand structure.

**Workflow:**
1. Analyze file: `python analyze_file.py unknown.bin`
2. Check file type detection results
3. Review magic bytes in Hex Viewer
4. Look for embedded files (container detection)
5. Extract strings for clues
6. Compare with known file signatures
7. Document findings for future reference

**Time**: 10-30 minutes

---

### Use Case 5: DevSecOps - CI/CD Integration

**Scenario**: Scan artifacts before deployment.

**Workflow:**
1. Add to CI/CD pipeline:
   ```yaml
   - name: Security Scan
     run: |
       python analyze_file.py build/app.zip
       # Check exit code for risk level
   ```
2. API integration for automated scanning:
   ```python
   import requests
   import sys
   
   response = requests.post(
       'http://scanner.internal:5000/api/analyze',
       files={'file': open('build/app.zip', 'rb')}
   )
   
   result = response.json()
   if result['results']['risk_score'] > 60:
       print("FAIL: High risk detected!")
       sys.exit(1)
   ```
3. Block deployment if high risk detected
4. Generate security report for audit

**Time**: Automated, ~2-10 seconds per file

---

## Troubleshooting

### Issue 1: Backend Not Connected

**Symptom**: Red "Disconnected" indicator in UI

**Solutions:**
1. Check if API server is running:
   ```bash
   curl http://localhost:5000/api/health
   ```

2. Start API server manually:
   ```bash
   python api_server.py --port 5000
   ```

3. Check for port conflicts:
   ```bash
   # Find process using port 5000
   lsof -i :5000          # macOS/Linux
   netstat -ano | findstr :5000  # Windows
   ```

4. Try different port:
   ```bash
   python api_server.py --port 8080
   # Update API client to use port 8080
   ```

---

### Issue 2: Analysis Fails

**Symptom**: Error message when analyzing file

**Solutions:**
1. Check file permissions:
   ```bash
   ls -l suspicious_file.exe
   chmod +r suspicious_file.exe
   ```

2. Check file size (very large files may timeout):
   ```bash
   ls -lh suspicious_file.exe
   # Files > 100MB may need special handling
   ```

3. Check disk space:
   ```bash
   df -h
   ```

4. View detailed error in logs:
   ```bash
   tail -f /tmp/api_server.log
   ```

---

### Issue 3: Missing Dependencies

**Symptom**: ImportError or ModuleNotFoundError

**Solutions:**
1. Reinstall dependencies:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

2. Check Python version:
   ```bash
   python --version
   # Should be 3.8 or higher
   ```

3. Use virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

---

### Issue 4: Electron UI Won't Start

**Symptom**: Desktop UI doesn't launch

**Solutions:**
1. Check Node.js installation:
   ```bash
   node --version
   # Should be 18.0 or higher
   ```

2. Install Electron dependencies:
   ```bash
   cd electron
   npm install
   ```

3. Try CLI mode instead:
   ```bash
   python start.py --cli
   ```

4. Start components separately:
   ```bash
   # Terminal 1: API server
   python api_server.py
   
   # Terminal 2: Electron UI
   cd electron
   npm start
   ```

---

### Issue 5: Export Fails

**Symptom**: Can't export reports

**Solutions:**
1. Check write permissions:
   ```bash
   mkdir -p exports
   chmod +w exports
   ```

2. Check disk space:
   ```bash
   df -h
   ```

3. Try different format:
   - If PDF fails, try JSON or HTML
   - PDF requires additional system libraries

4. Manual export from database:
   ```bash
   sqlite3 exports/[timestamp]/analysis.db
   .mode json
   .output export.json
   SELECT * FROM records;
   .quit
   ```

---

## Quick Reference

### Keyboard Shortcuts
- `Ctrl+A` - Analyze file
- `Ctrl+O` - Open database
- `Ctrl+E` - Export record
- `Ctrl+R` / `F5` - Refresh data
- `Ctrl+1-6` - Switch tabs
- `Ctrl+D` - Toggle dark mode
- `Ctrl+Q` - Quit application

### Command Line Quick Start
```bash
# Analyze single file
python analyze_file.py file.exe

# Start desktop app
python start.py

# Start API server only
python api_server.py --port 5000

# Run tests
python -m pytest tests/ -v
```

### API Quick Reference
```bash
# Health check
curl http://localhost:5000/api/health

# Analyze file
curl -X POST http://localhost:5000/api/analyze -F "file=@file.exe"

# List records
curl http://localhost:5000/api/records

# Get statistics
curl http://localhost:5000/api/stats
```

---

## Best Practices

### For SOC Analysts
1. ✅ Create cases by incident type
2. ✅ Use consistent session naming
3. ✅ Export reports for tickets
4. ✅ Share hashes with threat intel
5. ✅ Document high-risk findings

### For Forensic Investigators
1. ✅ Organize evidence by source/type
2. ✅ Maintain chain of custody
3. ✅ Export all reports to PDF
4. ✅ Keep original files separate
5. ✅ Document all findings thoroughly

### For Security Researchers
1. ✅ Use descriptive case names
2. ✅ Take screenshots of findings
3. ✅ Export in multiple formats
4. ✅ Compare with known samples
5. ✅ Share IOCs with community

### For DevSecOps
1. ✅ Integrate into CI/CD
2. ✅ Set risk score thresholds
3. ✅ Automate reporting
4. ✅ Track trends over time
5. ✅ Block high-risk artifacts

---

## Getting Help

### Documentation
- `README.md` - Main documentation
- `API.md` - REST API reference
- `QUICKSTART.md` - Quick setup guide
- `TESTING.md` - Testing guide
- `docs/FRONTEND_BACKEND_INTEGRATION.md` - Integration details

### Support
- Check documentation first
- Review troubleshooting section
- Check GitHub issues
- Test with sample files in `test_files/`

### Sample Files
Test the application with provided samples:
```bash
python analyze_file.py test_files/normal_archive.zip
python analyze_file.py test_files/document.pdf.exe
python analyze_file.py test_files/high_entropy_data.bin
```

---

**Version**: 1.0.0  
**Last Updated**: 2026-01-06  
**Status**: Production Ready ✅
