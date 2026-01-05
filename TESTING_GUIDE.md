# File Analysis Application - PART 1 Testing Guide

**Version:** 1.0  
**Date:** 2026-01-05  
**Purpose:** Comprehensive testing instructions for PART 1 functionality

---

## Table of Contents

1. [Overview](#overview)
2. [Test Environment Setup](#test-environment-setup)
3. [Running Tests](#running-tests)
4. [Test Coverage](#test-coverage)
5. [Manual Testing Guide](#manual-testing-guide)
6. [Expected Outputs](#expected-outputs)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Testing Scenarios](#advanced-testing-scenarios)

---

## Overview

This guide provides complete testing instructions for PART 1 of the File Analysis Application, covering:
- Automated unit tests (42 test cases)
- Manual testing procedures
- Expected output validation
- Edge case testing
- Performance verification

### What PART 1 Tests

1. **Secure File Ingestion** - Binary read-only mode, size verification
2. **Cryptographic Identity** - MD5, SHA-1, SHA-256, SHA-512 hashing
3. **Magic-Byte Detection** - Signature detection with polyglot indicators
4. **Container Identification** - ZIP, OLE, PDF, PE, ELF, Mach-O, TAR
5. **Semantic File-Type Resolution** - DOCX≠ZIP, OOXML validation
6. **Extension & Deception Analysis** - Unicode deception, byte offsets
7. **Filesystem Metadata** - Timestamps, permissions, NTFS ADS
8. **Advanced Checks** - Extension mismatch, trailing data, polyglot

---

## Test Environment Setup

### Prerequisites

**Python Version:**
- Python 3.8 or higher required
- Python 3.12.x recommended (tested)

**Operating Systems:**
- Linux (full functionality)
- macOS (full functionality)
- Windows (full functionality with NTFS ADS detection)

### Installation Steps

#### 1. Clone Repository

```bash
git clone https://github.com/ShubhamNagar-023/File_Analysis_App_v1.git
cd File_Analysis_App_v1
```

#### 2. Create Virtual Environment (Recommended)

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

#### 3. Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Install testing dependencies
pip install pytest pytest-cov

# Verify installation
python -c "import magic, olefile; print('Dependencies OK')"
```

**If `python-magic` fails on Windows:**
```bash
pip install python-magic-bin
```

#### 4. Verify Installation

```bash
# Quick verification
python -m src.file_analyzer.analyzer --help

# Should not produce errors (help message may not exist)
```

---

## Running Tests

### Quick Test Run

```bash
# Run all tests (default)
python -m pytest tests/test_analyzer.py -v

# Expected output: 42 passed in ~0.3-0.5s
```

### Test Execution Options

#### 1. Basic Test Runs

```bash
# Quiet mode (summary only)
python -m pytest tests/test_analyzer.py -q

# Verbose mode (detailed output)
python -m pytest tests/test_analyzer.py -v

# Very verbose (show test docstrings)
python -m pytest tests/test_analyzer.py -vv
```

#### 2. Selective Test Execution

```bash
# Run specific test class
python -m pytest tests/test_analyzer.py::TestFileIngestion -v

# Run specific test method
python -m pytest tests/test_analyzer.py::TestFileIngestion::test_ingestion_regular_file -v

# Run tests matching pattern
python -m pytest tests/test_analyzer.py -k "ingestion" -v
```

#### 3. Coverage Reports

```bash
# Generate coverage report
python -m pytest tests/test_analyzer.py --cov=src/file_analyzer --cov-report=html

# View report
# Open htmlcov/index.html in browser

# Terminal coverage report
python -m pytest tests/test_analyzer.py --cov=src/file_analyzer --cov-report=term-missing
```

#### 4. Stop on First Failure

```bash
# Stop at first failure
python -m pytest tests/test_analyzer.py -x

# Stop after N failures
python -m pytest tests/test_analyzer.py --maxfail=3
```

#### 5. Show Output from Tests

```bash
# Show print statements
python -m pytest tests/test_analyzer.py -v -s

# Show captured output on failure
python -m pytest tests/test_analyzer.py -v --tb=short
```

---

## Test Coverage

### Complete Test Suite (42 Tests)

#### File Ingestion (4 tests)
```bash
python -m pytest tests/test_analyzer.py::TestFileIngestion -v
```

| Test | Purpose |
|------|---------|
| `test_ingestion_regular_file` | Verify normal file ingestion |
| `test_ingestion_file_not_found` | Handle missing files gracefully |
| `test_ingestion_empty_file` | Handle zero-byte files |
| `test_ingestion_symlink_detection` | Detect symbolic links |

**Expected Result:** 4/4 passed

---

#### Cryptographic Identity (1 test)
```bash
python -m pytest tests/test_analyzer.py::TestCryptographicIdentity -v
```

| Test | Purpose |
|------|---------|
| `test_hash_computation` | Verify all 4 hash algorithms |

**Expected Result:** 1/1 passed

---

#### Magic Detection (4 tests)
```bash
python -m pytest tests/test_analyzer.py::TestMagicDetection -v
```

| Test | Purpose |
|------|---------|
| `test_jpeg_detection` | Detect JPEG magic bytes |
| `test_pdf_detection` | Detect PDF magic bytes |
| `test_png_detection` | Detect PNG magic bytes |
| `test_zip_detection` | Detect ZIP magic bytes |

**Expected Result:** 4/4 passed

---

#### Container Identification (3 tests)
```bash
python -m pytest tests/test_analyzer.py::TestContainerIdentification -v
```

| Test | Purpose |
|------|---------|
| `test_no_container` | Handle non-container files |
| `test_pdf_container` | Identify PDF container |
| `test_zip_container` | Identify ZIP container |

**Expected Result:** 3/3 passed

---

#### Semantic File Type (7 tests)
```bash
python -m pytest tests/test_analyzer.py::TestSemanticFileType -v
```

| Test | Purpose |
|------|---------|
| `test_docx_classification` | DOCX ≠ ZIP validation |
| `test_jpeg_classification` | JPEG identification |
| `test_plain_text_classification` | Plain text detection |
| `test_plain_zip_vs_docx` | ZIP vs DOCX distinction |
| `test_png_classification` | PNG identification |
| `test_pptx_classification` | PPTX ≠ ZIP validation |
| `test_xlsx_classification` | XLSX ≠ ZIP validation |

**Expected Result:** 7/7 passed

---

#### Extension Analysis (3 tests)
```bash
python -m pytest tests/test_analyzer.py::TestExtensionAnalysis -v
```

| Test | Purpose |
|------|---------|
| `test_double_extension_detection` | Detect double extensions |
| `test_extension_mismatch` | Detect extension/type mismatch |
| `test_simple_extension` | Handle normal extensions |

**Expected Result:** 3/3 passed

---

#### Advanced Checks (1 test)
```bash
python -m pytest tests/test_analyzer.py::TestAdvancedChecks -v
```

| Test | Purpose |
|------|---------|
| `test_trailing_data_detection` | Detect trailing data in ZIP |

**Expected Result:** 1/1 passed

---

#### Filesystem Metadata (1 test)
```bash
python -m pytest tests/test_analyzer.py::TestFilesystemMetadata -v
```

| Test | Purpose |
|------|---------|
| `test_metadata_extraction` | Extract timestamps & permissions |

**Expected Result:** 1/1 passed

---

#### Summary & Output (3 tests)
```bash
python -m pytest tests/test_analyzer.py::TestSummary -v
python -m pytest tests/test_analyzer.py::TestJSONOutput -v
python -m pytest tests/test_analyzer.py::TestConvenienceFunction -v
```

| Test | Purpose |
|------|---------|
| `test_summary_generated` | Verify summary block |
| `test_valid_json_output` | Validate JSON output |
| `test_analyze_file_function` | Test convenience function |

**Expected Result:** 3/3 passed

---

#### PART 1 Improvements Tests (15 tests)

**Magic-Byte Scanning Coverage (3 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestMagicByteScanningCoverage -v
```

| Test | Purpose |
|------|---------|
| `test_scan_coverage_reporting` | Verify scan coverage metrics |
| `test_polyglot_detection` | Detect polyglot files |
| `test_deep_scan_for_small_files` | Deep scan for files ≤1MB |

---

**Byte Offset Reporting (2 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestByteOffsetReporting -v
```

| Test | Purpose |
|------|---------|
| `test_unicode_deception_offsets` | Byte offsets for Unicode chars |
| `test_all_analysis_blocks_have_byte_ranges` | Consistent byte ranges |

---

**Uniform Output Contract (2 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestUniformOutputContract -v
```

| Test | Purpose |
|------|---------|
| `test_all_analysis_blocks_have_required_fields` | Required fields present |
| `test_hash_outputs_normalized` | Hash output consistency |

---

**External Verification (2 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestExternalVerificationMethods -v
```

| Test | Purpose |
|------|---------|
| `test_magic_detection_has_verification` | Verification methods present |
| `test_ooxml_validation_has_verification` | OOXML verification methods |

---

**Plain Text Enhancement (2 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestPlainTextEnhancement -v
```

| Test | Purpose |
|------|---------|
| `test_encoding_detection` | BOM and encoding detection |
| `test_binary_masquerading_detection` | Detect binary masquerading |

---

**NTFS ADS Detection (1 test)**
```bash
python -m pytest tests/test_analyzer.py::TestNTFSADSDetection -v
```

| Test | Purpose |
|------|---------|
| `test_ads_platform_detection` | Platform-aware ADS detection |

---

**Broken OOXML Detection (1 test)**
```bash
python -m pytest tests/test_analyzer.py::TestBrokenOOXMLDetection -v
```

| Test | Purpose |
|------|---------|
| `test_missing_required_components` | Detect broken OOXML files |

---

**Ambiguity Handling (2 tests)**
```bash
python -m pytest tests/test_analyzer.py::TestAmbiguityHandling -v
```

| Test | Purpose |
|------|---------|
| `test_ambiguity_with_polyglot` | Handle polyglot ambiguity |
| `test_ambiguity_criteria_documented` | Verify ambiguity rules |

---

## Manual Testing Guide

### Basic Manual Test

#### 1. Create Test File

```bash
echo "This is a test file" > /tmp/test.txt
```

#### 2. Run Analysis

```bash
python -m src.file_analyzer.analyzer /tmp/test.txt
```

#### 3. Expected Output Structure

```json
{
  "file_info": { ... },
  "ingestion": {
    "analysis_name": "secure_file_ingestion",
    "output_value": {
      "status": "SUCCESS",
      "actual_size_bytes": 19,
      "size_match": true
    }
  },
  "cryptographic_identity": {
    "hashes": [
      {
        "analysis_name": "hash_md5",
        "output_value": "..."
      }
    ]
  },
  "summary": {
    "semantic_file_type": "PLAIN_TEXT",
    "classification_confidence": "HIGH"
  }
}
```

### Test Different File Types

#### JPEG Image
```bash
# Create a minimal JPEG (if you have one)
python -m src.file_analyzer.analyzer /path/to/image.jpg | python -m json.tool
```

**Expected:**
- `semantic_file_type`: "IMAGE_JPEG"
- `container_type`: null
- Magic signature at offset 0: `FFD8FF`

#### PDF Document
```bash
python -m src.file_analyzer.analyzer /path/to/document.pdf | python -m json.tool
```

**Expected:**
- `semantic_file_type`: "PDF"
- `container_type`: "PDF"
- Magic signature at offset 0: `%PDF`

#### DOCX Document
```bash
python -m src.file_analyzer.analyzer /path/to/document.docx | python -m json.tool
```

**Expected:**
- `semantic_file_type`: "DOCX"
- `container_type`: "ZIP"
- Required components: `[Content_Types].xml`, `word/document.xml`

#### ZIP Archive
```bash
# Create test ZIP
echo "file content" > /tmp/file1.txt
zip /tmp/test.zip /tmp/file1.txt
python -m src.file_analyzer.analyzer /tmp/test.zip | python -m json.tool
```

**Expected:**
- `semantic_file_type`: "ARCHIVE_ZIP"
- `container_type`: "ZIP"
- No OOXML components

---

## Expected Outputs

### Output Block Structure

Every analysis block should contain:

```json
{
  "analysis_name": "string",
  "library_or_method": "string",
  "input_byte_range": "0-N",
  "output_value": { /* analysis-specific */ },
  "evidence": [ /* supporting data */ ],
  "verification_method": "string",
  "failure_reason": null
}
```

### Hash Output Example

```json
{
  "analysis_name": "hash_sha256",
  "library_or_method": "hashlib.sha256",
  "input_byte_range": "0-19",
  "output_value": "f5ebdb8b3d723bd9902b9c9289f5515e...",
  "evidence": {
    "algorithm": "SHA256",
    "digest_length_bits": 256,
    "full_file_coverage": true
  },
  "verification_method": "Compare with: sha256sum test.txt",
  "failure_reason": null
}
```

### Summary Block Example

```json
{
  "container_type": "ZIP",
  "semantic_file_type": "DOCX",
  "classification_confidence": "HIGH",
  "classification_notes": "OOXML document with all required components",
  "detected_deception_flags": [],
  "ambiguity": {
    "is_ambiguous": false,
    "ambiguity_reasons": []
  }
}
```

---

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Problem:**
```
ModuleNotFoundError: No module named 'magic'
```

**Solution:**
```bash
pip install python-magic
# On Windows:
pip install python-magic-bin
```

---

#### 2. Test Failures on Windows

**Problem:**
```
FAILED test_ads_platform_detection - AssertionError
```

**Solution:**
This is expected on non-Windows platforms. The test verifies platform-aware behavior.

---

#### 3. Encoding Issues

**Problem:**
```
UnicodeDecodeError: 'utf-8' codec can't decode
```

**Solution:**
This is expected for binary files. The analyzer handles this gracefully.

---

#### 4. Permission Errors

**Problem:**
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
```bash
# Ensure read permissions
chmod 644 /path/to/file

# Or run with appropriate permissions
sudo python -m pytest tests/test_analyzer.py -v
```

---

### Validating Test Results

#### Check Test Count
```bash
python -m pytest tests/test_analyzer.py --collect-only | grep "test session starts" -A 1
```

**Expected:** `collected 42 items`

#### Verify Coverage
```bash
python -m pytest tests/test_analyzer.py --cov=src/file_analyzer --cov-report=term
```

**Expected:** >90% coverage on `analyzer.py`

---

## Advanced Testing Scenarios

### 1. Testing Unicode Deception

```python
# Create file with RTL override
filename = "test\u202Etxt.exe"  # Displays as "testexe.txt"
with open(filename, 'w') as f:
    f.write("test")

# Analyze
from src.file_analyzer import FileAnalyzer
analyzer = FileAnalyzer(filename)
results = analyzer.analyze()

# Verify detection
ext_analysis = results['extension_analysis']['output_value']
assert len(ext_analysis['unicode_deception']) > 0
```

### 2. Testing Polyglot Files

```python
# Create ZIP+PDF polyglot
import zipfile
with zipfile.ZipFile('/tmp/polyglot.zip', 'w') as zf:
    zf.writestr('file.txt', 'content')

# Add PDF signature
with open('/tmp/polyglot.zip', 'rb') as f:
    data = f.read()
with open('/tmp/polyglot.zip', 'wb') as f:
    f.write(data + b'\n%PDF-1.4\n')

# Analyze
analyzer = FileAnalyzer('/tmp/polyglot.zip')
results = analyzer.analyze()

# Verify polyglot detection
magic = results['magic_detection']['output_value']
assert len(magic['polyglot_indicators']) > 0
```

### 3. Testing Broken OOXML

```python
import zipfile

# Create invalid DOCX (missing word/document.xml)
with zipfile.ZipFile('/tmp/broken.docx', 'w') as zf:
    zf.writestr('[Content_Types].xml', '<?xml version="1.0"?>')
    # Missing word/document.xml

# Analyze
analyzer = FileAnalyzer('/tmp/broken.docx')
results = analyzer.analyze()

# Verify detection
semantic = results['semantic_file_type']['output_value']
assert semantic['classification_confidence'] in ['MEDIUM', 'LOW']
```

### 4. Testing Extension Mismatch

```bash
# Create text file with .jpg extension
echo "This is text" > /tmp/fake.jpg

# Analyze
python -m src.file_analyzer.analyzer /tmp/fake.jpg

# Check for extension_mismatch in advanced_checks
```

---

## Performance Testing

### Benchmark Test

```bash
# Create 1MB test file
dd if=/dev/urandom of=/tmp/1mb.bin bs=1M count=1

# Time analysis
time python -m src.file_analyzer.analyzer /tmp/1mb.bin > /dev/null
```

**Expected:** <1 second for 1MB file

### Memory Usage

```bash
# Monitor memory usage
/usr/bin/time -v python -m src.file_analyzer.analyzer /tmp/1mb.bin
```

**Expected:** <50MB memory for 1MB file

---

## Continuous Integration Testing

### GitHub Actions

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: [3.8, 3.9, '3.10', '3.11', '3.12']
    
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      run: |
        python -m pytest tests/test_analyzer.py -v --cov=src/file_analyzer
```

---

## Test Data Recommendations

### Minimal Test Files

Create these files for comprehensive testing:

1. **Plain Text:** `test.txt` (UTF-8)
2. **JPEG:** `test.jpg` (valid JPEG)
3. **PNG:** `test.png` (valid PNG)
4. **PDF:** `test.pdf` (valid PDF)
5. **ZIP:** `test.zip` (plain archive)
6. **DOCX:** `test.docx` (valid Office document)
7. **XLSX:** `test.xlsx` (valid Excel document)
8. **PPTX:** `test.pptx` (valid PowerPoint document)

### Edge Cases

9. **Empty file:** 0 bytes
10. **Polyglot:** ZIP+PDF hybrid
11. **Unicode filename:** RTL override characters
12. **Double extension:** `file.txt.exe`
13. **Broken OOXML:** Missing required components
14. **Trailing data:** ZIP with extra bytes

---

## Summary

### Quick Test Checklist

- [ ] Install dependencies: `pip install -r requirements.txt pytest`
- [ ] Run full test suite: `python -m pytest tests/test_analyzer.py -v`
- [ ] Verify 42/42 tests pass
- [ ] Test with real files: JPEG, PDF, DOCX, ZIP
- [ ] Validate JSON output structure
- [ ] Check hash computation: `sha256sum` vs analyzer output
- [ ] Test edge cases: empty file, symlink, broken OOXML
- [ ] Verify platform-specific features (NTFS ADS on Windows)

### Expected Test Results

```
================================ test session starts ================================
collected 42 items

tests/test_analyzer.py::TestFileIngestion::test_ingestion_empty_file PASSED   [  2%]
tests/test_analyzer.py::TestFileIngestion::test_ingestion_file_not_found PASSED [ 4%]
...
tests/test_analyzer.py::TestAmbiguityHandling::test_ambiguity_with_polyglot PASSED [100%]

================================ 42 passed in 0.34s =================================
```

---

## Additional Resources

- **Main Documentation:** `README.md`
- **Verification Report:** `CODE_VS_DOC_VERIFICATION.md`
- **Improvements Documentation:** `PART1_IMPROVEMENTS.md`
- **Requirements Specification:** `File_analysis_app_plan`

---

## Support

For issues or questions:
1. Check `VERIFICATION_SUMMARY.md` for known issues
2. Review test output with `-vv` flag for details
3. Examine `CODE_VS_DOC_VERIFICATION.md` for implementation details

---

**Last Updated:** 2026-01-05  
**Test Suite Version:** 1.0 (42 tests)  
**Compatibility:** Python 3.8+ on Linux/macOS/Windows
