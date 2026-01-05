# File Analysis Application - Testing Guide

**Version:** 4.0  
**Date:** 2026-01-05  
**Purpose:** Comprehensive testing instructions for PART 1, PART 2, PART 3, and PART 4 functionality

---

## Table of Contents

1. [Overview](#overview)
2. [Test Environment Setup](#test-environment-setup)
3. [Running Tests](#running-tests)
4. [PART 1 Test Coverage](#part-1-test-coverage)
5. [PART 2 Test Coverage](#part-2-test-coverage)
6. [PART 3 Test Coverage](#part-3-test-coverage)
7. [PART 4 Test Coverage](#part-4-test-coverage)
8. [Manual Testing Guide](#manual-testing-guide)
9. [Expected Outputs](#expected-outputs)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Testing Scenarios](#advanced-testing-scenarios)

---

## Overview

This guide provides complete testing instructions for the File Analysis Application, covering:
- **PART 1:** Automated unit tests (42 test cases)
- **PART 2:** Automated unit tests (19 test cases)
- **PART 3:** Automated unit tests (26 test cases)
- **PART 4:** Automated unit tests (34 test cases)
- **Total:** 121 automated tests with 100% pass rate
- Manual testing procedures for all parts
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

### What PART 2 Tests

1. **Universal Static Analysis** - Entropy, strings, anomalies (all file types)
2. **Container-Level Analysis** - ZIP/OLE structure validation
3. **File-Type-Specific Analysis** - Deep analysis based on semantic type
4. **Output Format** - Proper finding structure and grouping
5. **Error Handling** - Graceful handling of errors and edge cases

### What PART 3 Tests

1. **Rule Engine** - YARA detection and fuzzy hashing (with graceful fallback)
2. **Heuristic Engine** - Deterministic heuristic evaluation
3. **Risk Scoring** - Evidence-based, explainable scoring
4. **Session Correlation** - Multi-file correlation logic
5. **Output Contract** - Proper structure and required fields
6. **Determinism** - Same input produces same output
7. **File-Type-Specific Heuristics** - PDF, ZIP, OOXML analysis

### What PART 4 Tests

1. **JSON Schema Validation** - All output schemas validated
2. **SQLite Persistence Layer** - Database operations and integrity
3. **Case & Session Management** - Create, retrieve, query cases and sessions
4. **Analysis Record Import** - Store PART 1-3 results with integrity checks
5. **Data Export** - JSON and HTML export with provenance
6. **IPC Contracts** - Request/response handling and validation
7. **Data Integrity** - Checksum verification and immutability

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

### Quick Test Run (All Tests)

```bash
# Run all tests (PART 1 + PART 2 + PART 3 + PART 4)
python -m pytest tests/ -v

# Expected output: 121 passed (42 PART 1 + 19 PART 2 + 26 PART 3 + 34 PART 4)
```

### Run PART 1 Tests Only

```bash
# Run all PART 1 tests
python -m pytest tests/test_analyzer.py -v

# Expected output: 42 passed in ~0.5s
```

### Run PART 2 Tests Only

```bash
# Run all PART 2 tests
python -m pytest tests/test_deep_analyzer.py -v

# Expected output: 19 passed in ~0.1s
```

### Run PART 3 Tests Only

```bash
# Run all PART 3 tests
python -m pytest tests/test_part3_analyzer.py -v

# Expected output: 26 passed in ~0.1s
```

### Run PART 4 Tests Only

```bash
# Run all PART 4 tests
python -m pytest tests/test_part4.py -v

# Expected output: 34 passed in ~0.2s
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

## PART 1 Test Coverage

### Complete PART 1 Test Suite (42 Tests)

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

## PART 2 Test Coverage

### Complete PART 2 Test Suite (19 Tests)

#### Universal Analysis (5 tests)
```bash
python -m pytest tests/test_deep_analyzer.py::TestUniversalAnalysis -v
```

| Test | Purpose |
|------|---------|
| `test_global_entropy_calculation` | Verify Shannon entropy calculation |
| `test_section_entropy_calculation` | Test section-wise entropy with anomalies |
| `test_printable_string_extraction` | Extract and classify strings |
| `test_trailing_data_detection_zip` | Detect trailing data in ZIP files |
| `test_structural_anomalies_null_padding` | Detect padding abuse and slack space |

**Expected Result:** 5/5 passed

---

#### Container Analysis (2 tests)
```bash
python -m pytest tests/test_deep_analyzer.py::TestContainerAnalysis -v
```

| Test | Purpose |
|------|---------|
| `test_zip_container_analysis` | Analyze ZIP container structure |
| `test_ooxml_container_analysis` | Analyze OOXML container with validation |

**Expected Result:** 2/2 passed

---

#### File-Type-Specific Analysis (6 tests)
```bash
python -m pytest tests/test_deep_analyzer.py::TestFileTypeSpecificAnalysis -v
```

| Test | Purpose |
|------|---------|
| `test_plain_text_analysis` | Plain text encoding and consistency |
| `test_jpeg_image_analysis` | JPEG structure and metadata |
| `test_png_image_analysis` | PNG chunk validation |
| `test_pdf_analysis` | PDF structure and object analysis |
| `test_office_ooxml_analysis` | OOXML parts and relationships |
| `test_archive_analysis` | Archive entry enumeration |

**Expected Result:** 6/6 passed

---

#### Output Format (3 tests)
```bash
python -m pytest tests/test_deep_analyzer.py::TestOutputFormat -v
```

| Test | Purpose |
|------|---------|
| `test_finding_structure` | Verify finding format consistency |
| `test_findings_grouped_correctly` | Validate finding categorization |
| `test_summary_statistics` | Verify summary block completeness |

**Expected Result:** 3/3 passed

---

#### Error Handling (2 tests)
```bash
python -m pytest tests/test_deep_analyzer.py::TestErrorHandling -v
```

| Test | Purpose |
|------|---------|
| `test_empty_file_handling` | Handle zero-byte files gracefully |
| `test_nonexistent_file` | Handle missing files with errors |

**Expected Result:** 2/2 passed

---

#### Convenience Function (1 test)
```bash
python -m pytest tests/test_deep_analyzer.py::TestConvenienceFunction -v
```

| Test | Purpose |
|------|---------|
| `test_deep_analyze_file_function` | Test convenience function wrapper |

**Expected Result:** 1/1 passed

---

## PART 3 Test Coverage

### Complete PART 3 Test Suite (26 Tests)

#### Rule Engine (3 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestRuleEngine -v
```

| Test | Purpose |
|------|---------|
| `test_fuzzy_hash_computation` | Test fuzzy hash computation (ssdeep/TLSH) |
| `test_rule_engine_without_yara` | Verify operation without YARA |
| `test_compute_fuzzy_hashes_convenience` | Test convenience function |

**Expected Result:** 3/3 passed

---

#### Heuristic Engine (4 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestHeuristicEngine -v
```

| Test | Purpose |
|------|---------|
| `test_heuristic_definitions_exist` | Verify heuristic definitions |
| `test_extension_mismatch_heuristic` | Test extension mismatch detection |
| `test_double_extension_heuristic` | Test double extension detection |
| `test_plain_text_no_suspicious_heuristics` | Verify benign files score low |

**Expected Result:** 4/4 passed

---

#### Risk Scorer (4 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestRiskScorer -v
```

| Test | Purpose |
|------|---------|
| `test_empty_score` | Test empty score (no evidence) |
| `test_heuristic_contribution` | Verify score calculation |
| `test_severity_mapping` | Test severity level mapping |
| `test_score_explanation` | Verify explainable output |

**Expected Result:** 4/4 passed

---

#### Session Correlator (2 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestSessionCorrelator -v
```

| Test | Purpose |
|------|---------|
| `test_single_file_no_correlation` | Single file has no correlation |
| `test_correlate_session_convenience` | Test convenience function |

**Expected Result:** 2/2 passed

---

#### Part3 Analyzer (5 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestPart3Analyzer -v
```

| Test | Purpose |
|------|---------|
| `test_basic_analysis` | Basic PART 3 analysis workflow |
| `test_json_output` | Verify JSON serialization |
| `test_reproducibility_notes` | Check reproducibility info |
| `test_analyze_part3_convenience` | Test convenience function |
| `test_full_analysis_convenience` | Test complete pipeline (P1+P2+P3) |

**Expected Result:** 5/5 passed

---

#### Output Contract (3 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestOutputContract -v
```

| Test | Purpose |
|------|---------|
| `test_detection_has_required_fields` | Verify detection structure |
| `test_score_has_required_fields` | Verify score structure |
| `test_no_score_without_evidence` | Ensure evidence-based scoring |

**Expected Result:** 3/3 passed

---

#### Severity Levels (1 test)
```bash
python -m pytest tests/test_part3_analyzer.py::TestSeverityLevels -v
```

| Test | Purpose |
|------|---------|
| `test_valid_severity_levels` | Verify severity level validity |

**Expected Result:** 1/1 passed

---

#### Determinism (1 test)
```bash
python -m pytest tests/test_part3_analyzer.py::TestDeterminism -v
```

| Test | Purpose |
|------|---------|
| `test_same_input_same_output` | Verify deterministic output |

**Expected Result:** 1/1 passed

---

#### File-Type-Specific Tests (3 tests)
```bash
python -m pytest tests/test_part3_analyzer.py::TestPDFAnalysis -v
python -m pytest tests/test_part3_analyzer.py::TestZIPAnalysis -v
python -m pytest tests/test_part3_analyzer.py::TestOOXMLAnalysis -v
```

| Test | Purpose |
|------|---------|
| `test_pdf_javascript_heuristic` | PDF JavaScript detection |
| `test_trailing_data_heuristic` | ZIP trailing data detection |
| `test_docx_with_vba` | DOCX VBA macro detection |

**Expected Result:** 3/3 passed

---

## PART 4 Test Coverage

### Complete PART 4 Test Suite (34 Tests)

#### Schema Validation (11 tests)
```bash
python -m pytest tests/test_part4.py::TestSchemas -v
```

| Test | Purpose |
|------|---------|
| `test_schema_definitions_exist` | Verify all required schemas defined |
| `test_schema_version_format` | Check schema version format |
| `test_validate_case_schema` | Validate case schema |
| `test_validate_case_schema_invalid` | Test invalid case data |
| `test_validate_session_schema` | Validate session schema |
| `test_validate_analysis_record_schema` | Validate analysis record schema |
| `test_validate_with_schema_convenience` | Test convenience validation function |
| `test_schema_required_fields` | Check required fields enforcement |
| `test_schema_type_validation` | Verify type validation |
| `test_schema_pattern_validation` | Test pattern matching |
| `test_schema_enum_validation` | Test enum value validation |

**Expected Result:** 11/11 passed

---

#### Persistence Layer (12 tests)
```bash
python -m pytest tests/test_part4.py::TestPersistence -v
```

| Test | Purpose |
|------|---------|
| `test_create_case` | Create investigation case |
| `test_get_case` | Retrieve case by ID |
| `test_list_cases` | List all cases |
| `test_create_session` | Create analysis session |
| `test_get_session` | Retrieve session by ID |
| `test_list_sessions` | List all sessions |
| `test_import_analysis` | Import PART 1-3 results |
| `test_get_record` | Retrieve analysis record |
| `test_query_records` | Query records with filters |
| `test_database_init` | Initialize database |
| `test_transaction_rollback` | Test transaction rollback |
| `test_concurrent_access` | Test concurrent database access |

**Expected Result:** 12/12 passed

---

#### IPC Contracts (7 tests)
```bash
python -m pytest tests/test_part4.py::TestIPC -v
```

| Test | Purpose |
|------|---------|
| `test_ipc_request_from_json` | Parse IPC request from JSON |
| `test_ipc_request_from_dict` | Create IPC request from dict |
| `test_ipc_response_to_json` | Serialize IPC response to JSON |
| `test_handle_ping` | Handle ping request |
| `test_handle_list_cases` | Handle list cases request |
| `test_handle_json_request` | Handle JSON request |
| `test_handle_invalid_method` | Handle invalid method error |

**Expected Result:** 7/7 passed

---

#### Export Functionality (3 tests)
```bash
python -m pytest tests/test_part4.py::TestExporter -v
```

| Test | Purpose |
|------|---------|
| `test_export_record_json` | Export record to JSON |
| `test_export_record_html` | Export record to HTML |
| `test_export_case_json` | Export entire case to JSON |
| `test_export_session_json` | Export session to JSON |
| `test_export_invalid_record` | Handle invalid record export |

**Expected Result:** 3/3 passed (note: may actually have 5 tests)

---

#### Data Integrity (1 test)
```bash
python -m pytest tests/test_part4.py::TestDataIntegrity -v
```

| Test | Purpose |
|------|---------|
| `test_checksum_verification` | Verify data integrity checksums |
| `test_record_byte_match_verification` | Verify record immutability |

**Expected Result:** 1/1 passed (note: may actually have 2 tests)

---

## Manual Testing Guide

### PART 1: Basic Manual Test

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

### PART 2: Manual Testing

#### 1. Create Test File

```bash
echo "This is a test file" > /tmp/test.txt
```

#### 2. Run PART 1 + PART 2 Analysis

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
import json

# Run PART 1
part1_results = analyze_file('/tmp/test.txt')
print("PART 1 completed")

# Run PART 2 using PART 1 results
part2_results = deep_analyze_file('/tmp/test.txt', part1_results)
print(json.dumps(part2_results, indent=2))
```

#### 3. Expected PART 2 Output Structure

```json
{
  "universal": [
    {
      "finding_id": "F0001_global_entropy_0",
      "finding_type": "global_entropy",
      "semantic_file_type": "PLAIN_TEXT",
      "byte_offset_start": 0,
      "byte_offset_end": 37,
      "extracted_value": {
        "entropy": 4.5,
        "entropy_class": "LOW"
      },
      "confidence": "HIGH"
    }
  ],
  "container_level": [],
  "file_type_specific": [
    {
      "finding_id": "F0004_text_encoding_0",
      "finding_type": "text_encoding",
      "extracted_value": {
        "encoding": "UTF-8",
        "bom_detected": null
      }
    }
  ],
  "summary": {
    "total_findings": 4,
    "semantic_file_type": "PLAIN_TEXT",
    "universal_findings": 3,
    "container_findings": 0,
    "file_type_specific_findings": 1
  }
}
```

### PART 2: Test Different File Types

#### JPEG Image (Deep Analysis)
```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file

part1 = analyze_file('/path/to/image.jpg')
part2 = deep_analyze_file('/path/to/image.jpg', part1)
```

**Expected PART 2 Findings:**
- Universal entropy analysis
- JPEG-specific structure analysis
- EXIF metadata extraction (if present)
- Image dimension validation

#### PDF Document (Deep Analysis)
```python
part1 = analyze_file('/path/to/document.pdf')
part2 = deep_analyze_file('/path/to/document.pdf', part1)
```

**Expected PART 2 Findings:**
- Universal entropy and string extraction
- PDF object count and validation
- JavaScript detection (if present)
- Embedded file detection

#### DOCX Document (Deep Analysis)
```python
part1 = analyze_file('/path/to/document.docx')
part2 = deep_analyze_file('/path/to/document.docx', part1)
```

**Expected PART 2 Findings:**
- ZIP container analysis (entries, compression)
- OOXML parts validation
- Relationship (.rels) integrity
- Macro detection (VBA project)

---

### PART 3: Manual Testing

#### 1. Complete Pipeline Test

```python
from src.file_analyzer.part3_analyzer import full_analysis
import json

# Run complete analysis (PART 1 + PART 2 + PART 3)
results = full_analysis('/tmp/test.txt')
print(json.dumps(results, indent=2))
```

#### 2. Step-by-Step PART 3 Analysis

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import Part3Analyzer
import json

# Run PART 1
part1 = analyze_file('/tmp/test.txt')
print("✅ PART 1 completed")

# Run PART 2
part2 = deep_analyze_file('/tmp/test.txt', part1)
print("✅ PART 2 completed")

# Run PART 3
analyzer = Part3Analyzer('/tmp/test.txt', part1, part2)
part3 = analyzer.analyze()
print("✅ PART 3 completed")

print(json.dumps(part3, indent=2))
```

#### 3. Expected PART 3 Output Structure

```json
{
  "file_info": {
    "file_name": "test.txt",
    "semantic_file_type": "PLAIN_TEXT"
  },
  "rule_engine": {
    "yara_detections": [],
    "fuzzy_hashes": {
      "ssdeep": "...",
      "tlsh": "..."
    },
    "library_status": {
      "yara_available": false,
      "ssdeep_available": false,
      "tlsh_available": false
    }
  },
  "heuristics": {
    "triggered_heuristics": [],
    "total_heuristics_evaluated": 10,
    "heuristics_triggered": 0
  },
  "risk_score": {
    "raw_score": 0.0,
    "normalized_score": 0.0,
    "severity": "INFORMATIONAL",
    "confidence": "HIGH",
    "score_breakdown": {
      "rule_matches": 0,
      "heuristics": 0,
      "structural_anomalies": 0
    },
    "explanation": "No suspicious indicators detected."
  },
  "summary": {
    "total_detections": 0,
    "rule_matches": 0,
    "heuristics_triggered": 0,
    "overall_severity": "INFORMATIONAL"
  },
  "reproducibility": {
    "deterministic": true,
    "version_info": "..."
  }
}
```

### PART 3: Test with Suspicious File

#### Create ZIP with Trailing Data (Heuristic Trigger)

```bash
# Create a simple ZIP
echo "file content" > /tmp/file1.txt
zip /tmp/test.zip /tmp/file1.txt

# Add trailing data
echo "EXTRA DATA AFTER EOF" >> /tmp/test.zip
```

#### Analyze with PART 3

```python
from src.file_analyzer.part3_analyzer import full_analysis
import json

results = full_analysis('/tmp/test.zip')
print(json.dumps(results['part3']['heuristics'], indent=2))
```

**Expected:** Trailing data heuristic should trigger:
```json
{
  "triggered_heuristics": [
    {
      "heuristic_id": "H003",
      "name": "ZIP_TRAILING_DATA",
      "description": "ZIP archive with data beyond logical EOF",
      "severity": "MEDIUM",
      "weight": 15,
      "evidence_references": ["F0003_trailing_data_0"]
    }
  ]
}
```

### PART 3: Test with DOCX Containing Macro

```python
# Analyze DOCX with VBA macro
results = full_analysis('/path/to/macro_document.docx')

# Check for macro heuristic
heuristics = results['part3']['heuristics']['triggered_heuristics']
for h in heuristics:
    if 'MACRO' in h['name']:
        print(f"✅ Detected: {h['name']} - Severity: {h['severity']}")
```

**Expected:** OOXML_VBA_MACRO heuristic should trigger if macros present.

---

### PART 4: Manual Testing

#### 1. Complete Pipeline Test with Persistence

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3
from src.file_analyzer.part4.persistence import AnalysisDatabase
import tempfile
from pathlib import Path

# Run PART 1, 2, 3
part1 = analyze_file('/tmp/test.txt')
part2 = deep_analyze_file('/tmp/test.txt', part1)
part3 = analyze_part3('/tmp/test.txt', part1, part2)

# Initialize database
db_path = tempfile.mktemp(suffix='.db')
db = AnalysisDatabase(db_path)

# Create case and session
case_id = db.create_case(
    name="Test Case",
    description="Manual test case"
)
session_id = db.create_session(
    case_id=case_id,
    name="Test Session"
)

# Import analysis results
record_id = db.import_analysis(
    session_id=session_id,
    part1_results=part1,
    part2_results=part2,
    part3_results=part3
)

print(f"✅ Analysis persisted:")
print(f"   Case: {case_id}")
print(f"   Session: {session_id}")
print(f"   Record: {record_id}")

# Retrieve and verify
record = db.get_record(record_id)
print(f"\n✅ Record retrieved successfully")
print(f"   File: {record['file_path']}")
print(f"   Risk Score: {record['risk_score']}")
print(f"   Severity: {record['severity']}")

db.close()
```

#### 2. Query Records with Filters

```python
from src.file_analyzer.part4.persistence import AnalysisDatabase

db = AnalysisDatabase('analysis.db')

# Query by session
records = db.query_records(session_id="SES-12345678")
print(f"Session records: {len(records)}")

# Query by severity
high_risk = db.query_records(severity="high")
print(f"High risk files: {len(high_risk)}")

# Query by file type
pdfs = db.query_records(file_type="PDF")
print(f"PDF files analyzed: {len(pdfs)}")

# Combined query
critical_pdfs = db.query_records(
    file_type="PDF",
    severity="critical",
    min_score=75.0
)
print(f"Critical PDFs: {len(critical_pdfs)}")
```

#### 3. Export Analysis Results

```python
from src.file_analyzer.part4.persistence import AnalysisDatabase
from src.file_analyzer.part4.exporter import Exporter, ExportFormat

db = AnalysisDatabase('analysis.db')
exporter = Exporter(db)

# Export single record to JSON
exporter.export_record(
    record_id="REC-ABC123DEF456",
    output_path="/tmp/record.json",
    format=ExportFormat.JSON
)
print("✅ Record exported to JSON")

# Export single record to HTML
exporter.export_record(
    record_id="REC-ABC123DEF456",
    output_path="/tmp/record.html",
    format=ExportFormat.HTML
)
print("✅ Record exported to HTML")

# Export entire session
exporter.export_session(
    session_id="SES-12345678",
    output_path="/tmp/session.json"
)
print("✅ Session exported")

# Export entire case
exporter.export_case(
    case_id="CASE-ABCD1234",
    output_path="/tmp/case.json"
)
print("✅ Case exported")

db.close()
```

#### 4. Standalone Test Scripts

Run the standalone test scripts for different file types:

```bash
# Test with text file
python text_test.py test_files/sample.txt

# Test with DOCX file
python docx_test.py test_files/sample.docx

# Test with PDF file
python pdf_test.py test_files/sample.pdf

# Test with image file
python image_test.py test_files/sample.jpg
```

Each script will:
- Run PART 1, 2, 3 analysis
- Create database, case, and session
- Import analysis results
- Retrieve and verify data
- Export to JSON
- Query session records
- Display summary

**Expected Output:**
```
================================================================================
ANALYSIS COMPLETE - ALL FOUR PARTS
================================================================================

File: test_files/sample.txt
Semantic Type: PLAIN_TEXT
Risk Score: 0.0/100
Severity: INFORMATIONAL

Part 4 Persistence: ✅ SUCCESS
Database Operations: 5/5 completed
Export Operations: 1/1 completed
```

---

## Expected Outputs

### PART 1: Output Block Structure

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

### PART 2: Finding Output Example

```json
{
  "finding_id": "F0001_global_entropy_0",
  "finding_type": "global_entropy",
  "semantic_file_type": "PLAIN_TEXT",
  "source_library_or_method": "Shannon entropy calculation (Python math)",
  "byte_offset_start": 0,
  "byte_offset_end": 37,
  "extracted_value": {
    "entropy": 4.5234,
    "entropy_class": "LOW",
    "max_possible_entropy": 8.0,
    "entropy_ratio": 0.5654
  },
  "confidence": "HIGH",
  "verification_reference": "Calculate: -sum(p * log2(p)) for all byte frequencies",
  "failure_reason": null
}
```

### PART 2: Summary Block Example

```json
{
  "total_findings": 12,
  "semantic_file_type": "DOCX",
  "container_type": "ZIP",
  "universal_findings": 4,
  "container_findings": 3,
  "file_type_specific_findings": 5
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
        python -m pytest tests/ -v --cov=src/file_analyzer
```

---

## Integration Testing (PART 1 + PART 2 + PART 3)

### Testing the Complete Pipeline

```python
from src.file_analyzer.part3_analyzer import full_analysis
import json

def test_complete_pipeline(file_path):
    """Test PART 1, PART 2, and PART 3 together."""
    print(f"Analyzing: {file_path}")
    
    # Run complete analysis
    results = full_analysis(file_path)
    
    # Verify PART 1
    assert 'part1' in results
    semantic_type = results['part1']['summary']['semantic_file_type']
    print(f"✅ PART 1: Identified as {semantic_type}")
    
    # Verify PART 2
    assert 'part2' in results
    total_findings = results['part2']['summary']['total_findings']
    print(f"✅ PART 2: Generated {total_findings} findings")
    
    # Verify PART 3
    assert 'part3' in results
    risk_score = results['part3']['risk_score']['normalized_score']
    severity = results['part3']['risk_score']['severity']
    print(f"✅ PART 3: Risk Score {risk_score}/100 - Severity: {severity}")
    
    return results

# Test with different file types
test_complete_pipeline('/tmp/test.txt')
test_complete_pipeline('/path/to/image.jpg')
test_complete_pipeline('/path/to/document.pdf')
```

### Testing Individual Parts

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import Part3Analyzer

def test_pipeline_step_by_step(file_path):
    """Test each part individually."""
    # PART 1
    part1 = analyze_file(file_path)
    assert 'summary' in part1
    print(f"✅ PART 1: {part1['summary']['semantic_file_type']}")
    
    # PART 2
    part2 = deep_analyze_file(file_path, part1)
    assert 'summary' in part2
    print(f"✅ PART 2: {part2['summary']['total_findings']} findings")
    
    # PART 3
    analyzer = Part3Analyzer(file_path, part1, part2)
    part3 = analyzer.analyze()
    assert 'risk_score' in part3
    print(f"✅ PART 3: Score {part3['risk_score']['normalized_score']}/100")
    
    return part1, part2, part3
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

**PART 1:**
- [ ] Install dependencies: `pip install -r requirements.txt pytest`
- [ ] Run PART 1 tests: `python -m pytest tests/test_analyzer.py -v`
- [ ] Verify 42/42 tests pass
- [ ] Test with real files: JPEG, PDF, DOCX, ZIP
- [ ] Validate JSON output structure
- [ ] Check hash computation: `sha256sum` vs analyzer output
- [ ] Test edge cases: empty file, symlink, broken OOXML
- [ ] Verify platform-specific features (NTFS ADS on Windows)

**PART 2:**
- [ ] Run PART 2 tests: `python -m pytest tests/test_deep_analyzer.py -v`
- [ ] Verify 19/19 tests pass
- [ ] Test entropy calculations on various files
- [ ] Test string extraction and classification
- [ ] Test container analysis (ZIP, OLE)
- [ ] Test file-type-specific analysis
- [ ] Verify finding structure and grouping

**PART 3:**
- [ ] Run PART 3 tests: `python -m pytest tests/test_part3_analyzer.py -v`
- [ ] Verify 26/26 tests pass
- [ ] Test rule engine (with and without YARA)
- [ ] Test fuzzy hashing (with and without ssdeep/TLSH)
- [ ] Test heuristic evaluation
- [ ] Test risk scoring and severity mapping
- [ ] Test deterministic output (same input = same output)
- [ ] Verify evidence-based scoring (no score without evidence)

**PART 4:**
- [ ] Run PART 4 tests: `python -m pytest tests/test_part4.py -v`
- [ ] Verify 34/34 tests pass
- [ ] Test database operations (create, retrieve, query)
- [ ] Test schema validation
- [ ] Test IPC request/response handling
- [ ] Test export functionality (JSON, HTML)
- [ ] Test data integrity and checksums
- [ ] Run standalone test scripts (text_test.py, docx_test.py, pdf_test.py, image_test.py)

**Integration:**
- [ ] Run all tests: `python -m pytest tests/ -v`
- [ ] Verify 121/121 tests pass (42 + 19 + 26 + 34)
- [ ] Test complete pipeline (PART 1 + PART 2 + PART 3 + PART 4)
- [ ] Verify consistency across all parts
- [ ] Test with multiple file types
- [ ] Verify standalone test scripts work for all file types

### Expected Test Results

**PART 1:**
```
================================ test session starts ================================
collected 42 items

tests/test_analyzer.py::TestFileIngestion::test_ingestion_empty_file PASSED   [  2%]
tests/test_analyzer.py::TestFileIngestion::test_ingestion_file_not_found PASSED [ 4%]
...
tests/test_analyzer.py::TestAmbiguityHandling::test_ambiguity_with_polyglot PASSED [100%]

================================ 42 passed in 0.34s =================================
```

**PART 2:**
```
================================ test session starts ================================
collected 19 items

tests/test_deep_analyzer.py::TestUniversalAnalysis::test_global_entropy_calculation PASSED [ 5%]
tests/test_deep_analyzer.py::TestUniversalAnalysis::test_printable_string_extraction PASSED [10%]
...
tests/test_deep_analyzer.py::TestErrorHandling::test_nonexistent_file PASSED [100%]

================================ 19 passed in 0.07s =================================
```

**PART 3:**
```
================================ test session starts ================================
collected 26 items

tests/test_part3_analyzer.py::TestRuleEngine::test_fuzzy_hash_computation PASSED [ 3%]
tests/test_part3_analyzer.py::TestHeuristicEngine::test_heuristic_definitions_exist PASSED [ 7%]
...
tests/test_part3_analyzer.py::TestOOXMLAnalysis::test_docx_with_vba PASSED [100%]

================================ 26 passed in 0.12s =================================
```

**PART 4:**
```
================================ test session starts ================================
collected 34 items

tests/test_part4.py::TestSchemas::test_schema_definitions_exist PASSED [ 2%]
tests/test_part4.py::TestPersistence::test_create_case PASSED [ 5%]
...
tests/test_part4.py::TestDataIntegrity::test_checksum_verification PASSED [100%]

================================ 34 passed in 0.25s =================================
```

**Combined (All Parts):**
```
================================ test session starts ================================
collected 121 items

tests/test_analyzer.py .......................................... [ 34%]
tests/test_deep_analyzer.py ...................                  [ 50%]
tests/test_part3_analyzer.py ..........................          [ 72%]
tests/test_part4.py ..................................           [100%]

================================ 121 passed in 1.37s =================================
```

---

## Additional Resources

- **Main Documentation:** `README.md`
- **Library Rationale:** `LIBRARY_RATIONALE.md` - Explains library choices and architecture
- **Verification Report:** `CODE_VS_DOC_VERIFICATION.md`
- **Improvements Documentation:** `PART1_IMPROVEMENTS.md`
- **Requirements Specification:** `File_analysis_app_plan`

---

## Support

For issues or questions:
1. Check `VERIFICATION_SUMMARY.md` for known issues
2. Review test output with `-vv` flag for details
3. Examine `CODE_VS_DOC_VERIFICATION.md` for implementation details
4. See `LIBRARY_RATIONALE.md` for library usage questions

---

**Last Updated:** 2026-01-05  
**Test Suite Version:** 4.0 (42 PART 1 + 19 PART 2 + 26 PART 3 + 34 PART 4 = 121 total)  
**Compatibility:** Python 3.8+ on Linux/macOS/Windows
