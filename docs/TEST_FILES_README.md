# Test Files for File Analysis Application

This directory contains sample test files used by the file analysis test scripts.

## Test Files

All test files are located in the `test_files/` directory:

- **sample.txt** - Plain text file for testing text analysis
- **sample.docx** - Minimal valid OOXML Word document for testing DOCX analysis
- **sample.pdf** - Minimal valid PDF document for testing PDF analysis
- **sample.jpg** - Minimal valid JPEG image for testing image analysis

## Test Scripts

The following test scripts have been updated to include **all three parts** of the analysis:

### 1. text_test.py
Tests plain text file analysis
```bash
python text_test.py                    # Uses default: test_files/sample.txt
python text_test.py /path/to/file.txt  # Uses custom file
```

### 2. docx_test.py
Tests DOCX (Word) document analysis
```bash
python docx_test.py                     # Uses default: test_files/sample.docx
python docx_test.py /path/to/file.docx  # Uses custom file
```

### 3. pdf_test.py
Tests PDF document analysis
```bash
python pdf_test.py                    # Uses default: test_files/sample.pdf
python pdf_test.py /path/to/file.pdf  # Uses custom file
```

### 4. image_test.py
Tests image file analysis
```bash
python image_test.py                     # Uses default: test_files/sample.jpg
python image_test.py /path/to/image.jpg  # Uses custom file
```

## Analysis Parts

Each test script now executes all three parts of the file analysis:

### Part 1: File Ingestion & Type Resolution
- Secure file ingestion
- Cryptographic identity (MD5, SHA1, SHA256, SHA512)
- Magic byte detection
- Container identification
- Semantic file-type resolution
- Extension analysis
- Filesystem metadata
- Advanced security checks

### Part 2: Deep File-Type-Aware Static Analysis
- Universal analysis (entropy, strings, trailing data, structural anomalies)
- Container-level analysis (ZIP, PDF, OLE)
- File-type-specific analysis (text encoding, image metadata, PDF structure, OOXML analysis, archive analysis)

### Part 3: Rules, Correlation & Explainable Risk Scoring
- Rule-based detections (YARA)
- Fuzzy hash similarity (ssdeep, TLSH)
- Deterministic heuristic evaluation
- Evidence-based risk scoring
- Session-level correlation

## Running All Tests

To run all test scripts at once:

```bash
python run_all_tests.py
```

This will:
1. Check that all test files exist
2. Run each test script with its corresponding file
3. Validate that all components are working correctly
4. Display a summary of test results

Expected output:
```
🎉 ALL TESTS PASSED! 🎉
```

## Test Output

Each test script produces comprehensive JSON output for all three parts, followed by a summary showing:
- File path
- Semantic file type
- Risk score (0-100)
- Severity level (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)

Example:
```
================================================================================
ANALYSIS COMPLETE - ALL THREE PARTS
================================================================================

File: test_files/sample.txt
Semantic Type: PLAIN_TEXT
Risk Score: 0.0/100
Severity: INFORMATIONAL
```

## File Paths

All test scripts support two modes:
1. **Default mode**: Run without arguments to use the default test file from `test_files/`
2. **Custom mode**: Provide a file path as an argument to test any file

This ensures backward compatibility while providing flexibility for testing various files.
