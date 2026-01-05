# Testing Guide

## Quick Test

```bash
# Run all tests
pip install pytest
python -m pytest tests/ -v
```

**Expected:** 121 tests passed

## Test by Component

```bash
# PART 1: File Ingestion (42 tests)
python -m pytest tests/test_analyzer.py -v

# PART 2: Deep Analysis (19 tests)
python -m pytest tests/test_deep_analyzer.py -v

# PART 3: Risk Scoring (26 tests)
python -m pytest tests/test_part3_analyzer.py -v

# PART 4: Persistence (34 tests)
python -m pytest tests/test_part4.py -v
```

## Manual Testing

### Test Individual Files

```bash
# Analyze any file
python analyze_file.py test_files/sample.pdf
python analyze_file.py test_files/sample.docx
python analyze_file.py test_files/sample.jpg
```

### Test File Types

```bash
# Specific file type tests (detailed output)
python text_test.py test_files/sample.txt
python docx_test.py test_files/sample.docx
python pdf_test.py test_files/sample.pdf
python image_test.py test_files/sample.jpg
```

## What's Tested

- ✅ File type detection and magic bytes
- ✅ Cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512)
- ✅ Container analysis (ZIP, OLE, PDF)
- ✅ Semantic file type resolution (DOCX vs ZIP)
- ✅ Entropy analysis and anomaly detection
- ✅ String extraction and classification
- ✅ Risk scoring and heuristics
- ✅ Database persistence and export

## Expected Output

All tests should pass. Example:

```
===================== 121 passed in 1.59s =======================
```

For detailed testing information, see [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md).
