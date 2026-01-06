# Risky Test Files - Comprehensive Security Testing Suite

This directory contains 21 carefully crafted test files organized by risk level to test the file analysis system's ability to detect various security concerns.

## Overview

- **7 Normal/Low Risk Files** - Clean files with no security concerns
- **7 Moderate Risk Files** - Files with suspicious characteristics but not immediately dangerous
- **7 High Risk/Dangerous Files** - Files with clear security threats

## Test Files by Risk Level

### NORMAL/LOW RISK (7 files)

These files represent legitimate, clean files with no security concerns:

1. **normal_plain_text.txt**
   - Type: Plain text
   - Risk: None
   - Description: Standard text file with safe content

2. **normal_document.docx**
   - Type: DOCX (OOXML)
   - Risk: None
   - Description: Clean Word document with standard business content

3. **normal_report.pdf**
   - Type: PDF
   - Risk: None
   - Description: Standard PDF report with no suspicious features

4. **normal_photo.jpg**
   - Type: JPEG image
   - Risk: None
   - Description: Clean JPEG image file

5. **normal_archive.zip**
   - Type: ZIP archive
   - Risk: None
   - Description: Standard ZIP archive with documentation files

6. **normal_data.csv**
   - Type: CSV
   - Risk: None
   - Description: Clean CSV data file

7. **normal_config.json**
   - Type: JSON
   - Risk: None
   - Description: Standard JSON configuration file

**Expected Analysis Results:**
- Risk Score: 0-10
- Severity: informational
- Heuristics Triggered: 0-1 (low severity only)

---

### MODERATE RISK (7 files)

These files have suspicious characteristics that warrant investigation:

8. **mismatch_image.txt**
   - Type: JPEG (with .txt extension)
   - Risk: Extension mismatch
   - Description: JPEG image file disguised with .txt extension
   - **Triggers:** Extension Mismatch heuristic

9. **trailing_data_archive.zip**
   - Type: ZIP with trailing data
   - Risk: Data hiding, tampering
   - Description: ZIP archive with data appended after EOF marker
   - **Triggers:** Trailing Data heuristic

10. **pdf_with_urls.pdf**
    - Type: PDF
    - Risk: Embedded URLs
    - Description: PDF document containing embedded URLs that could be malicious
    - **Triggers:** Embedded URLs heuristic

11. **suspicious_script.txt**
    - Type: Text
    - Risk: Suspicious command strings
    - Description: Text file containing suspicious commands (cmd.exe, powershell, wget, curl)
    - **Triggers:** Suspicious Strings heuristic

12. **docx_custom_xml.docx**
    - Type: DOCX
    - Risk: Custom XML parts
    - Description: DOCX with custom XML components (potential data exfiltration)
    - **Triggers:** May trigger OOXML analysis warnings

13. **pdf_incremental.pdf**
    - Type: PDF
    - Risk: Tampering indicator
    - Description: PDF with multiple incremental updates (3+ %%EOF markers)
    - **Triggers:** PDF Incremental Updates heuristic

14. **nested_archive.zip**
    - Type: ZIP
    - Risk: Nested archives
    - Description: ZIP containing other archive files (.zip, .7z)
    - **Triggers:** Archive Analysis warnings

**Expected Analysis Results:**
- Risk Score: 15-40
- Severity: low to medium
- Heuristics Triggered: 1-2 (medium severity)

---

### HIGH RISK/DANGEROUS (7 files)

These files represent serious security threats:

15. **document.pdf.exe**
    - Type: Executable (PE)
    - Risk: **CRITICAL** - Double extension spoofing
    - Description: Executable file disguised with .pdf.exe double extension
    - **Triggers:** Double Extension heuristic
    - **Threat:** Social engineering, malware delivery

16. **polyglot.zip**
    - Type: Polyglot (ZIP + PDF)
    - Risk: **HIGH** - Format confusion
    - Description: File valid as both ZIP and PDF formats
    - **Triggers:** Polyglot File heuristic
    - **Threat:** Security tool evasion, confusion attacks

17. **pdf_with_javascript.pdf**
    - Type: PDF
    - Risk: **HIGH** - Code execution
    - Description: PDF containing JavaScript code
    - **Triggers:** PDF with JavaScript heuristic
    - **Threat:** Arbitrary code execution, exploitation

18. **pdf_auto_action.pdf**
    - Type: PDF
    - Risk: **HIGH** - Auto-execution
    - Description: PDF with OpenAction trigger (executes on open)
    - **Triggers:** PDF Auto-Action heuristic
    - **Threat:** Automatic code execution, exploitation

19. **high_entropy_data.bin**
    - Type: Binary
    - Risk: **HIGH** - Encryption/Packing
    - Description: File with very high entropy (randomness)
    - **Triggers:** High Entropy indicators
    - **Threat:** Packed malware, encrypted payload

20. **docx_with_macros.docx**
    - Type: DOCX
    - Risk: **HIGH** - Macro execution
    - Description: Word document with VBA macros including AutoOpen
    - **Triggers:** Macro with Auto-Exec heuristic
    - **Threat:** Macro malware, auto-execution

21. **unicode_deception.txt**
    - Type: Text
    - Risk: **MEDIUM-HIGH** - Unicode deception
    - Description: Demonstrates Unicode RLO character deception
    - **Triggers:** Unicode Deception heuristic
    - **Threat:** Filename spoofing, social engineering

**Expected Analysis Results:**
- Risk Score: 35-70+
- Severity: medium to high/critical
- Heuristics Triggered: 1-3+ (high severity)

---

## Security Techniques Covered

This test suite comprehensively covers:

### File Masquerading & Deception
- ✅ Extension mismatch (file type doesn't match extension)
- ✅ Double extension (.pdf.exe)
- ✅ Unicode deception (RLO characters)

### Polyglot & Format Confusion
- ✅ Polyglot files (valid as multiple formats)
- ✅ Trailing data (hidden data after EOF)

### Code Execution Risks
- ✅ PDF JavaScript
- ✅ PDF OpenAction/auto-execution
- ✅ VBA macros with AutoOpen
- ✅ Suspicious command strings

### Tampering & Integrity
- ✅ PDF incremental updates (tampering indicator)
- ✅ Custom XML in OOXML documents

### Obfuscation & Evasion
- ✅ High entropy (packing/encryption)
- ✅ Nested archives

### Information Disclosure
- ✅ Embedded URLs
- ✅ Suspicious strings

## Usage

### Testing Individual Files

```bash
# Test a specific risky file
python text_test.py test_files/document.pdf.exe
python pdf_test.py test_files/pdf_with_javascript.pdf
```

### Automated Testing

Run the creation script to regenerate all files:

```bash
python create_risky_test_files.py
```

### Analysis Example

```python
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file
from src.file_analyzer.part3_analyzer import analyze_part3

# Analyze high-risk file
file_path = 'test_files/document.pdf.exe'
part1 = analyze_file(file_path)
part2 = deep_analyze_file(file_path, part1)
part3 = analyze_part3(file_path, part1, part2)

print(f"Risk Score: {part3['risk_score']['normalized_score']}/100")
print(f"Severity: {part3['risk_score']['severity']}")
print(f"Triggered Heuristics: {part3['heuristics']['triggered_count']}")
```

## Expected Results Summary

| File | Risk Level | Expected Score | Key Heuristics |
|------|-----------|----------------|----------------|
| normal_* | Low | 0-10 | None |
| mismatch_image.txt | Moderate | 15-25 | Extension Mismatch |
| trailing_data_archive.zip | Moderate | 15-25 | Trailing Data |
| pdf_with_urls.pdf | Moderate | 10-20 | Embedded URLs |
| suspicious_script.txt | Moderate | 15-25 | Suspicious Strings |
| docx_custom_xml.docx | Moderate | 10-20 | Custom XML |
| pdf_incremental.pdf | Moderate | 10-20 | Multiple Updates |
| nested_archive.zip | Moderate | 10-20 | Nested Archives |
| document.pdf.exe | High | 25-40 | Double Extension |
| polyglot.zip | High | 40-60 | Polyglot |
| pdf_with_javascript.pdf | High | 35-50 | JavaScript |
| pdf_auto_action.pdf | High | 30-45 | Auto-Action |
| high_entropy_data.bin | High | 20-40 | High Entropy |
| docx_with_macros.docx | High | 40-60 | Macro Auto-Exec |
| unicode_deception.txt | Moderate-High | 25-40 | Unicode Deception |

## Validation

All test files have been validated to:
1. ✅ Be syntactically valid (or intentionally malformed)
2. ✅ Trigger specific heuristics as designed
3. ✅ Demonstrate real-world security concerns
4. ✅ Cover different file types (PDF, DOCX, ZIP, images, text, executables)
5. ✅ Test various attack vectors and evasion techniques

## Security Notes

⚠️ **WARNING**: These files are designed to trigger security alerts and contain patterns found in real malware. While they are crafted samples and not actual malware:

- Do **NOT** execute .exe files
- Do **NOT** enable macros in Office documents
- Do **NOT** open PDFs with JavaScript enabled
- Keep these files isolated for testing purposes only

## References

These test files are based on real-world attack techniques documented in:
- MITRE ATT&CK Framework
- OWASP File Upload Testing Guide
- Common malware analysis patterns
- PDF malware research
- Office document macro attacks
