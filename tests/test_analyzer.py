"""
Tests for the File Analyzer - PART 1

These tests verify the file ingestion, cryptographic identity,
magic detection, container identification, and semantic file-type
resolution functionality.
"""

import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from file_analyzer.analyzer import FileAnalyzer, analyze_file


class TestFileIngestion(unittest.TestCase):
    """Test secure file ingestion functionality."""
    
    def test_ingestion_regular_file(self):
        """Test ingesting a regular file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            content = b'Hello, World!'
            f.write(content)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            ingestion = results['ingestion']
            self.assertEqual(ingestion['output_value']['status'], 'SUCCESS')
            self.assertEqual(ingestion['output_value']['actual_size_bytes'], len(content))
            self.assertTrue(ingestion['output_value']['size_match'])
            self.assertFalse(ingestion['output_value']['is_symlink'])
        finally:
            os.unlink(temp_path)
    
    def test_ingestion_file_not_found(self):
        """Test ingesting a non-existent file."""
        analyzer = FileAnalyzer('/nonexistent/path/file.txt')
        results = analyzer.analyze()
        
        self.assertIn('error', results)
        self.assertEqual(results['error']['type'], 'FileNotFoundError')
    
    def test_ingestion_empty_file(self):
        """Test ingesting an empty file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            self.assertEqual(results['ingestion']['output_value']['actual_size_bytes'], 0)
        finally:
            os.unlink(temp_path)
    
    def test_ingestion_symlink_detection(self):
        """Test symlink detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            content = b'Target file content'
            f.write(content)
            target_path = f.name
        
        link_path = target_path + '_link'
        
        try:
            os.symlink(target_path, link_path)
            
            analyzer = FileAnalyzer(link_path)
            results = analyzer.analyze()
            
            self.assertTrue(results['ingestion']['output_value']['is_symlink'])
        finally:
            os.unlink(link_path)
            os.unlink(target_path)


class TestCryptographicIdentity(unittest.TestCase):
    """Test cryptographic hash computation."""
    
    def test_hash_computation(self):
        """Test that all hashes are computed correctly."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            content = b'Test content for hashing'
            f.write(content)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            crypto = results['cryptographic_identity']
            hashes = crypto['hashes']
            
            self.assertEqual(len(hashes), 4)  # MD5, SHA1, SHA256, SHA512
            
            algorithms = [h['evidence']['algorithm'] for h in hashes]
            self.assertIn('MD5', algorithms)
            self.assertIn('SHA1', algorithms)
            self.assertIn('SHA256', algorithms)
            self.assertIn('SHA512', algorithms)
            
            # Verify hash lengths
            for h in hashes:
                if h['evidence']['algorithm'] == 'MD5':
                    self.assertEqual(len(h['output_value']), 32)
                elif h['evidence']['algorithm'] == 'SHA1':
                    self.assertEqual(len(h['output_value']), 40)
                elif h['evidence']['algorithm'] == 'SHA256':
                    self.assertEqual(len(h['output_value']), 64)
                elif h['evidence']['algorithm'] == 'SHA512':
                    self.assertEqual(len(h['output_value']), 128)
        finally:
            os.unlink(temp_path)


class TestMagicDetection(unittest.TestCase):
    """Test magic byte detection."""
    
    def test_jpeg_detection(self):
        """Test JPEG signature detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
            # JPEG header
            f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            signatures = magic['output_value']['signatures_found']
            
            types = [s['signature_type'] for s in signatures]
            self.assertIn('JPEG', types)
        finally:
            os.unlink(temp_path)
    
    def test_png_detection(self):
        """Test PNG signature detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as f:
            # PNG header
            f.write(b'\x89PNG\r\n\x1a\n')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            signatures = magic['output_value']['signatures_found']
            
            types = [s['signature_type'] for s in signatures]
            self.assertIn('PNG', types)
        finally:
            os.unlink(temp_path)
    
    def test_pdf_detection(self):
        """Test PDF signature detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            f.write(b'%PDF-1.4\n')
            f.write(b'%' + bytes([0xE2, 0xE3, 0xCF, 0xD3]) + b'\n')
            f.write(b'1 0 obj\n<<>>\nendobj\n')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            signatures = magic['output_value']['signatures_found']
            
            types = [s['signature_type'] for s in signatures]
            self.assertIn('PDF', types)
        finally:
            os.unlink(temp_path)
    
    def test_zip_detection(self):
        """Test ZIP signature detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create a valid ZIP file
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test content')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            signatures = magic['output_value']['signatures_found']
            
            types = [s['signature_type'] for s in signatures]
            self.assertIn('ZIP', types)
        finally:
            os.unlink(temp_path)


class TestContainerIdentification(unittest.TestCase):
    """Test container type identification."""
    
    def test_zip_container(self):
        """Test ZIP container identification."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            container = results['container_identification']
            self.assertEqual(container['output_value']['container_type'], 'ZIP')
        finally:
            os.unlink(temp_path)
    
    def test_pdf_container(self):
        """Test PDF container identification."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            f.write(b'%PDF-1.4\n')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            container = results['container_identification']
            self.assertEqual(container['output_value']['container_type'], 'PDF')
        finally:
            os.unlink(temp_path)
    
    def test_no_container(self):
        """Test file with no recognized container."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Plain text content')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            container = results['container_identification']
            self.assertIsNone(container['output_value']['container_type'])
        finally:
            os.unlink(temp_path)


class TestSemanticFileType(unittest.TestCase):
    """Test semantic file type resolution - CRITICAL functionality."""
    
    def test_plain_zip_vs_docx(self):
        """Test that plain ZIP is not classified as DOCX."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create a plain ZIP (not OOXML)
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('file1.txt', 'content 1')
                zf.writestr('file2.txt', 'content 2')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'ARCHIVE_ZIP')
            self.assertNotEqual(semantic['output_value']['semantic_file_type'], 'DOCX')
        finally:
            os.unlink(temp_path)
    
    def test_docx_classification(self):
        """Test DOCX is classified as DOCX, not ZIP."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            temp_path = f.name
        
        try:
            # Create a minimal OOXML DOCX structure
            with zipfile.ZipFile(temp_path, 'w') as zf:
                # Content Types
                content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                
                # Minimal document.xml
                document = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body>
</w:document>'''
                zf.writestr('word/document.xml', document)
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'DOCX')
            self.assertEqual(semantic['output_value']['container_type'], 'ZIP')
            self.assertIn(semantic['output_value']['classification_confidence'], ['HIGH', 'MEDIUM'])
        finally:
            os.unlink(temp_path)
    
    def test_xlsx_classification(self):
        """Test XLSX is classified as XLSX, not ZIP."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                
                workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheets><sheet name="Sheet1" sheetId="1"/></sheets>
</workbook>'''
                zf.writestr('xl/workbook.xml', workbook)
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'XLSX')
        finally:
            os.unlink(temp_path)
    
    def test_pptx_classification(self):
        """Test PPTX is classified as PPTX, not ZIP."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pptx') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                
                presentation = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
</p:presentation>'''
                zf.writestr('ppt/presentation.xml', presentation)
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'PPTX')
        finally:
            os.unlink(temp_path)
    
    def test_plain_text_classification(self):
        """Test plain text file classification."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'This is plain text content.\n')
            f.write(b'It contains only ASCII characters.\n')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'PLAIN_TEXT')
        finally:
            os.unlink(temp_path)
    
    def test_jpeg_classification(self):
        """Test JPEG image classification."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
            # JPEG header
            f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'IMAGE_JPEG')
        finally:
            os.unlink(temp_path)
    
    def test_png_classification(self):
        """Test PNG image classification."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as f:
            f.write(b'\x89PNG\r\n\x1a\n')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertEqual(semantic['output_value']['semantic_file_type'], 'IMAGE_PNG')
        finally:
            os.unlink(temp_path)


class TestExtensionAnalysis(unittest.TestCase):
    """Test extension chain and deception analysis."""
    
    def test_simple_extension(self):
        """Test simple single extension."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            ext = results['extension_analysis']
            self.assertEqual(ext['output_value']['primary_extension'], 'txt')
            self.assertFalse(ext['output_value']['double_extension_detected'])
        finally:
            os.unlink(temp_path)
    
    def test_double_extension_detection(self):
        """Test double extension detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt.exe') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            ext = results['extension_analysis']
            self.assertTrue(ext['output_value']['double_extension_detected'])
            self.assertEqual(ext['output_value']['primary_extension'], 'exe')
            self.assertEqual(len(ext['output_value']['extension_chain']), 2)
        finally:
            os.unlink(temp_path)
    
    def test_extension_mismatch(self):
        """Test extension mismatch detection."""
        # Create a JPEG file with .txt extension
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            ext = results['extension_analysis']
            # The file is detected as JPEG but has .txt extension
            self.assertTrue(ext['output_value']['extension_mismatch'])
        finally:
            os.unlink(temp_path)


class TestAdvancedChecks(unittest.TestCase):
    """Test advanced security checks."""
    
    def test_trailing_data_detection(self):
        """Test detection of trailing data after ZIP."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create a valid ZIP
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test')
            
            # Append trailing data
            with open(temp_path, 'ab') as f:
                f.write(b'TRAILING_DATA_AFTER_ZIP' * 10)
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            advanced = results['advanced_checks']
            issues = advanced['output_value']['issues_found']
            
            trailing_issues = [i for i in issues if i['check'] == 'trailing_data']
            self.assertTrue(len(trailing_issues) > 0)
        finally:
            os.unlink(temp_path)


class TestFilesystemMetadata(unittest.TestCase):
    """Test filesystem metadata extraction."""
    
    def test_metadata_extraction(self):
        """Test that filesystem metadata is extracted."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            metadata = results['filesystem_metadata']
            self.assertIn('timestamps', metadata['output_value'])
            self.assertIn('permissions', metadata['output_value'])
            self.assertIn('ownership', metadata['output_value'])
            
            self.assertIn('modified', metadata['output_value']['timestamps'])
            self.assertIn('accessed', metadata['output_value']['timestamps'])
        finally:
            os.unlink(temp_path)


class TestSummary(unittest.TestCase):
    """Test summary generation."""
    
    def test_summary_generated(self):
        """Test that summary is properly generated."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test content')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            summary = results['summary']
            self.assertIn('semantic_file_type', summary)
            self.assertIn('classification_confidence', summary)
            self.assertIn('classification_notes', summary)
            self.assertIn('detected_deception_flags', summary)
            self.assertIn('file_size', summary)
            self.assertTrue(summary['analysis_complete'])
        finally:
            os.unlink(temp_path)


class TestJSONOutput(unittest.TestCase):
    """Test JSON output functionality."""
    
    def test_valid_json_output(self):
        """Test that output is valid JSON."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            analyzer.analyze()
            json_output = analyzer.to_json()
            
            # Should be valid JSON
            parsed = json.loads(json_output)
            self.assertIsInstance(parsed, dict)
            
            # Should have all required sections
            self.assertIn('file_info', parsed)
            self.assertIn('ingestion', parsed)
            self.assertIn('cryptographic_identity', parsed)
            self.assertIn('magic_detection', parsed)
            self.assertIn('container_identification', parsed)
            self.assertIn('semantic_file_type', parsed)
            self.assertIn('extension_analysis', parsed)
            self.assertIn('filesystem_metadata', parsed)
            self.assertIn('advanced_checks', parsed)
            self.assertIn('summary', parsed)
        finally:
            os.unlink(temp_path)


class TestConvenienceFunction(unittest.TestCase):
    """Test the analyze_file convenience function."""
    
    def test_analyze_file_function(self):
        """Test the analyze_file function."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            results = analyze_file(temp_path)
            
            self.assertIsInstance(results, dict)
            self.assertIn('summary', results)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
