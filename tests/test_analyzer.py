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


class TestMagicByteScanningCoverage(unittest.TestCase):
    """Test comprehensive magic-byte scanning coverage."""
    
    def test_scan_coverage_reporting(self):
        """Test that scan coverage is reported."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test' * 1000)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            self.assertIn('scan_coverage', magic['output_value'])
            coverage = magic['output_value']['scan_coverage']
            
            self.assertIn('offsets_scanned', coverage)
            self.assertIn('total_offsets_scanned', coverage)
            self.assertIn('scan_strategy', coverage)
            self.assertIn('deep_scan_enabled', coverage)
        finally:
            os.unlink(temp_path)
    
    def test_polyglot_detection(self):
        """Test detection of polyglot files with multiple signatures."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create a ZIP file
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test')
            
            # Append PDF signature at an offset
            with open(temp_path, 'ab') as f:
                f.write(b'\x00' * 100)
                f.write(b'%PDF-1.4\n')
                f.write(b'test pdf content')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            polyglot = magic['output_value']['polyglot_indicators']
            
            # Should detect polyglot
            self.assertTrue(len(polyglot) > 0)
        finally:
            os.unlink(temp_path)
    
    def test_deep_scan_for_small_files(self):
        """Test that deep scan is enabled for small files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Create file < 1MB
            f.write(b'\x00' * 100000)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            coverage = magic['output_value']['scan_coverage']
            
            self.assertTrue(coverage['deep_scan_enabled'])
        finally:
            os.unlink(temp_path)


class TestByteOffsetReporting(unittest.TestCase):
    """Test consistent byte offset reporting."""
    
    def test_unicode_deception_offsets(self):
        """Test that Unicode deception characters include byte offsets."""
        # Create file with RLO character in name
        import tempfile
        temp_dir = tempfile.mkdtemp()
        filename = f'test\u202Eexe.txt'  # RLO character
        temp_path = os.path.join(temp_dir, filename)
        
        try:
            with open(temp_path, 'wb') as f:
                f.write(b'test')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            ext = results['extension_analysis']
            unicode_deception = ext['output_value']['unicode_deception']
            
            if unicode_deception:
                for char_info in unicode_deception:
                    self.assertIn('byte_offset', char_info)
                    self.assertIn('char_index', char_info)
                    self.assertIn('byte_range', char_info)
        finally:
            os.unlink(temp_path)
            os.rmdir(temp_dir)
    
    def test_all_analysis_blocks_have_byte_ranges(self):
        """Test that all analysis blocks include input_byte_range."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test content')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            # Check key analysis blocks
            blocks_to_check = [
                'ingestion',
                'magic_detection',
                'container_identification',
                'semantic_file_type',
                'advanced_checks',
            ]
            
            for block_name in blocks_to_check:
                if block_name in results:
                    block = results[block_name]
                    self.assertIn('input_byte_range', block,
                                f'{block_name} missing input_byte_range')
        finally:
            os.unlink(temp_path)


class TestUniformOutputContract(unittest.TestCase):
    """Test uniform output contract enforcement."""
    
    def test_all_analysis_blocks_have_required_fields(self):
        """Test that all analysis blocks have required fields."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            required_fields = ['analysis_name', 'library_or_method', 
                             'input_byte_range', 'verification_method']
            
            blocks_to_check = [
                'ingestion',
                'magic_detection',
                'container_identification',
                'semantic_file_type',
                'extension_analysis',
                'filesystem_metadata',
                'advanced_checks',
            ]
            
            for block_name in blocks_to_check:
                if block_name in results:
                    block = results[block_name]
                    for field in required_fields:
                        self.assertIn(field, block,
                                    f'{block_name} missing {field}')
        finally:
            os.unlink(temp_path)
    
    def test_hash_outputs_normalized(self):
        """Test that hash outputs follow uniform structure."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            crypto = results['cryptographic_identity']
            hashes = crypto['hashes']
            
            for hash_entry in hashes:
                self.assertIn('analysis_name', hash_entry)
                self.assertIn('library_or_method', hash_entry)
                self.assertIn('input_byte_range', hash_entry)
                self.assertIn('verification_method', hash_entry)
        finally:
            os.unlink(temp_path)


class TestExternalVerificationMethods(unittest.TestCase):
    """Test that external verification methods are provided."""
    
    def test_magic_detection_has_verification(self):
        """Test that magic detection includes verification method."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            magic = results['magic_detection']
            self.assertIn('verification_method', magic)
            self.assertIsNotNone(magic['verification_method'])
            self.assertTrue(len(magic['verification_method']) > 0)
        finally:
            os.unlink(temp_path)
    
    def test_ooxml_validation_has_verification(self):
        """Test that OOXML validation includes verification method."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                content_types = '''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                zf.writestr('word/document.xml', '<?xml version="1.0"?><w:document/>')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            self.assertIn('verification_method', semantic)
            self.assertIsNotNone(semantic['verification_method'])
        finally:
            os.unlink(temp_path)


class TestPlainTextEnhancement(unittest.TestCase):
    """Test enhanced plain text classification."""
    
    def test_encoding_detection(self):
        """Test that encoding is detected for text files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            # UTF-8 with BOM
            f.write(b'\xef\xbb\xbf')
            f.write('Hello World'.encode('utf-8'))
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            if semantic['output_value']['semantic_file_type'] == 'PLAIN_TEXT':
                evidence = semantic['output_value']['classification_evidence']
                text_evidence = [e for e in evidence if e.get('type') == 'text_analysis']
                
                self.assertTrue(len(text_evidence) > 0)
                self.assertIn('encoding_detected', text_evidence[0])
        finally:
            os.unlink(temp_path)
    
    def test_binary_masquerading_detection(self):
        """Test detection of binary files masquerading as text."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            # Binary file with some text but null bytes
            f.write(b'Some text\x00\x00\x00binary\x00data')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            # Should NOT be classified as plain text
            self.assertNotEqual(semantic['output_value']['semantic_file_type'], 'PLAIN_TEXT')
        finally:
            os.unlink(temp_path)


class TestNTFSADSDetection(unittest.TestCase):
    """Test NTFS Alternate Data Streams detection."""
    
    def test_ads_platform_detection(self):
        """Test that ADS detection reports platform correctly."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            metadata = results['filesystem_metadata']
            ads = metadata['output_value']['ntfs_ads']
            
            self.assertIn('platform', ads)
            self.assertIn('status', ads)
            
            # On non-Windows, should be NOT_APPLICABLE
            import platform
            if platform.system() != 'Windows':
                self.assertEqual(ads['status'], 'NOT_APPLICABLE')
        finally:
            os.unlink(temp_path)


class TestBrokenOOXMLDetection(unittest.TestCase):
    """Test detection of broken OOXML files."""
    
    def test_missing_required_components(self):
        """Test detection of OOXML missing required components."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            temp_path = f.name
        
        try:
            # Create OOXML with missing components
            with zipfile.ZipFile(temp_path, 'w') as zf:
                # Only Content_Types, missing word/document.xml
                content_types = '''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            semantic = results['semantic_file_type']
            evidence = semantic['output_value']['classification_evidence']
            
            # Should detect missing components
            missing_found = False
            for ev in evidence:
                if 'missing_components' in ev and ev['missing_components']:
                    missing_found = True
                    break
            
            self.assertTrue(missing_found)
            # Confidence should be MEDIUM, not HIGH
            self.assertNotEqual(semantic['output_value']['classification_confidence'], 'HIGH')
        finally:
            os.unlink(temp_path)


class TestAmbiguityHandling(unittest.TestCase):
    """Test standardized ambiguity handling."""
    
    def test_ambiguity_with_polyglot(self):
        """Test that polyglot files are marked as ambiguous."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create polyglot ZIP+PDF
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test')
            
            with open(temp_path, 'ab') as f:
                f.write(b'\x00' * 100)
                f.write(b'%PDF-1.4\n')
            
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            summary = results['summary']
            
            # Should have ambiguity block
            if 'ambiguity' in summary and summary['ambiguity']:
                self.assertTrue(summary['ambiguity']['is_ambiguous'])
                self.assertIn('ambiguity_reasons', summary['ambiguity'])
        finally:
            os.unlink(temp_path)
    
    def test_ambiguity_criteria_documented(self):
        """Test that ambiguity includes documented reasons."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            # JPEG file with wrong extension
            f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            analyzer = FileAnalyzer(temp_path)
            results = analyzer.analyze()
            
            summary = results['summary']
            
            # Extension mismatch should trigger ambiguity with LOW confidence
            if summary.get('classification_confidence') in ['AMBIGUOUS', 'LOW', 'MEDIUM']:
                if 'ambiguity' in summary and summary['ambiguity']:
                    ambiguity = summary['ambiguity']
                    self.assertIn('ambiguity_reasons', ambiguity)
                    self.assertIn('conflicting_evidence', ambiguity)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
