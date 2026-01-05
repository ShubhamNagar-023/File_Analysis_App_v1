"""
Tests for the Deep Analyzer - PART 2

These tests verify the deep file-type-aware static analysis
functionality including universal analysis, container analysis,
and file-type-specific analysis.
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

from file_analyzer.analyzer import FileAnalyzer
from file_analyzer.deep_analyzer import DeepAnalyzer, deep_analyze_file


class TestUniversalAnalysis(unittest.TestCase):
    """Test universal static analysis performed on all file types."""
    
    def test_global_entropy_calculation(self):
        """Test global Shannon entropy calculation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Hello, World! This is a test file with some content.\n')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            entropy_findings = [f for f in part2['universal'] if f['finding_type'] == 'global_entropy']
            self.assertEqual(len(entropy_findings), 1)
            
            entropy = entropy_findings[0]['extracted_value']
            self.assertIn('entropy', entropy)
            self.assertIn('entropy_class', entropy)
            self.assertIn('entropy_ratio', entropy)
            self.assertTrue(0 <= entropy['entropy'] <= 8.0)
        finally:
            os.unlink(temp_path)
    
    def test_section_entropy_calculation(self):
        """Test section-wise entropy calculation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Create file with varying entropy sections
            f.write(b'A' * 4096)  # Low entropy section
            f.write(os.urandom(4096))  # High entropy section
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            section_findings = [f for f in part2['universal'] if f['finding_type'] == 'section_entropy']
            self.assertEqual(len(section_findings), 1)
            
            section_data = section_findings[0]['extracted_value']
            self.assertIn('sections', section_data)
            self.assertIn('mean_entropy', section_data)
            self.assertIn('variance', section_data)
            self.assertTrue(len(section_data['sections']) >= 2)
        finally:
            os.unlink(temp_path)
    
    def test_printable_string_extraction(self):
        """Test extraction and classification of printable strings."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00\x00\x00')
            f.write(b'https://example.com/malware')
            f.write(b'\x00\x00\x00')
            f.write(b'192.168.1.100')
            f.write(b'\x00\x00\x00')
            f.write(b'test@example.com')
            f.write(b'\x00\x00\x00')
            f.write(b'C:\\Windows\\System32\\cmd.exe')
            f.write(b'\x00\x00\x00')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            string_findings = [f for f in part2['universal'] if f['finding_type'] == 'printable_strings']
            self.assertEqual(len(string_findings), 1)
            
            strings = string_findings[0]['extracted_value']
            self.assertIn('urls', strings)
            self.assertIn('ip_addresses', strings)
            self.assertIn('emails', strings)
            self.assertIn('file_paths', strings)
            
            # Should have detected at least some classified strings
            self.assertTrue(strings['total_strings'] > 0)
        finally:
            os.unlink(temp_path)
    
    def test_trailing_data_detection_zip(self):
        """Test detection of trailing data after ZIP EOF."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create valid ZIP then append trailing data
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'content')
            
            with open(temp_path, 'ab') as f:
                f.write(b'TRAILING_DATA_HIDDEN' * 5)
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            trailing_findings = [f for f in part2['universal'] if f['finding_type'] == 'trailing_data']
            self.assertEqual(len(trailing_findings), 1)
            self.assertTrue(trailing_findings[0]['extracted_value']['trailing_size'] > 0)
        finally:
            os.unlink(temp_path)
    
    def test_structural_anomalies_null_padding(self):
        """Test detection of null padding anomalies."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Header content')
            f.write(b'\x00' * 2048)  # Large null padding
            f.write(b'Footer content')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            anomaly_findings = [f for f in part2['universal'] if f['finding_type'] == 'structural_anomalies']
            self.assertEqual(len(anomaly_findings), 1)
            
            anomalies = anomaly_findings[0]['extracted_value']['anomalies']
            null_anomalies = [a for a in anomalies if a['type'] == 'null_padding']
            self.assertTrue(len(null_anomalies) > 0)
        finally:
            os.unlink(temp_path)


class TestContainerAnalysis(unittest.TestCase):
    """Test container-level analysis for ZIP and OLE containers."""
    
    def test_zip_container_analysis(self):
        """Test ZIP container analysis with entries and compression."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('file1.txt', 'Content 1' * 100)
                zf.writestr('folder/file2.txt', 'Content 2' * 100)
                zf.writestr('file3.bin', os.urandom(500))
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            container_findings = [f for f in part2['container_level'] if f['finding_type'] == 'zip_container_analysis']
            self.assertEqual(len(container_findings), 1)
            
            container = container_findings[0]['extracted_value']
            self.assertEqual(container['entry_count'], 3)
            self.assertIn('DEFLATE', container['compression_methods'])
        finally:
            os.unlink(temp_path)
    
    def test_ooxml_container_analysis(self):
        """Test OOXML container analysis for DOCX files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                zf.writestr('word/document.xml', '<doc/>')
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            # Should have both container and OOXML-specific analysis
            container_findings = [f for f in part2['container_level'] if 'zip' in f['finding_type']]
            ooxml_findings = [f for f in part2['file_type_specific'] if 'ooxml' in f['finding_type']]
            
            self.assertTrue(len(container_findings) > 0)
            self.assertTrue(len(ooxml_findings) > 0)
        finally:
            os.unlink(temp_path)


class TestFileTypeSpecificAnalysis(unittest.TestCase):
    """Test file-type-specific deep static analysis."""
    
    def test_plain_text_analysis(self):
        """Test plain text encoding and line ending detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            # UTF-8 BOM + content with LF line endings
            f.write(b'\xef\xbb\xbf')
            f.write(b'Line 1\nLine 2\nLine 3\n')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            text_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'plain_text_analysis']
            self.assertEqual(len(text_findings), 1)
            
            text_info = text_findings[0]['extracted_value']
            self.assertEqual(text_info['bom_detected'], 'UTF-8')
            self.assertEqual(text_info['line_ending_style'], 'LF')
        finally:
            os.unlink(temp_path)
    
    def test_jpeg_image_analysis(self):
        """Test JPEG image structure analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
            # Minimal JPEG with SOI, JFIF APP0, SOF0, and EOI
            f.write(b'\xFF\xD8')  # SOI
            f.write(b'\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')  # JFIF APP0
            f.write(b'\xFF\xC0\x00\x11\x08\x00\x64\x00\xC8\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01')  # SOF0: 200x100
            f.write(b'\x00' * 50)
            f.write(b'\xFF\xD9')  # EOI
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            image_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'image_analysis']
            self.assertEqual(len(image_findings), 1)
            
            image_info = image_findings[0]['extracted_value']
            self.assertEqual(image_info['format'], 'JPEG')
            self.assertEqual(image_info['width'], 200)
            self.assertEqual(image_info['height'], 100)
        finally:
            os.unlink(temp_path)
    
    def test_png_image_analysis(self):
        """Test PNG image structure analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as f:
            # Minimal PNG with header and IHDR chunk
            f.write(b'\x89PNG\r\n\x1a\n')  # PNG signature
            # IHDR chunk: width=256, height=128, bit_depth=8, color_type=2 (RGB)
            ihdr_data = struct.pack('>IIBBBBB', 256, 128, 8, 2, 0, 0, 0)
            f.write(struct.pack('>I', 13))  # IHDR length
            f.write(b'IHDR')
            f.write(ihdr_data)
            f.write(b'\x00\x00\x00\x00')  # CRC (fake)
            # IEND chunk
            f.write(struct.pack('>I', 0))
            f.write(b'IEND')
            f.write(b'\xae\x42\x60\x82')  # IEND CRC
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            image_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'image_analysis']
            self.assertEqual(len(image_findings), 1)
            
            image_info = image_findings[0]['extracted_value']
            self.assertEqual(image_info['format'], 'PNG')
            self.assertEqual(image_info['width'], 256)
            self.assertEqual(image_info['height'], 128)
        finally:
            os.unlink(temp_path)
    
    def test_pdf_analysis(self):
        """Test PDF structure analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            f.write(b'%PDF-1.7\n')
            f.write(b'1 0 obj\n<< /Type /Catalog >>\nendobj\n')
            f.write(b'2 0 obj\n<< /JavaScript (test) >>\nendobj\n')
            f.write(b'3 0 obj\n<< /Encrypt /something >>\nendobj\n')
            f.write(b'xref\n0 4\n')
            f.write(b'trailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            pdf_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'pdf_analysis']
            self.assertEqual(len(pdf_findings), 1)
            
            pdf_info = pdf_findings[0]['extracted_value']
            self.assertEqual(pdf_info['version'], '1.7')
            self.assertEqual(pdf_info['object_count'], 3)
            self.assertTrue(pdf_info['has_javascript'])
            self.assertTrue(pdf_info['has_encryption'])
        finally:
            os.unlink(temp_path)
    
    def test_office_ooxml_analysis(self):
        """Test OOXML Office document analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                content_types = '''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
                zf.writestr('[Content_Types].xml', content_types)
                zf.writestr('word/document.xml', '<doc/>')
                zf.writestr('word/vbaProject.bin', 'fake vba')  # Simulate VBA
                zf.writestr('customXml/item1.xml', '<custom/>')
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            ooxml_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'office_ooxml_analysis']
            self.assertEqual(len(ooxml_findings), 1)
            
            ooxml_info = ooxml_findings[0]['extracted_value']
            self.assertTrue(ooxml_info['has_vba_macros'])
            self.assertTrue(len(ooxml_info['custom_xml']) > 0)
        finally:
            os.unlink(temp_path)
    
    def test_archive_analysis(self):
        """Test archive file analysis with nested archives."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('readme.txt', 'Content')
                zf.writestr('nested.zip', 'fake nested archive')
                zf.writestr('another.7z', 'fake 7z archive')
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            archive_findings = [f for f in part2['file_type_specific'] if f['finding_type'] == 'archive_analysis']
            self.assertEqual(len(archive_findings), 1)
            
            archive_info = archive_findings[0]['extracted_value']
            self.assertEqual(len(archive_info['file_tree']), 3)
            self.assertIn('nested.zip', archive_info['nested_archives'])
            self.assertIn('another.7z', archive_info['nested_archives'])
        finally:
            os.unlink(temp_path)


class TestOutputFormat(unittest.TestCase):
    """Test that output format matches PART 2 requirements."""
    
    def test_finding_structure(self):
        """Test that each finding has required fields."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            required_fields = [
                'finding_id', 'finding_type', 'semantic_file_type',
                'source_library_or_method', 'byte_offset_start',
                'byte_offset_end', 'extracted_value', 'confidence',
                'verification_reference', 'failure_reason'
            ]
            
            for finding in part2['universal']:
                for field in required_fields:
                    self.assertIn(field, finding, f"Missing field: {field}")
        finally:
            os.unlink(temp_path)
    
    def test_findings_grouped_correctly(self):
        """Test that findings are grouped by category."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'content')
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            self.assertIn('universal', part2)
            self.assertIn('container_level', part2)
            self.assertIn('file_type_specific', part2)
            self.assertIn('summary', part2)
            
            # Universal should have entropy and strings
            self.assertTrue(len(part2['universal']) > 0)
            
            # Container level should have ZIP analysis
            self.assertTrue(len(part2['container_level']) > 0)
        finally:
            os.unlink(temp_path)
    
    def test_summary_statistics(self):
        """Test that summary contains correct statistics."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            summary = part2['summary']
            self.assertIn('total_findings', summary)
            self.assertIn('semantic_file_type', summary)
            self.assertIn('universal_findings', summary)
            self.assertIn('container_findings', summary)
            self.assertIn('file_type_specific_findings', summary)
            
            # Verify total matches sum
            total = (
                summary['universal_findings'] +
                summary['container_findings'] +
                summary['file_type_specific_findings']
            )
            self.assertEqual(summary['total_findings'], total)
        finally:
            os.unlink(temp_path)


class TestConvenienceFunction(unittest.TestCase):
    """Test the deep_analyze_file convenience function."""
    
    def test_deep_analyze_file_function(self):
        """Test the convenience function."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            results = deep_analyze_file(temp_path, part1)
            
            self.assertIsInstance(results, dict)
            self.assertIn('universal', results)
            self.assertIn('summary', results)
        finally:
            os.unlink(temp_path)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and failure reporting."""
    
    def test_empty_file_handling(self):
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            self.assertIn('summary', part2)
            self.assertEqual(part2['summary']['total_findings'], 0)
        finally:
            os.unlink(temp_path)
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent files."""
        part1 = {'semantic_file_type': {'output_value': {'semantic_file_type': 'UNKNOWN'}}}
        part2 = DeepAnalyzer('/nonexistent/file.txt', part1).analyze()
        
        self.assertIn('error', part2)
        self.assertEqual(part2['error']['type'], 'FileNotFoundError')


if __name__ == '__main__':
    unittest.main()
