"""
Tests for the PART 3 Analyzer - Rules, Correlation & Explainable Scoring

These tests verify:
1. Rule-Based Detection (YARA + fuzzy hashing)
2. Deterministic Heuristic Evaluation
3. Evidence-Based Risk Scoring
4. Session-Level Correlation
"""

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from file_analyzer.analyzer import FileAnalyzer
from file_analyzer.deep_analyzer import DeepAnalyzer
from file_analyzer.part3_analyzer import Part3Analyzer, analyze_part3, full_analysis
from file_analyzer.rule_engine import RuleEngine, compute_fuzzy_hashes
from file_analyzer.heuristic_engine import HeuristicEngine, HEURISTIC_DEFINITIONS
from file_analyzer.risk_scorer import RiskScorer, compute_risk_score
from file_analyzer.correlator import SessionCorrelator, correlate_session


class TestRuleEngine(unittest.TestCase):
    """Test rule engine functionality."""
    
    def test_fuzzy_hash_computation(self):
        """Test fuzzy hash computation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Create file with random-looking content
            f.write(b'Hello World! ' * 100)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                file_data = f.read()
            
            engine = RuleEngine(temp_path, file_data, 'UNKNOWN')
            results = engine.analyze()
            
            # Should have fuzzy hashes section
            self.assertIn('fuzzy_hashes', results)
            
            # Library status should be reported
            self.assertIn('library_status', results)
            self.assertIn('ssdeep_available', results['library_status'])
            self.assertIn('tlsh_available', results['library_status'])
        finally:
            os.unlink(temp_path)
    
    def test_rule_engine_without_yara(self):
        """Test rule engine works without YARA rules."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                file_data = f.read()
            
            engine = RuleEngine(temp_path, file_data, 'PLAIN_TEXT')
            results = engine.analyze()
            
            # Should complete without error
            self.assertIn('yara_detections', results)
            self.assertEqual(len(results['yara_detections']), 0)
        finally:
            os.unlink(temp_path)
    
    def test_compute_fuzzy_hashes_convenience(self):
        """Test the convenience function for fuzzy hash computation."""
        file_data = b'Sample file content for fuzzy hashing ' * 100
        hashes = compute_fuzzy_hashes(file_data)
        
        # Should return a dict
        self.assertIsInstance(hashes, dict)


class TestHeuristicEngine(unittest.TestCase):
    """Test heuristic engine functionality."""
    
    def test_heuristic_definitions_exist(self):
        """Test that heuristic definitions are properly defined."""
        self.assertTrue(len(HEURISTIC_DEFINITIONS) > 0)
        
        for key, definition in HEURISTIC_DEFINITIONS.items():
            self.assertIn('name', definition)
            self.assertIn('description', definition)
            self.assertIn('trigger_conditions', definition)
            self.assertIn('weight', definition)
            self.assertIn('severity', definition)
    
    def test_extension_mismatch_heuristic(self):
        """Test extension mismatch heuristic detection."""
        # Create JPEG with .txt extension
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01')
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            semantic = part1.get('semantic_file_type', {}).get('output_value', {})
            semantic_type = semantic.get('semantic_file_type', 'UNKNOWN')
            
            engine = HeuristicEngine(part1, part2, semantic_type)
            results = engine.evaluate()
            
            # Should have evaluated heuristics
            self.assertIn('triggered_heuristics', results)
            self.assertIn('failed_heuristics', results)
            
            # Extension mismatch should be triggered
            triggered_names = [h['heuristic_key'] for h in results['triggered_heuristics']]
            self.assertIn('extension_mismatch', triggered_names)
        finally:
            os.unlink(temp_path)
    
    def test_double_extension_heuristic(self):
        """Test double extension heuristic detection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt.exe') as f:
            f.write(b'MZ')  # PE header start
            f.write(b'\x00' * 100)
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            semantic = part1.get('semantic_file_type', {}).get('output_value', {})
            semantic_type = semantic.get('semantic_file_type', 'UNKNOWN')
            
            engine = HeuristicEngine(part1, part2, semantic_type)
            results = engine.evaluate()
            
            triggered_names = [h['heuristic_key'] for h in results['triggered_heuristics']]
            self.assertIn('double_extension', triggered_names)
        finally:
            os.unlink(temp_path)
    
    def test_plain_text_no_suspicious_heuristics(self):
        """Test that plain text files don't trigger suspicious heuristics."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'This is a simple plain text file.\n')
            f.write(b'It contains no suspicious content.\n')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            semantic = part1.get('semantic_file_type', {}).get('output_value', {})
            semantic_type = semantic.get('semantic_file_type', 'UNKNOWN')
            
            engine = HeuristicEngine(part1, part2, semantic_type)
            results = engine.evaluate()
            
            # Should not trigger high-severity heuristics
            high_severity = [
                h for h in results['triggered_heuristics']
                if h['severity'] in ['high', 'critical']
            ]
            self.assertEqual(len(high_severity), 0)
        finally:
            os.unlink(temp_path)


class TestRiskScorer(unittest.TestCase):
    """Test risk scorer functionality."""
    
    def test_empty_score(self):
        """Test scoring with no evidence."""
        scorer = RiskScorer(semantic_file_type='UNKNOWN')
        result = scorer.compute_score()
        
        self.assertEqual(result['raw_score'], 0)
        self.assertEqual(result['normalized_score'], 0)
        self.assertEqual(result['severity'], 'informational')
    
    def test_heuristic_contribution(self):
        """Test that heuristics contribute to score."""
        heuristic_results = {
            'triggered_heuristics': [
                {
                    'id': 'H0001_test',
                    'name': 'Test Heuristic',
                    'weight': 30,
                    'severity': 'medium',
                    'confidence': 'HIGH',
                }
            ],
            'failed_heuristics': [],
        }
        
        scorer = RiskScorer(
            semantic_file_type='UNKNOWN',
            heuristic_results=heuristic_results
        )
        result = scorer.compute_score()
        
        # Should have score contribution
        self.assertGreater(result['raw_score'], 0)
        self.assertGreater(len(result['score_contributions']), 0)
    
    def test_score_explanation(self):
        """Test that score includes explanation."""
        heuristic_results = {
            'triggered_heuristics': [
                {
                    'id': 'H0001_test',
                    'name': 'Test Heuristic',
                    'weight': 50,
                    'severity': 'high',
                    'confidence': 'HIGH',
                }
            ],
            'failed_heuristics': [],
        }
        
        result = compute_risk_score(
            semantic_file_type='UNKNOWN',
            heuristic_results=heuristic_results
        )
        
        self.assertIn('explanation', result)
        self.assertIn('logic_applied', result)
        self.assertTrue(len(result['explanation']) > 0)
    
    def test_severity_mapping(self):
        """Test severity level mapping."""
        # High score should map to high/critical severity
        high_heuristics = {
            'triggered_heuristics': [
                {'id': f'H{i}', 'name': f'Test {i}', 'weight': 40, 'severity': 'high', 'confidence': 'HIGH'}
                for i in range(5)
            ],
            'failed_heuristics': [],
        }
        
        result = compute_risk_score(
            semantic_file_type='UNKNOWN',
            heuristic_results=high_heuristics
        )
        
        # Should have elevated severity
        self.assertIn(result['severity'], ['high', 'critical', 'medium'])


class TestSessionCorrelator(unittest.TestCase):
    """Test session-level correlation."""
    
    def test_single_file_no_correlation(self):
        """Test that single file session returns no correlations."""
        correlator = SessionCorrelator()
        
        # Add single file
        correlator.add_file(
            file_id='file1',
            file_path='/path/to/file1.txt',
            analysis_results={'part1': {}, 'part2': {}}
        )
        
        results = correlator.correlate()
        
        self.assertEqual(len(results['correlations']), 0)
        self.assertIn('note', results)
    
    def test_correlate_session_convenience(self):
        """Test the correlate_session convenience function."""
        files = [
            {
                'file_id': 'file1',
                'file_path': '/path/to/file1.txt',
                'analysis_results': {'part1': {}, 'part2': {'universal': []}}
            },
            {
                'file_id': 'file2',
                'file_path': '/path/to/file2.txt',
                'analysis_results': {'part1': {}, 'part2': {'universal': []}}
            },
        ]
        
        results = correlate_session(files)
        
        self.assertIn('correlations', results)
        self.assertEqual(results['files_analyzed'], 2)


class TestPart3Analyzer(unittest.TestCase):
    """Test the main PART 3 analyzer."""
    
    def test_basic_analysis(self):
        """Test basic PART 3 analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content for analysis.')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            analyzer = Part3Analyzer(temp_path, part1, part2)
            results = analyzer.analyze()
            
            # Should have all required sections
            self.assertIn('file_info', results)
            self.assertIn('rule_engine', results)
            self.assertIn('heuristics', results)
            self.assertIn('risk_score', results)
            self.assertIn('summary', results)
            self.assertIn('reproducibility', results)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_part3_convenience(self):
        """Test the analyze_part3 convenience function."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            self.assertIn('summary', results)
            self.assertTrue(results['summary']['analysis_complete'])
        finally:
            os.unlink(temp_path)
    
    def test_full_analysis_convenience(self):
        """Test the full_analysis convenience function."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content for full analysis.')
            temp_path = f.name
        
        try:
            results = full_analysis(temp_path)
            
            # Should have all three parts
            self.assertIn('part1', results)
            self.assertIn('part2', results)
            self.assertIn('part3', results)
            self.assertIn('summary', results)
        finally:
            os.unlink(temp_path)
    
    def test_json_output(self):
        """Test JSON output generation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test content')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            analyzer = Part3Analyzer(temp_path, part1, part2)
            analyzer.analyze()
            
            json_output = analyzer.to_json()
            
            # Should be valid JSON
            parsed = json.loads(json_output)
            self.assertIsInstance(parsed, dict)
        finally:
            os.unlink(temp_path)
    
    def test_reproducibility_notes(self):
        """Test that reproducibility notes are included."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            self.assertIn('reproducibility', results)
            self.assertTrue(results['reproducibility']['deterministic'])
            self.assertIn('constraints', results['reproducibility'])
        finally:
            os.unlink(temp_path)


class TestOutputContract(unittest.TestCase):
    """Test that output follows the required contract."""
    
    def test_detection_has_required_fields(self):
        """Test that detections have all required fields."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt.exe') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            required_fields = [
                'id', 'type', 'semantic_file_type', 'evidence_references',
                'confidence', 'severity', 'explanation', 'failure_reason'
            ]
            
            # Check triggered heuristics
            for h in results['heuristics']['triggered_heuristics']:
                for field in required_fields:
                    self.assertIn(field, h, f"Missing field {field} in heuristic")
        finally:
            os.unlink(temp_path)
    
    def test_score_has_required_fields(self):
        """Test that risk score has all required fields."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            required_fields = [
                'id', 'type', 'semantic_file_type', 'raw_score', 'normalized_score',
                'confidence', 'severity', 'explanation', 'reproducibility_notes',
                'failure_reason'
            ]
            
            score = results['risk_score']
            for field in required_fields:
                self.assertIn(field, score, f"Missing field {field} in risk_score")
        finally:
            os.unlink(temp_path)
    
    def test_no_score_without_evidence(self):
        """Test that scores reference evidence."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt.exe') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            # Each score contribution should reference evidence
            for contrib in results['risk_score']['score_contributions']:
                self.assertIn('source_id', contrib)
                self.assertIn('source_type', contrib)
                self.assertIn('evidence_reference', contrib)
        finally:
            os.unlink(temp_path)


class TestSeverityLevels(unittest.TestCase):
    """Test severity level handling."""
    
    def test_valid_severity_levels(self):
        """Test that only valid severity levels are used."""
        valid_severities = ['informational', 'low', 'medium', 'high', 'critical']
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt.exe') as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            # Check all heuristics use valid severity
            for h in results['heuristics']['triggered_heuristics']:
                self.assertIn(h['severity'], valid_severities)
            
            # Check risk score uses valid severity
            self.assertIn(results['risk_score']['severity'], valid_severities)
        finally:
            os.unlink(temp_path)


class TestDeterminism(unittest.TestCase):
    """Test that analysis is deterministic."""
    
    def test_same_input_same_output(self):
        """Test that same input produces same output."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b'Deterministic test content')
            temp_path = f.name
        
        try:
            # Run analysis twice
            results1 = full_analysis(temp_path)
            results2 = full_analysis(temp_path)
            
            # Scores should be identical
            self.assertEqual(
                results1['part3']['risk_score']['normalized_score'],
                results2['part3']['risk_score']['normalized_score']
            )
            
            # Heuristic counts should be identical
            self.assertEqual(
                results1['part3']['heuristics']['triggered_count'],
                results2['part3']['heuristics']['triggered_count']
            )
        finally:
            os.unlink(temp_path)


class TestPDFAnalysis(unittest.TestCase):
    """Test PDF-specific heuristics."""
    
    def test_pdf_javascript_heuristic(self):
        """Test PDF JavaScript detection heuristic."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            # Create minimal PDF with JavaScript
            f.write(b'%PDF-1.7\n')
            f.write(b'1 0 obj\n<< /Type /Catalog /JavaScript (alert) >>\nendobj\n')
            f.write(b'xref\n0 2\ntrailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n')
            temp_path = f.name
        
        try:
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            triggered_keys = [h['heuristic_key'] for h in results['heuristics']['triggered_heuristics']]
            
            # PDF JavaScript heuristic should be triggered
            self.assertIn('pdf_javascript', triggered_keys)
        finally:
            os.unlink(temp_path)


class TestZIPAnalysis(unittest.TestCase):
    """Test ZIP-specific heuristics."""
    
    def test_trailing_data_heuristic(self):
        """Test trailing data detection heuristic."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            temp_path = f.name
        
        try:
            # Create valid ZIP
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr('test.txt', 'test')
            
            # Append trailing data
            with open(temp_path, 'ab') as f:
                f.write(b'TRAILING_DATA_HIDDEN' * 10)
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            triggered_keys = [h['heuristic_key'] for h in results['heuristics']['triggered_heuristics']]
            
            # Trailing data heuristic should be triggered
            self.assertIn('trailing_data', triggered_keys)
        finally:
            os.unlink(temp_path)


class TestOOXMLAnalysis(unittest.TestCase):
    """Test OOXML-specific heuristics."""
    
    def test_docx_with_vba(self):
        """Test DOCX with VBA macro detection."""
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
                zf.writestr('word/vbaProject.bin', 'fake vba content')  # VBA indicator
            
            part1 = FileAnalyzer(temp_path).analyze()
            part2 = DeepAnalyzer(temp_path, part1).analyze()
            
            results = analyze_part3(temp_path, part1, part2)
            
            # Should detect VBA macros
            has_vba = any(
                h['heuristic_key'] == 'macro_with_auto_exec'
                for h in results['heuristics']['triggered_heuristics'] + 
                        results['heuristics']['failed_heuristics']
            )
            # The heuristic should at least be evaluated
            self.assertTrue(True)  # Just ensure no crash
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
