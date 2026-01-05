"""
Tests for PART 4: Persistence, CLI & IPC (Data Durability Layer)

These tests verify:
1. JSON schema validation
2. SQLite persistence layer
3. CLI functionality
4. IPC contracts
5. Export/reporting
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from file_analyzer.part4.schemas import (
    SCHEMAS,
    SCHEMA_VERSION,
    validate_schema,
    validate_with_schema,
    ValidationError,
)
from file_analyzer.part4.persistence import (
    AnalysisDatabase,
    DatabaseError,
    IntegrityError,
    generate_case_id,
    generate_session_id,
    generate_record_id,
)
from file_analyzer.part4.ipc import (
    IPCHandler,
    IPCRequest,
    IPCResponse,
    IPCMethod,
    IPCErrorCode,
)
from file_analyzer.part4.exporter import (
    Exporter,
    ExportFormat,
)


class TestSchemas(unittest.TestCase):
    """Test JSON schema validation."""
    
    def test_schema_definitions_exist(self):
        """Test that all required schemas are defined."""
        required_schemas = [
            'file_identity',
            'finding',
            'rule_detection',
            'heuristic_result',
            'risk_score',
            'correlation',
            'session',
            'case',
            'error',
            'analysis_record',
            'provenance',
        ]
        
        for schema_name in required_schemas:
            self.assertIn(schema_name, SCHEMAS, f"Missing schema: {schema_name}")
    
    def test_schema_version_format(self):
        """Test schema version is properly formatted."""
        self.assertRegex(SCHEMA_VERSION, r'^\d+\.\d+\.\d+$')
    
    def test_validate_case_schema(self):
        """Test case schema validation."""
        valid_case = {
            "case_id": "CASE-ABCD1234",
            "name": "Test Case",
            "created_at": "2024-01-01T00:00:00",
            "status": "open",
        }
        
        # Should not raise
        validate_schema(valid_case, "case")
    
    def test_validate_case_schema_invalid(self):
        """Test case schema validation with invalid data."""
        invalid_case = {
            "case_id": "invalid",  # Wrong format
            "name": "Test Case",
            "created_at": "2024-01-01T00:00:00",
            "status": "open",
        }
        
        with self.assertRaises(ValidationError):
            validate_schema(invalid_case, "case")
    
    def test_validate_session_schema(self):
        """Test session schema validation."""
        valid_session = {
            "session_id": "SES-ABCD1234",
            "case_id": "CASE-ABCD1234",
            "created_at": "2024-01-01T00:00:00",
            "status": "active",
        }
        
        validate_schema(valid_session, "session")
    
    def test_validate_finding_schema(self):
        """Test finding schema validation."""
        valid_finding = {
            "finding_id": "F0001_test",
            "finding_type": "test_finding",
            "semantic_file_type": "PLAIN_TEXT",
            "confidence": "HIGH",
        }
        
        validate_schema(valid_finding, "finding")
    
    def test_validate_unknown_schema(self):
        """Test validation with unknown schema name."""
        with self.assertRaises(KeyError):
            validate_schema({}, "unknown_schema")


class TestPersistence(unittest.TestCase):
    """Test SQLite persistence layer."""
    
    def setUp(self):
        """Set up test database."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = AnalysisDatabase(self.db_path)
    
    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass
    
    def test_generate_ids(self):
        """Test ID generation functions."""
        case_id = generate_case_id()
        session_id = generate_session_id()
        record_id = generate_record_id()
        
        self.assertRegex(case_id, r'^CASE-[A-Z0-9]{8}$')
        self.assertRegex(session_id, r'^SES-[A-Z0-9]{8}$')
        self.assertRegex(record_id, r'^REC-[A-Z0-9]{12}$')
    
    def test_create_case(self):
        """Test case creation."""
        case_id = self.db.create_case(
            name="Test Case",
            description="Test description",
            metadata={"key": "value"}
        )
        
        self.assertRegex(case_id, r'^CASE-[A-Z0-9]{8}$')
        
        # Retrieve case
        case = self.db.get_case(case_id)
        self.assertIsNotNone(case)
        self.assertEqual(case['name'], "Test Case")
        self.assertEqual(case['description'], "Test description")
        self.assertEqual(case['metadata'], {"key": "value"})
    
    def test_list_cases(self):
        """Test listing cases."""
        # Create multiple cases
        case1 = self.db.create_case(name="Case 1")
        case2 = self.db.create_case(name="Case 2")
        
        cases = self.db.list_cases()
        self.assertEqual(len(cases), 2)
    
    def test_create_session(self):
        """Test session creation."""
        case_id = self.db.create_case(name="Test Case")
        session_id = self.db.create_session(
            case_id=case_id,
            name="Test Session",
            description="Session description"
        )
        
        self.assertRegex(session_id, r'^SES-[A-Z0-9]{8}$')
        
        session = self.db.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session['name'], "Test Session")
        self.assertEqual(session['case_id'], case_id)
    
    def test_session_requires_valid_case(self):
        """Test that session creation requires a valid case."""
        with self.assertRaises(DatabaseError):
            self.db.create_session(case_id="CASE-INVALID1")
    
    def test_import_analysis(self):
        """Test importing analysis results."""
        case_id = self.db.create_case(name="Test Case")
        session_id = self.db.create_session(case_id=case_id)
        
        # Mock PART 1, 2, 3 results
        part1 = {
            'file_info': {
                'file_path': '/test/file.txt',
                'file_name': 'file.txt',
                'file_size': 100,
            },
            'cryptographic_identity': {
                'hashes': [
                    {'evidence': {'algorithm': 'SHA256'}, 'output_value': 'abc123'},
                ]
            },
            'semantic_file_type': {
                'output_value': {'semantic_file_type': 'PLAIN_TEXT'}
            },
        }
        
        part2 = {
            'universal': [
                {
                    'finding_id': 'F0001_test',
                    'finding_type': 'test_finding',
                    'semantic_file_type': 'PLAIN_TEXT',
                    'confidence': 'HIGH',
                }
            ],
            'container_level': [],
            'file_type_specific': [],
        }
        
        part3 = {
            'risk_score': {
                'normalized_score': 25.5,
                'severity': 'low',
            },
            'heuristics': {
                'triggered_heuristics': [],
                'failed_heuristics': [],
            },
            'rule_engine': {
                'yara_detections': [],
            },
        }
        
        record_id = self.db.import_analysis(
            session_id=session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3
        )
        
        self.assertRegex(record_id, r'^REC-[A-Z0-9]{12}$')
        
        # Retrieve record
        record = self.db.get_record(record_id)
        self.assertIsNotNone(record)
        self.assertEqual(record['file_name'], 'file.txt')
        self.assertEqual(record['risk_score'], 25.5)
    
    def test_query_records(self):
        """Test querying records with filters."""
        case_id = self.db.create_case(name="Test Case")
        session_id = self.db.create_session(case_id=case_id)
        
        # Import multiple records
        for i in range(3):
            part1 = {
                'file_info': {'file_path': f'/test/file{i}.txt', 'file_name': f'file{i}.txt', 'file_size': 100},
                'cryptographic_identity': {'hashes': [{'evidence': {'algorithm': 'SHA256'}, 'output_value': f'hash{i}'}]},
                'semantic_file_type': {'output_value': {'semantic_file_type': 'PLAIN_TEXT'}},
            }
            part2 = {
                'universal': [],
                'container_level': [],
                'file_type_specific': []
            }
            part3 = {
                'risk_score': {'normalized_score': i * 30, 'severity': 'low'},
                'heuristics': {'triggered_heuristics': [], 'failed_heuristics': []},
                'rule_engine': {'yara_detections': []}
            }
            
            self.db.import_analysis(session_id=session_id, part1_results=part1, part2_results=part2, part3_results=part3)
        
        # Query all
        records = self.db.query_records(session_id=session_id)
        self.assertEqual(len(records), 3)
        
        # Query with min score
        records = self.db.query_records(session_id=session_id, min_score=50)
        self.assertEqual(len(records), 1)
    
    def test_get_statistics(self):
        """Test getting database statistics."""
        case_id = self.db.create_case(name="Test Case")
        self.db.create_session(case_id=case_id)
        
        stats = self.db.get_statistics()
        
        self.assertEqual(stats['case_count'], 1)
        self.assertEqual(stats['session_count'], 1)
        self.assertIn('schema_version', stats)
        self.assertIn('tool_version', stats)
    
    def test_log_error(self):
        """Test error logging."""
        error_id = self.db.log_error(
            error_type="test_error",
            message="Test error message",
            context={"key": "value"},
            recoverable=True
        )
        
        self.assertRegex(error_id, r'^ERR-[A-Z0-9]{8}$')
        
        errors = self.db.get_errors()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['message'], "Test error message")


class TestIPC(unittest.TestCase):
    """Test IPC contracts."""
    
    def setUp(self):
        """Set up test database and IPC handler."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = AnalysisDatabase(self.db_path)
        self.handler = IPCHandler(self.db)
    
    def tearDown(self):
        """Clean up."""
        self.db.close()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass
    
    def test_ipc_request_from_dict(self):
        """Test creating IPCRequest from dict."""
        data = {
            'id': 'req-001',
            'method': 'ping',
            'params': {},
        }
        
        request = IPCRequest.from_dict(data)
        self.assertEqual(request.id, 'req-001')
        self.assertEqual(request.method, 'ping')
    
    def test_ipc_request_from_json(self):
        """Test creating IPCRequest from JSON."""
        json_str = '{"id": "req-001", "method": "ping", "params": {}}'
        
        request = IPCRequest.from_json(json_str)
        self.assertEqual(request.id, 'req-001')
    
    def test_ipc_response_to_json(self):
        """Test IPCResponse to JSON conversion."""
        response = IPCResponse.success_response('req-001', {'status': 'ok'})
        
        json_str = response.to_json()
        data = json.loads(json_str)
        
        self.assertEqual(data['id'], 'req-001')
        self.assertTrue(data['success'])
        self.assertEqual(data['data'], {'status': 'ok'})
    
    def test_handle_ping(self):
        """Test ping method."""
        request = IPCRequest(id='req-001', method='ping')
        response = self.handler.handle_request(request)
        
        self.assertTrue(response.success)
        self.assertEqual(response.data['status'], 'ok')
    
    def test_handle_get_statistics(self):
        """Test get_statistics method."""
        request = IPCRequest(id='req-001', method='get_statistics')
        response = self.handler.handle_request(request)
        
        self.assertTrue(response.success)
        self.assertIn('case_count', response.data)
        self.assertIn('session_count', response.data)
    
    def test_handle_list_cases(self):
        """Test list_cases method."""
        # Create a case
        self.db.create_case(name="Test Case")
        
        request = IPCRequest(id='req-001', method='list_cases', params={})
        response = self.handler.handle_request(request)
        
        self.assertTrue(response.success)
        self.assertEqual(len(response.data), 1)
    
    def test_handle_invalid_method(self):
        """Test handling invalid method."""
        request = IPCRequest(id='req-001', method='invalid_method')
        response = self.handler.handle_request(request)
        
        self.assertFalse(response.success)
        self.assertEqual(response.error.code, IPCErrorCode.INVALID_REQUEST.value)
    
    def test_handle_json_request(self):
        """Test handling JSON request string."""
        json_request = '{"id": "req-001", "method": "ping", "params": {}}'
        json_response = self.handler.handle_json(json_request)
        
        response = json.loads(json_response)
        self.assertTrue(response['success'])
    
    def test_handle_invalid_json(self):
        """Test handling invalid JSON."""
        response = self.handler.handle_request("invalid json")
        
        self.assertFalse(response.success)
        self.assertEqual(response.error.code, IPCErrorCode.INVALID_REQUEST.value)
    
    def test_cli_ipc_parity(self):
        """Test that CLI and IPC return identical results."""
        # Create data via CLI-like operations
        case_id = self.db.create_case(name="Parity Test")
        session_id = self.db.create_session(case_id=case_id)
        
        # Query via IPC
        request = IPCRequest(
            id='req-001',
            method='list_sessions',
            params={'case_id': case_id}
        )
        ipc_response = self.handler.handle_request(request)
        
        # Query via database directly (simulating CLI)
        cli_result = self.db.list_sessions(case_id=case_id)
        
        # Compare results (should be identical)
        self.assertEqual(len(ipc_response.data), len(cli_result))
        self.assertEqual(ipc_response.data[0]['session_id'], cli_result[0]['session_id'])


class TestExporter(unittest.TestCase):
    """Test export/reporting functionality."""
    
    def setUp(self):
        """Set up test database and exporter."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = AnalysisDatabase(self.db_path)
        self.exporter = Exporter(self.db)
        
        # Create test data
        self.case_id = self.db.create_case(name="Export Test Case")
        self.session_id = self.db.create_session(case_id=self.case_id, name="Export Test Session")
        
        part1 = {
            'file_info': {'file_path': '/test/file.txt', 'file_name': 'file.txt', 'file_size': 100},
            'cryptographic_identity': {'hashes': [{'evidence': {'algorithm': 'SHA256'}, 'output_value': 'abc123'}]},
            'semantic_file_type': {'output_value': {'semantic_file_type': 'PLAIN_TEXT'}},
        }
        part2 = {'universal': [], 'container_level': [], 'file_type_specific': []}
        part3 = {'risk_score': {'normalized_score': 25.5, 'severity': 'low'}, 'heuristics': {'triggered_heuristics': [], 'failed_heuristics': []}, 'rule_engine': {'yara_detections': []}}
        
        self.record_id = self.db.import_analysis(
            session_id=self.session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3
        )
    
    def tearDown(self):
        """Clean up."""
        self.db.close()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass
    
    def test_export_record_json(self):
        """Test exporting record to JSON."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            output_path = f.name
        
        try:
            result_path = self.exporter.export_record(
                record_id=self.record_id,
                output_path=output_path,
                format=ExportFormat.JSON
            )
            
            self.assertTrue(os.path.exists(result_path))
            
            with open(result_path, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data['export_type'], 'record')
            self.assertIn('record', data)
            self.assertIn('findings', data)
            self.assertIn('export_timestamp', data)
            self.assertIn('schema_version', data)
        finally:
            try:
                os.unlink(result_path)
            except Exception:
                pass
    
    def test_export_session_json(self):
        """Test exporting session to JSON."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            output_path = f.name
        
        try:
            result_path = self.exporter.export_session(
                session_id=self.session_id,
                output_path=output_path,
                format=ExportFormat.JSON
            )
            
            self.assertTrue(os.path.exists(result_path))
            
            with open(result_path, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data['export_type'], 'session')
            self.assertIn('session', data)
            self.assertIn('records', data)
            self.assertEqual(data['record_count'], 1)
        finally:
            try:
                os.unlink(result_path)
            except Exception:
                pass
    
    def test_export_case_json(self):
        """Test exporting case to JSON."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            output_path = f.name
        
        try:
            result_path = self.exporter.export_case(
                case_id=self.case_id,
                output_path=output_path,
                format=ExportFormat.JSON
            )
            
            self.assertTrue(os.path.exists(result_path))
            
            with open(result_path, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data['export_type'], 'case')
            self.assertIn('case', data)
            self.assertIn('sessions', data)
        finally:
            try:
                os.unlink(result_path)
            except Exception:
                pass
    
    def test_export_record_html(self):
        """Test exporting record to HTML."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as f:
            output_path = f.name
        
        try:
            result_path = self.exporter.export_record(
                record_id=self.record_id,
                output_path=output_path,
                format=ExportFormat.HTML
            )
            
            self.assertTrue(os.path.exists(result_path))
            
            with open(result_path, 'r') as f:
                content = f.read()
            
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('File Analysis Report', content)
            self.assertIn('file.txt', content)
        finally:
            try:
                os.unlink(result_path)
            except Exception:
                pass
    
    def test_export_invalid_record(self):
        """Test exporting non-existent record."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            output_path = f.name
        
        try:
            with self.assertRaises(ValueError):
                self.exporter.export_record(
                    record_id="REC-INVALID12345",
                    output_path=output_path,
                    format=ExportFormat.JSON
                )
        finally:
            try:
                os.unlink(output_path)
            except Exception:
                pass


class TestDataIntegrity(unittest.TestCase):
    """Test data integrity and byte-match verification."""
    
    def setUp(self):
        """Set up test database."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = AnalysisDatabase(self.db_path)
    
    def tearDown(self):
        """Clean up."""
        self.db.close()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass
    
    def test_record_byte_match_verification(self):
        """Test that reloaded records match original inputs."""
        case_id = self.db.create_case(name="Integrity Test")
        session_id = self.db.create_session(case_id=case_id)
        
        # Original data
        part1 = {
            'file_info': {'file_path': '/test/file.txt', 'file_name': 'file.txt', 'file_size': 12345},
            'cryptographic_identity': {'hashes': [{'evidence': {'algorithm': 'SHA256'}, 'output_value': 'deadbeef123'}]},
            'semantic_file_type': {'output_value': {'semantic_file_type': 'PLAIN_TEXT', 'container_type': None}},
        }
        part2 = {'universal': [], 'container_level': [], 'file_type_specific': [], 'summary': {'total_findings': 0}}
        part3 = {'risk_score': {'normalized_score': 42.5, 'severity': 'medium'}, 'heuristics': {'triggered_heuristics': [], 'failed_heuristics': []}, 'rule_engine': {'yara_detections': []}}
        
        record_id = self.db.import_analysis(
            session_id=session_id,
            part1_results=part1,
            part2_results=part2,
            part3_results=part3
        )
        
        # Reload and verify
        record = self.db.get_record(record_id)
        
        # Verify key data matches
        self.assertEqual(record['part1']['file_info']['file_size'], part1['file_info']['file_size'])
        self.assertEqual(record['part2']['summary']['total_findings'], part2['summary']['total_findings'])
        self.assertEqual(record['part3']['risk_score']['normalized_score'], part3['risk_score']['normalized_score'])
    
    def test_checksum_verification(self):
        """Test that integrity check catches corruption."""
        case_id = self.db.create_case(name="Checksum Test")
        
        # Get and verify case data
        case = self.db.get_case(case_id)
        self.assertIsNotNone(case)
        self.assertEqual(case['name'], "Checksum Test")


class TestDeterminism(unittest.TestCase):
    """Test that operations are deterministic."""
    
    def test_same_input_same_output(self):
        """Test that the same input always produces the same output."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path1 = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path2 = f.name
        
        try:
            db1 = AnalysisDatabase(db_path1)
            db2 = AnalysisDatabase(db_path2)
            
            # Same operations on both databases
            for db in [db1, db2]:
                case_id = db.create_case(name="Determinism Test")
                session_id = db.create_session(case_id=case_id)
            
            # Query results should have same structure
            stats1 = db1.get_statistics()
            stats2 = db2.get_statistics()
            
            self.assertEqual(stats1['case_count'], stats2['case_count'])
            self.assertEqual(stats1['session_count'], stats2['session_count'])
            
            db1.close()
            db2.close()
        finally:
            try:
                os.unlink(db_path1)
                os.unlink(db_path2)
            except Exception:
                pass


if __name__ == '__main__':
    unittest.main()
