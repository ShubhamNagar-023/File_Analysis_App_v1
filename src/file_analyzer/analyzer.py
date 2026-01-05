"""
File Analyzer - PART 1: File Ingestion & Exact File-Type Resolution

This module implements secure file ingestion, cryptographic identity computation,
magic-byte detection, container identification, and exact semantic file-type resolution.
"""

import hashlib
import json
import os
import stat
import struct
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Third-party imports with fallback handling
try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


# Magic signatures database
MAGIC_SIGNATURES = {
    # Images
    b'\xFF\xD8\xFF': {'type': 'JPEG', 'offset': 0, 'category': 'image'},
    b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'offset': 0, 'category': 'image'},
    b'GIF87a': {'type': 'GIF', 'offset': 0, 'category': 'image'},
    b'GIF89a': {'type': 'GIF', 'offset': 0, 'category': 'image'},
    
    # PDF
    b'%PDF': {'type': 'PDF', 'offset': 0, 'category': 'document'},
    
    # Archive formats
    b'PK\x03\x04': {'type': 'ZIP', 'offset': 0, 'category': 'archive'},
    b'PK\x05\x06': {'type': 'ZIP_EMPTY', 'offset': 0, 'category': 'archive'},
    b'PK\x07\x08': {'type': 'ZIP_SPANNED', 'offset': 0, 'category': 'archive'},
    b'Rar!\x1a\x07\x00': {'type': 'RAR', 'offset': 0, 'category': 'archive'},
    b'Rar!\x1a\x07\x01\x00': {'type': 'RAR5', 'offset': 0, 'category': 'archive'},
    b'7z\xbc\xaf\x27\x1c': {'type': '7Z', 'offset': 0, 'category': 'archive'},
    
    # OLE Compound Document (legacy Office)
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {'type': 'OLE', 'offset': 0, 'category': 'container'},
    
    # Executables
    b'MZ': {'type': 'PE', 'offset': 0, 'category': 'executable'},
    b'\x7fELF': {'type': 'ELF', 'offset': 0, 'category': 'executable'},
    b'\xfe\xed\xfa\xce': {'type': 'MACH_O_32', 'offset': 0, 'category': 'executable'},
    b'\xfe\xed\xfa\xcf': {'type': 'MACH_O_64', 'offset': 0, 'category': 'executable'},
    b'\xce\xfa\xed\xfe': {'type': 'MACH_O_32_BE', 'offset': 0, 'category': 'executable'},
    b'\xcf\xfa\xed\xfe': {'type': 'MACH_O_64_BE', 'offset': 0, 'category': 'executable'},
    b'\xca\xfe\xba\xbe': {'type': 'MACH_O_UNIVERSAL', 'offset': 0, 'category': 'executable'},
}

# OOXML content types that indicate specific Office document types
OOXML_CONTENT_TYPES = {
    'word/document.xml': 'DOCX',
    'word/': 'DOCX',
    'xl/workbook.xml': 'XLSX',
    'xl/': 'XLSX',
    'ppt/presentation.xml': 'PPTX',
    'ppt/': 'PPTX',
}

# Required OOXML components for validation
OOXML_REQUIRED_COMPONENTS = {
    'DOCX': ['[Content_Types].xml', 'word/document.xml'],
    'XLSX': ['[Content_Types].xml', 'xl/workbook.xml'],
    'PPTX': ['[Content_Types].xml', 'ppt/presentation.xml'],
}

# OLE stream identifiers for legacy Office documents
OLE_DOCUMENT_STREAMS = {
    'WordDocument': 'DOC',
    'Workbook': 'XLS',
    'Book': 'XLS',
    'PowerPoint Document': 'PPT',
}

# Unicode deception characters
UNICODE_DECEPTION_CHARS = {
    '\u202E': 'RLO (Right-to-Left Override)',
    '\u202D': 'LRO (Left-to-Right Override)',
    '\u202C': 'PDF (Pop Directional Formatting)',
    '\u200E': 'LRM (Left-to-Right Mark)',
    '\u200F': 'RLM (Right-to-Left Mark)',
    '\u2066': 'LRI (Left-to-Right Isolate)',
    '\u2067': 'RLI (Right-to-Left Isolate)',
    '\u2068': 'FSI (First Strong Isolate)',
    '\u2069': 'PDI (Pop Directional Isolate)',
    '\u200B': 'ZWSP (Zero Width Space)',
    '\u200C': 'ZWNJ (Zero Width Non-Joiner)',
    '\u200D': 'ZWJ (Zero Width Joiner)',
    '\uFEFF': 'BOM (Byte Order Mark)',
}

# Homoglyph mappings (partial, common examples)
HOMOGLYPHS = {
    '\u0430': 'a',  # Cyrillic a
    '\u0435': 'e',  # Cyrillic e
    '\u043e': 'o',  # Cyrillic o
    '\u0440': 'p',  # Cyrillic p
    '\u0441': 'c',  # Cyrillic c
    '\u0443': 'y',  # Cyrillic y
    '\u0445': 'x',  # Cyrillic x
    '\u0456': 'i',  # Cyrillic i
    '\u0458': 'j',  # Cyrillic j
    '\u04bb': 'h',  # Cyrillic h
    '\u04bd': 'c',  # Cyrillic c (with hook)
}


class FileAnalyzer:
    """
    Forensic-sound file analyzer for PART 1 requirements.
    
    Performs secure file ingestion, cryptographic identity computation,
    magic-byte detection, container identification, and exact semantic
    file-type resolution.
    """
    
    def __init__(self, file_path: str):
        """
        Initialize the analyzer with a file path.
        
        Args:
            file_path: Absolute or relative path to the file to analyze.
        """
        self.original_path = Path(file_path).absolute()
        self.file_path = self.original_path.resolve()
        self.file_data: Optional[bytes] = None
        self.file_size: int = 0
        self.analysis_results: Dict[str, Any] = {
            'file_info': {},
            'ingestion': {},
            'cryptographic_identity': {},
            'magic_detection': {},
            'container_identification': {},
            'semantic_file_type': {},
            'extension_analysis': {},
            'filesystem_metadata': {},
            'advanced_checks': {},
            'summary': {},
        }
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform full PART 1 analysis on the file.
        
        Returns:
            Dict containing all analysis results in structured JSON format.
        """
        try:
            # Step 1: Secure file ingestion
            self._perform_secure_ingestion()
            
            # Step 2: Cryptographic file identity
            self._compute_cryptographic_identity()
            
            # Step 3: Magic-byte and signature detection
            self._detect_magic_signatures()
            
            # Step 4: Container type identification
            self._identify_container_type()
            
            # Step 5: Exact semantic file-type resolution
            self._resolve_semantic_file_type()
            
            # Step 6: Extension chain and filename deception analysis
            self._analyze_extensions()
            
            # Step 7: Filesystem metadata extraction
            self._extract_filesystem_metadata()
            
            # Step 8: Advanced checks
            self._perform_advanced_checks()
            
            # Step 9: Generate summary
            self._generate_summary()
            
        except Exception as e:
            self.analysis_results['error'] = {
                'type': type(e).__name__,
                'message': str(e),
                'analysis_state': 'FAILED',
            }
        
        return self.analysis_results
    
    def _perform_secure_ingestion(self) -> None:
        """Securely ingest the file in binary read-only mode."""
        result = {
            'analysis_name': 'secure_file_ingestion',
            'library_or_method': 'Python os/pathlib/stat',
            'input_byte_range': 'N/A',
            'output_value': {},
            'evidence': [],
            'verification_method': 'filesystem stat comparison',
            'failure_reason': None,
        }
        
        # Check file existence
        if not self.file_path.exists():
            result['failure_reason'] = f'File does not exist: {self.file_path}'
            result['output_value']['status'] = 'FAILED'
            self.analysis_results['ingestion'] = result
            raise FileNotFoundError(result['failure_reason'])
        
        # Check if it's a symbolic link (using original path before resolution)
        is_symlink = self.original_path.is_symlink()
        if is_symlink:
            result['evidence'].append({
                'type': 'symlink_detected',
                'original_path': str(self.original_path),
                'real_path': str(self.file_path),
            })
        
        # Get file stats
        file_stat = os.stat(self.file_path)
        lstat = os.lstat(self.file_path)
        
        # Check for hard links
        hard_link_count = file_stat.st_nlink
        is_hard_linked = hard_link_count > 1
        
        # Check for sparse file (on Unix systems)
        is_sparse = False
        try:
            if hasattr(file_stat, 'st_blocks'):
                # st_blocks is in 512-byte units
                apparent_size = file_stat.st_size
                actual_blocks = file_stat.st_blocks * 512
                is_sparse = actual_blocks < apparent_size
        except Exception:
            pass
        
        # Read the file in binary mode
        expected_size = file_stat.st_size
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
        except PermissionError as e:
            result['failure_reason'] = f'Permission denied: {e}'
            result['output_value']['status'] = 'FAILED'
            self.analysis_results['ingestion'] = result
            raise
        
        actual_size = len(self.file_data)
        self.file_size = actual_size
        
        # Verify bytes read match filesystem size
        size_match = actual_size == expected_size
        is_truncated = actual_size < expected_size
        
        result['output_value'] = {
            'status': 'SUCCESS' if size_match else 'SIZE_MISMATCH',
            'file_path': str(self.file_path),
            'expected_size_bytes': expected_size,
            'actual_size_bytes': actual_size,
            'size_match': size_match,
            'is_truncated': is_truncated,
            'is_symlink': is_symlink,
            'is_hard_linked': is_hard_linked,
            'hard_link_count': hard_link_count,
            'is_sparse': is_sparse,
        }
        
        if is_symlink:
            result['output_value']['symlink_target'] = str(os.readlink(self.original_path))
        
        result['evidence'].append({
            'type': 'size_verification',
            'expected': expected_size,
            'actual': actual_size,
            'match': size_match,
        })
        
        if not size_match:
            result['failure_reason'] = f'Size mismatch: expected {expected_size}, got {actual_size}'
        
        self.analysis_results['ingestion'] = result
        
        # Store basic file info
        self.analysis_results['file_info'] = {
            'file_path': str(self.file_path),
            'file_name': self.file_path.name,
            'file_size': actual_size,
        }
    
    def _compute_cryptographic_identity(self) -> None:
        """Compute cryptographic hashes for file identity."""
        if self.file_data is None:
            return
        
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        results = []
        
        for algo in algorithms:
            hasher = hashlib.new(algo)
            hasher.update(self.file_data)
            hash_value = hasher.hexdigest()
            
            results.append({
                'analysis_name': f'hash_{algo}',
                'library_or_method': f'hashlib.{algo}',
                'input_byte_range': f'0-{self.file_size}',
                'output_value': hash_value,
                'evidence': {
                    'algorithm': algo.upper(),
                    'digest_length_bits': len(hash_value) * 4,
                    'full_file_coverage': True,
                },
                'verification_method': f'Compare with: {algo}sum {self.file_path.name}',
                'failure_reason': None,
            })
        
        self.analysis_results['cryptographic_identity'] = {
            'hashes': results,
            'byte_range_covered': f'0-{self.file_size}',
            'verification_note': 'Hashes computed over entire file content',
        }
    
    def _detect_magic_signatures(self) -> None:
        """Detect magic bytes and file signatures."""
        if self.file_data is None:
            return
        
        result = {
            'analysis_name': 'magic_signature_detection',
            'library_or_method': 'Built-in signature matching + python-magic',
            'input_byte_range': f'0-{min(self.file_size, 8192)}',
            'output_value': {
                'signatures_found': [],
                'overlapping_signatures': [],
                'polyglot_indicators': [],
            },
            'evidence': [],
            'verification_method': 'Byte-by-byte signature matching',
            'failure_reason': None,
        }
        
        signatures_found = []
        
        # Check built-in signatures
        for signature, info in MAGIC_SIGNATURES.items():
            offset = info.get('offset', 0)
            if len(self.file_data) >= offset + len(signature):
                if self.file_data[offset:offset + len(signature)] == signature:
                    signatures_found.append({
                        'signature_type': info['type'],
                        'category': info['category'],
                        'offset': offset,
                        'signature_hex': signature.hex(),
                        'signature_length': len(signature),
                    })
        
        # Check for PE with DOS stub (need to verify PE signature)
        if self.file_data[:2] == b'MZ' and len(self.file_data) >= 64:
            try:
                pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
                if pe_offset < len(self.file_data) - 4:
                    if self.file_data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                        # Confirm it's a valid PE
                        for sig in signatures_found:
                            if sig['signature_type'] == 'PE':
                                sig['pe_signature_offset'] = pe_offset
                                sig['pe_signature_verified'] = True
            except Exception:
                pass
        
        # Use python-magic if available
        if HAS_MAGIC:
            try:
                magic_result = magic.from_buffer(self.file_data, mime=False)
                mime_result = magic.from_buffer(self.file_data, mime=True)
                result['output_value']['magic_library_detection'] = {
                    'description': magic_result,
                    'mime_type': mime_result,
                }
            except Exception as e:
                result['output_value']['magic_library_detection'] = {
                    'error': str(e),
                }
        
        # Check for TAR format (ustar signature at offset 257)
        if len(self.file_data) >= 263:  # Need at least 263 bytes for ustar check
            if self.file_data[257:262] == b'ustar':
                signatures_found.append({
                    'signature_type': 'TAR',
                    'category': 'archive',
                    'offset': 0,
                    'signature_hex': self.file_data[257:263].hex(),
                    'signature_length': 6,
                    'note': 'ustar format at offset 257',
                })
        
        # Detect overlapping signatures
        if len(signatures_found) > 1:
            result['output_value']['overlapping_signatures'] = [
                {
                    'types': [s['signature_type'] for s in signatures_found],
                    'note': 'Multiple signatures detected - potential polyglot',
                }
            ]
        
        # Polyglot detection
        polyglot_indicators = []
        
        # Check for PDF after ZIP (common polyglot)
        if any(s['signature_type'] == 'ZIP' for s in signatures_found):
            pdf_pos = self.file_data.find(b'%PDF')
            if pdf_pos > 0:
                polyglot_indicators.append({
                    'type': 'ZIP+PDF polyglot',
                    'pdf_offset': pdf_pos,
                })
        
        # Check for hidden signatures at non-zero offsets
        for offset in [1, 2, 4, 8, 512, 1024]:
            if len(self.file_data) > offset + 8:
                for signature, info in MAGIC_SIGNATURES.items():
                    if self.file_data[offset:offset + len(signature)] == signature:
                        polyglot_indicators.append({
                            'type': f'Hidden {info["type"]} signature',
                            'offset': offset,
                            'note': 'Signature at non-standard offset',
                        })
        
        result['output_value']['signatures_found'] = signatures_found
        result['output_value']['polyglot_indicators'] = polyglot_indicators
        result['evidence'] = signatures_found
        
        self.analysis_results['magic_detection'] = result
    
    def _identify_container_type(self) -> None:
        """Identify the base container type (if any)."""
        if self.file_data is None:
            return
        
        result = {
            'analysis_name': 'container_type_identification',
            'library_or_method': 'Signature-based detection',
            'input_byte_range': f'0-{min(self.file_size, 1024)}',
            'output_value': {
                'container_type': None,
                'is_container': False,
            },
            'evidence': [],
            'verification_method': 'Magic byte verification',
            'failure_reason': None,
        }
        
        container_type = None
        
        # Check for ZIP container
        if self.file_data[:4] in [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']:
            container_type = 'ZIP'
        
        # Check for OLE container
        elif self.file_data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            container_type = 'OLE'
        
        # Check for PDF
        elif self.file_data[:4] == b'%PDF':
            container_type = 'PDF'
        
        # Check for PE/ELF/Mach-O
        elif self.file_data[:2] == b'MZ':
            container_type = 'PE'
        elif self.file_data[:4] == b'\x7fELF':
            container_type = 'ELF'
        elif self.file_data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                      b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                                      b'\xca\xfe\xba\xbe']:
            container_type = 'MACH_O'
        
        # Check for TAR
        elif len(self.file_data) > 262 and self.file_data[257:262] == b'ustar':
            container_type = 'TAR'
        
        # Check for 7Z
        elif self.file_data[:6] == b'7z\xbc\xaf\x27\x1c':
            container_type = '7Z'
        
        # Check for RAR
        elif self.file_data[:7] == b'Rar!\x1a\x07\x00' or \
             self.file_data[:8] == b'Rar!\x1a\x07\x01\x00':
            container_type = 'RAR'
        
        result['output_value']['container_type'] = container_type
        result['output_value']['is_container'] = container_type is not None
        result['evidence'].append({
            'detected_type': container_type,
            'method': 'magic_byte_match',
        })
        
        self.analysis_results['container_identification'] = result
    
    def _resolve_semantic_file_type(self) -> None:
        """
        Resolve the true semantic file type using internal structure.
        
        This is the CRITICAL function that distinguishes:
        - DOCX from ZIP
        - DOC from OLE
        - And other semantic types from their containers
        """
        if self.file_data is None:
            return
        
        result = {
            'analysis_name': 'semantic_file_type_resolution',
            'library_or_method': 'Internal structure analysis + olefile/zipfile',
            'input_byte_range': f'0-{self.file_size}',
            'output_value': {
                'container_type': None,
                'semantic_file_type': 'UNKNOWN',
                'classification_confidence': 'LOW',
                'classification_evidence': [],
            },
            'evidence': [],
            'verification_method': 'Internal structure validation',
            'failure_reason': None,
        }
        
        container = self.analysis_results.get('container_identification', {})
        container_type = container.get('output_value', {}).get('container_type')
        
        result['output_value']['container_type'] = container_type
        
        semantic_type = 'UNKNOWN'
        confidence = 'LOW'
        evidence = []
        
        if container_type == 'ZIP':
            # Check for OOXML documents
            semantic_type, confidence, evidence = self._analyze_zip_contents()
        
        elif container_type == 'OLE':
            # Check for legacy Office documents
            semantic_type, confidence, evidence = self._analyze_ole_contents()
        
        elif container_type == 'PDF':
            semantic_type = 'PDF'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'PDF signature confirmed'})
        
        elif container_type == 'PE':
            semantic_type = 'EXECUTABLE_PE'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'PE signature confirmed'})
        
        elif container_type == 'ELF':
            semantic_type = 'EXECUTABLE_ELF'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'ELF signature confirmed'})
        
        elif container_type == 'MACH_O':
            semantic_type = 'EXECUTABLE_MACH_O'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'Mach-O signature confirmed'})
        
        elif container_type == 'TAR':
            semantic_type = 'ARCHIVE_TAR'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'TAR signature confirmed'})
        
        elif container_type == '7Z':
            semantic_type = 'ARCHIVE_7Z'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': '7Z signature confirmed'})
        
        elif container_type == 'RAR':
            semantic_type = 'ARCHIVE_RAR'
            confidence = 'HIGH'
            evidence.append({'type': 'magic_match', 'value': 'RAR signature confirmed'})
        
        else:
            # Check for images and other formats
            semantic_type, confidence, evidence = self._analyze_non_container()
        
        result['output_value']['semantic_file_type'] = semantic_type
        result['output_value']['classification_confidence'] = confidence
        result['output_value']['classification_evidence'] = evidence
        result['evidence'] = evidence
        
        self.analysis_results['semantic_file_type'] = result
    
    def _analyze_zip_contents(self) -> Tuple[str, str, List[Dict]]:
        """Analyze ZIP contents to determine semantic file type."""
        evidence = []
        
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(self.file_data), 'r') as zf:
                file_list = zf.namelist()
                
                # Check for [Content_Types].xml - OOXML indicator
                has_content_types = '[Content_Types].xml' in file_list
                
                if has_content_types:
                    evidence.append({
                        'type': 'ooxml_marker',
                        'file': '[Content_Types].xml',
                        'present': True,
                    })
                    
                    # Read Content_Types.xml to determine type
                    try:
                        content_types = zf.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                        
                        # Check for DOCX
                        if 'word/document.xml' in file_list or \
                           'application/vnd.openxmlformats-officedocument.wordprocessingml' in content_types:
                            # Verify required components
                            missing = []
                            for req in OOXML_REQUIRED_COMPONENTS.get('DOCX', []):
                                if req not in file_list:
                                    missing.append(req)
                            
                            evidence.append({
                                'type': 'ooxml_docx',
                                'paths_found': [f for f in file_list if f.startswith('word/')],
                                'missing_components': missing,
                            })
                            
                            if not missing:
                                return 'DOCX', 'HIGH', evidence
                            else:
                                return 'DOCX', 'MEDIUM', evidence
                        
                        # Check for XLSX
                        elif 'xl/workbook.xml' in file_list or \
                             'application/vnd.openxmlformats-officedocument.spreadsheetml' in content_types:
                            missing = []
                            for req in OOXML_REQUIRED_COMPONENTS.get('XLSX', []):
                                if req not in file_list:
                                    missing.append(req)
                            
                            evidence.append({
                                'type': 'ooxml_xlsx',
                                'paths_found': [f for f in file_list if f.startswith('xl/')],
                                'missing_components': missing,
                            })
                            
                            if not missing:
                                return 'XLSX', 'HIGH', evidence
                            else:
                                return 'XLSX', 'MEDIUM', evidence
                        
                        # Check for PPTX
                        elif 'ppt/presentation.xml' in file_list or \
                             'application/vnd.openxmlformats-officedocument.presentationml' in content_types:
                            missing = []
                            for req in OOXML_REQUIRED_COMPONENTS.get('PPTX', []):
                                if req not in file_list:
                                    missing.append(req)
                            
                            evidence.append({
                                'type': 'ooxml_pptx',
                                'paths_found': [f for f in file_list if f.startswith('ppt/')],
                                'missing_components': missing,
                            })
                            
                            if not missing:
                                return 'PPTX', 'HIGH', evidence
                            else:
                                return 'PPTX', 'MEDIUM', evidence
                    
                    except Exception as e:
                        evidence.append({
                            'type': 'content_types_parse_error',
                            'error': str(e),
                        })
                
                # Not OOXML, it's a regular ZIP archive
                evidence.append({
                    'type': 'plain_zip',
                    'file_count': len(file_list),
                    'sample_files': file_list[:10],
                })
                return 'ARCHIVE_ZIP', 'HIGH', evidence
                
        except zipfile.BadZipFile as e:
            evidence.append({
                'type': 'zip_parse_error',
                'error': str(e),
            })
            return 'CORRUPTED_ZIP', 'HIGH', evidence
        except Exception as e:
            evidence.append({
                'type': 'analysis_error',
                'error': str(e),
            })
            return 'UNKNOWN', 'LOW', evidence
    
    def _analyze_ole_contents(self) -> Tuple[str, str, List[Dict]]:
        """Analyze OLE contents to determine semantic file type."""
        evidence = []
        
        if not HAS_OLEFILE:
            evidence.append({
                'type': 'library_unavailable',
                'library': 'olefile',
                'note': 'Cannot perform deep OLE analysis',
            })
            return 'OLE_COMPOUND_DOCUMENT', 'MEDIUM', evidence
        
        try:
            import io
            ole = olefile.OleFileIO(io.BytesIO(self.file_data))
            
            streams = ole.listdir()
            stream_names = ['/'.join(s) for s in streams]
            
            evidence.append({
                'type': 'ole_streams',
                'streams': stream_names[:20],  # First 20 streams
                'total_count': len(streams),
            })
            
            # Check for Word document
            if ole.exists('WordDocument'):
                evidence.append({
                    'type': 'ole_word',
                    'stream': 'WordDocument',
                    'present': True,
                })
                ole.close()
                return 'DOC', 'HIGH', evidence
            
            # Check for Excel workbook
            if ole.exists('Workbook') or ole.exists('Book'):
                stream_name = 'Workbook' if ole.exists('Workbook') else 'Book'
                evidence.append({
                    'type': 'ole_excel',
                    'stream': stream_name,
                    'present': True,
                })
                ole.close()
                return 'XLS', 'HIGH', evidence
            
            # Check for PowerPoint
            if ole.exists('PowerPoint Document'):
                evidence.append({
                    'type': 'ole_powerpoint',
                    'stream': 'PowerPoint Document',
                    'present': True,
                })
                ole.close()
                return 'PPT', 'HIGH', evidence
            
            ole.close()
            
            # Generic OLE document
            return 'OLE_COMPOUND_DOCUMENT', 'MEDIUM', evidence
            
        except Exception as e:
            evidence.append({
                'type': 'ole_parse_error',
                'error': str(e),
            })
            return 'CORRUPTED_OLE', 'HIGH', evidence
    
    def _analyze_non_container(self) -> Tuple[str, str, List[Dict]]:
        """Analyze files that are not containers."""
        evidence = []
        
        # Check for images
        if self.file_data[:3] == b'\xFF\xD8\xFF':
            evidence.append({'type': 'magic_match', 'format': 'JPEG'})
            return 'IMAGE_JPEG', 'HIGH', evidence
        
        if self.file_data[:8] == b'\x89PNG\r\n\x1a\n':
            evidence.append({'type': 'magic_match', 'format': 'PNG'})
            return 'IMAGE_PNG', 'HIGH', evidence
        
        if self.file_data[:6] in [b'GIF87a', b'GIF89a']:
            evidence.append({'type': 'magic_match', 'format': 'GIF'})
            return 'IMAGE_GIF', 'HIGH', evidence
        
        # Check for plain text
        is_text, text_confidence = self._check_if_text()
        if is_text:
            evidence.append({
                'type': 'text_analysis',
                'confidence': text_confidence,
                'sample_bytes_checked': min(self.file_size, 8192),
            })
            return 'PLAIN_TEXT', text_confidence, evidence
        
        evidence.append({
            'type': 'unrecognized_format',
            'first_bytes_hex': self.file_data[:16].hex() if self.file_data else '',
        })
        return 'UNKNOWN', 'LOW', evidence
    
    def _check_if_text(self) -> Tuple[bool, str]:
        """Check if file appears to be plain text."""
        if not self.file_data:
            return False, 'LOW'
        
        # Check first 8KB
        sample = self.file_data[:8192]
        
        # Count text-like bytes
        text_chars = 0.0  # Use float for consistent type
        binary_chars = 0
        
        # Text-like: printable ASCII, common control chars
        for byte in sample:
            if byte in range(32, 127) or byte in [9, 10, 13]:  # Printable + tab, LF, CR
                text_chars += 1.0
            elif byte in [0]:  # Null byte is binary indicator
                binary_chars += 10  # Heavily penalize null bytes
            elif byte in range(1, 32):  # Other control characters
                binary_chars += 1
            else:
                # Extended ASCII - could be text encoding
                text_chars += 0.5
        
        total = len(sample)
        if total == 0:
            return False, 'LOW'
        
        text_ratio = text_chars / total
        
        if binary_chars > 0 and b'\x00' in sample:
            return False, 'LOW'
        
        if text_ratio > 0.95:
            return True, 'HIGH'
        elif text_ratio > 0.85:
            return True, 'MEDIUM'
        elif text_ratio > 0.70:
            return True, 'LOW'
        
        return False, 'LOW'
    
    def _analyze_extensions(self) -> None:
        """Analyze extension chain and detect filename deception."""
        result = {
            'analysis_name': 'extension_chain_analysis',
            'library_or_method': 'Python pathlib/unicodedata',
            'input_byte_range': 'N/A (filename analysis)',
            'output_value': {
                'raw_filename': '',
                'normalized_filename': '',
                'extension_chain': [],
                'primary_extension': '',
                'double_extension_detected': False,
                'hidden_extension_detected': False,
                'extension_mismatch': False,
                'unicode_deception': [],
                'homoglyphs_detected': [],
            },
            'evidence': [],
            'verification_method': 'Filename parsing and Unicode analysis',
            'failure_reason': None,
        }
        
        filename = self.file_path.name
        result['output_value']['raw_filename'] = filename
        
        # Extract extension chain
        parts = filename.split('.')
        if len(parts) > 1:
            extensions = parts[1:]
            result['output_value']['extension_chain'] = extensions
            result['output_value']['primary_extension'] = extensions[-1] if extensions else ''
            
            # Detect double extension
            if len(extensions) >= 2:
                result['output_value']['double_extension_detected'] = True
                result['evidence'].append({
                    'type': 'double_extension',
                    'extensions': extensions,
                })
        
        # Check for Unicode deception characters
        unicode_deception = []
        for char in filename:
            if char in UNICODE_DECEPTION_CHARS:
                unicode_deception.append({
                    'character': repr(char),
                    'codepoint': f'U+{ord(char):04X}',
                    'description': UNICODE_DECEPTION_CHARS[char],
                })
        
        result['output_value']['unicode_deception'] = unicode_deception
        
        # Check for homoglyphs
        homoglyphs_detected = []
        for char in filename:
            if char in HOMOGLYPHS:
                homoglyphs_detected.append({
                    'character': char,
                    'codepoint': f'U+{ord(char):04X}',
                    'looks_like': HOMOGLYPHS[char],
                })
        
        result['output_value']['homoglyphs_detected'] = homoglyphs_detected
        
        # Normalize filename (remove deception characters)
        normalized = filename
        for char in UNICODE_DECEPTION_CHARS:
            normalized = normalized.replace(char, '')
        for char in HOMOGLYPHS:
            normalized = normalized.replace(char, HOMOGLYPHS[char])
        
        result['output_value']['normalized_filename'] = normalized
        
        # Check for hidden extension (RLO attack simulation)
        if '\u202E' in filename:
            result['output_value']['hidden_extension_detected'] = True
            result['evidence'].append({
                'type': 'rlo_attack_indicator',
                'description': 'Right-to-Left Override character detected',
            })
        
        # Check extension mismatch with semantic type
        semantic_type = self.analysis_results.get('semantic_file_type', {}).get(
            'output_value', {}).get('semantic_file_type', 'UNKNOWN')
        
        extension = result['output_value']['primary_extension'].lower()
        
        expected_extensions = {
            'DOCX': ['docx'],
            'XLSX': ['xlsx'],
            'PPTX': ['pptx'],
            'DOC': ['doc'],
            'XLS': ['xls'],
            'PPT': ['ppt'],
            'PDF': ['pdf'],
            'IMAGE_JPEG': ['jpg', 'jpeg'],
            'IMAGE_PNG': ['png'],
            'IMAGE_GIF': ['gif'],
            'ARCHIVE_ZIP': ['zip'],
            'ARCHIVE_TAR': ['tar'],
            'ARCHIVE_7Z': ['7z'],
            'ARCHIVE_RAR': ['rar'],
            'EXECUTABLE_PE': ['exe', 'dll', 'sys'],
            'EXECUTABLE_ELF': ['so', 'elf', 'bin', 'out'],
            'PLAIN_TEXT': ['txt', 'text', 'log', 'md', 'csv', 'json', 'xml', 'html', 'htm', 'css', 'js', 'py', 'c', 'h', 'cpp', 'java', 'sh', 'bat', 'cfg', 'conf', 'ini', 'yml', 'yaml'],
        }
        
        # Handle files without extension explicitly
        has_extension = bool(extension)
        
        if semantic_type in expected_extensions:
            valid_extensions = expected_extensions[semantic_type]
            if has_extension and extension not in valid_extensions:
                result['output_value']['extension_mismatch'] = True
                result['evidence'].append({
                    'type': 'extension_mismatch',
                    'semantic_type': semantic_type,
                    'actual_extension': extension,
                    'expected_extensions': expected_extensions[semantic_type],
                })
        
        self.analysis_results['extension_analysis'] = result
    
    def _extract_filesystem_metadata(self) -> None:
        """Extract filesystem metadata."""
        result = {
            'analysis_name': 'filesystem_metadata',
            'library_or_method': 'Python os/stat',
            'input_byte_range': 'N/A (filesystem metadata)',
            'output_value': {},
            'evidence': [],
            'verification_method': 'System stat calls',
            'failure_reason': None,
        }
        
        try:
            stat_info = os.stat(self.file_path)
            
            # Timestamps
            result['output_value']['timestamps'] = {
                'created': None,  # Not always available
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            }
            
            # Try to get creation time (platform-specific)
            try:
                if hasattr(stat_info, 'st_birthtime'):  # macOS
                    result['output_value']['timestamps']['created'] = \
                        datetime.fromtimestamp(stat_info.st_birthtime).isoformat()
                elif hasattr(stat_info, 'st_ctime'):  # Unix (metadata change) / Windows (creation)
                    result['output_value']['timestamps']['ctime'] = \
                        datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            except Exception:
                pass
            
            # Permissions
            mode = stat_info.st_mode
            result['output_value']['permissions'] = {
                'mode_octal': oct(mode),
                'is_readable': os.access(self.file_path, os.R_OK),
                'is_writable': os.access(self.file_path, os.W_OK),
                'is_executable': os.access(self.file_path, os.X_OK),
                'owner_read': bool(mode & stat.S_IRUSR),
                'owner_write': bool(mode & stat.S_IWUSR),
                'owner_execute': bool(mode & stat.S_IXUSR),
                'group_read': bool(mode & stat.S_IRGRP),
                'group_write': bool(mode & stat.S_IWGRP),
                'group_execute': bool(mode & stat.S_IXGRP),
                'other_read': bool(mode & stat.S_IROTH),
                'other_write': bool(mode & stat.S_IWOTH),
                'other_execute': bool(mode & stat.S_IXOTH),
            }
            
            # Ownership
            result['output_value']['ownership'] = {
                'uid': stat_info.st_uid,
                'gid': stat_info.st_gid,
            }
            
            # Try to resolve names
            try:
                import pwd
                import grp
                result['output_value']['ownership']['user_name'] = pwd.getpwuid(stat_info.st_uid).pw_name
                result['output_value']['ownership']['group_name'] = grp.getgrgid(stat_info.st_gid).gr_name
            except (ImportError, KeyError):
                pass
            
            # NTFS Alternate Data Streams (Windows-specific, noted for completeness)
            result['output_value']['ntfs_ads'] = {
                'note': 'NTFS ADS detection requires Windows-specific APIs',
                'detected': False,
            }
            
            result['evidence'].append({
                'type': 'stat_info',
                'st_mode': mode,
                'st_uid': stat_info.st_uid,
                'st_gid': stat_info.st_gid,
            })
            
        except Exception as e:
            result['failure_reason'] = str(e)
        
        self.analysis_results['filesystem_metadata'] = result
    
    def _perform_advanced_checks(self) -> None:
        """Perform advanced checks for deception and anomalies."""
        result = {
            'analysis_name': 'advanced_checks',
            'library_or_method': 'Combined analysis',
            'input_byte_range': f'0-{self.file_size}',
            'output_value': {
                'checks_performed': [],
                'issues_found': [],
            },
            'evidence': [],
            'verification_method': 'Multi-method verification',
            'failure_reason': None,
        }
        
        issues = []
        checks = []
        
        # Check 1: Correct extension but wrong magic
        checks.append('extension_magic_mismatch')
        ext_analysis = self.analysis_results.get('extension_analysis', {}).get('output_value', {})
        semantic = self.analysis_results.get('semantic_file_type', {}).get('output_value', {})
        
        if ext_analysis.get('extension_mismatch'):
            issues.append({
                'check': 'extension_magic_mismatch',
                'severity': 'HIGH',
                'description': 'File extension does not match detected file type',
                'extension': ext_analysis.get('primary_extension'),
                'detected_type': semantic.get('semantic_file_type'),
            })
        
        # Check 2: OOXML containers missing required components
        checks.append('ooxml_completeness')
        semantic_type = semantic.get('semantic_file_type', '')
        if semantic_type in ['DOCX', 'XLSX', 'PPTX']:
            evidence = semantic.get('classification_evidence', [])
            for ev in evidence:
                if ev.get('type', '').startswith('ooxml_') and ev.get('missing_components'):
                    issues.append({
                        'check': 'ooxml_missing_components',
                        'severity': 'MEDIUM',
                        'description': 'OOXML document missing required components',
                        'missing': ev.get('missing_components'),
                    })
        
        # Check 3: Extra undocumented components in OOXML
        checks.append('ooxml_extra_components')
        if semantic_type in ['DOCX', 'XLSX', 'PPTX']:
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(self.file_data), 'r') as zf:
                    file_list = zf.namelist()
                    
                    # Known standard prefixes
                    standard_prefixes = ['word/', 'xl/', 'ppt/', '_rels/', 'docProps/', 
                                        '[Content_Types].xml', 'customXml/']
                    
                    extra_files = []
                    for f in file_list:
                        if not any(f.startswith(p) or f == p for p in standard_prefixes):
                            extra_files.append(f)
                    
                    if extra_files:
                        issues.append({
                            'check': 'ooxml_extra_components',
                            'severity': 'LOW',
                            'description': 'OOXML document contains undocumented components',
                            'extra_files': extra_files[:10],
                        })
            except Exception:
                pass
        
        # Check 4: Trailing data beyond logical EOF
        checks.append('trailing_data')
        container = self.analysis_results.get('container_identification', {}).get('output_value', {})
        
        if container.get('container_type') == 'ZIP':
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(self.file_data), 'r') as zf:
                    # Find the end of central directory
                    # ZIP files end with EOCD signature
                    eocd_pos = self.file_data.rfind(b'PK\x05\x06')
                    if eocd_pos != -1:
                        # EOCD is 22 bytes minimum, but can have variable comment
                        eocd_comment_len = struct.unpack('<H', self.file_data[eocd_pos + 20:eocd_pos + 22])[0]
                        expected_end = eocd_pos + 22 + eocd_comment_len
                        
                        if self.file_size > expected_end:
                            trailing_size = self.file_size - expected_end
                            issues.append({
                                'check': 'trailing_data',
                                'severity': 'MEDIUM',
                                'description': 'File contains data after logical end of ZIP',
                                'trailing_bytes': trailing_size,
                                'trailing_sample_hex': self.file_data[expected_end:expected_end + 32].hex(),
                            })
            except Exception:
                pass
        
        # Check 5: Multiple valid format signatures (polyglot)
        checks.append('polyglot_detection')
        magic_result = self.analysis_results.get('magic_detection', {}).get('output_value', {})
        signatures = magic_result.get('signatures_found', [])
        polyglot = magic_result.get('polyglot_indicators', [])
        
        if len(signatures) > 1 or polyglot:
            issues.append({
                'check': 'polyglot_detection',
                'severity': 'HIGH',
                'description': 'File contains multiple valid format signatures',
                'signatures': [s.get('signature_type') for s in signatures],
                'indicators': polyglot,
            })
        
        # Check 6: Correct magic but broken internal invariants
        checks.append('internal_structure_validation')
        if semantic.get('classification_confidence') in ['LOW', 'MEDIUM']:
            issues.append({
                'check': 'internal_structure_validation',
                'severity': 'MEDIUM',
                'description': 'File structure could not be fully validated',
                'confidence': semantic.get('classification_confidence'),
            })
        
        result['output_value']['checks_performed'] = checks
        result['output_value']['issues_found'] = issues
        result['evidence'] = issues
        
        self.analysis_results['advanced_checks'] = result
    
    def _generate_summary(self) -> None:
        """Generate analysis summary."""
        semantic = self.analysis_results.get('semantic_file_type', {}).get('output_value', {})
        ext_analysis = self.analysis_results.get('extension_analysis', {}).get('output_value', {})
        advanced = self.analysis_results.get('advanced_checks', {}).get('output_value', {})
        
        # Compile deception flags
        deception_flags = []
        
        if ext_analysis.get('extension_mismatch'):
            deception_flags.append('EXTENSION_MISMATCH')
        
        if ext_analysis.get('double_extension_detected'):
            deception_flags.append('DOUBLE_EXTENSION')
        
        if ext_analysis.get('hidden_extension_detected'):
            deception_flags.append('HIDDEN_EXTENSION')
        
        if ext_analysis.get('unicode_deception'):
            deception_flags.append('UNICODE_DECEPTION')
        
        if ext_analysis.get('homoglyphs_detected'):
            deception_flags.append('HOMOGLYPHS')
        
        issues = advanced.get('issues_found', [])
        for issue in issues:
            if issue.get('check') == 'polyglot_detection':
                deception_flags.append('POLYGLOT')
            if issue.get('check') == 'trailing_data':
                deception_flags.append('TRAILING_DATA')
        
        # Build classification notes
        notes = []
        container_type = semantic.get('container_type')
        semantic_type = semantic.get('semantic_file_type')
        
        if container_type and semantic_type and container_type != semantic_type:
            notes.append(f'Base container is {container_type}, resolved to {semantic_type}')
        
        if semantic.get('classification_confidence') != 'HIGH':
            notes.append(f'Classification confidence: {semantic.get("classification_confidence")}')
        
        if deception_flags:
            notes.append(f'Deception indicators found: {", ".join(deception_flags)}')
        
        # Mark as ambiguous if evidence conflicts
        is_ambiguous = False
        magic_detection = self.analysis_results.get('magic_detection', {})
        magic_output = magic_detection.get('output_value', {})
        signatures_found = magic_output.get('signatures_found', [])
        unique_signature_types = set(s.get('signature_type') for s in signatures_found)
        
        if len(unique_signature_types) > 1:
            is_ambiguous = True
            notes.append('AMBIGUOUS: Multiple conflicting signatures detected')
        
        self.analysis_results['summary'] = {
            'container_type': container_type,
            'semantic_file_type': semantic_type,
            'classification_confidence': 'AMBIGUOUS' if is_ambiguous else semantic.get('classification_confidence'),
            'classification_notes': notes,
            'detected_deception_flags': deception_flags,
            'file_path': str(self.file_path),
            'file_size': self.file_size,
            'analysis_complete': True,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export analysis results as JSON string."""
        return json.dumps(self.analysis_results, indent=indent, default=str)


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to analyze a file and return results.
    
    Args:
        file_path: Path to the file to analyze.
    
    Returns:
        Dict containing analysis results.
    """
    analyzer = FileAnalyzer(file_path)
    return analyzer.analyze()


def main():
    """Main entry point for command-line usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_path>")
        print()
        print("I understand PART 1 constraints and am ready to receive a real file path")
        print("to perform forensic-sound file ingestion and exact semantic file-type")
        print("resolution using real libraries and real file data only.")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        analyzer = FileAnalyzer(file_path)
        results = analyzer.analyze()
        print(analyzer.to_json())
    except Exception as e:
        error_result = {
            'error': {
                'type': type(e).__name__,
                'message': str(e),
            }
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == '__main__':
    main()
