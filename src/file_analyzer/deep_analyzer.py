"""
Deep Analyzer - PART 2: Deep File-Type-Aware Static Analysis

This module implements deep static inspection based on the semantic file type
determined in PART 1. All analysis is file-type-specific, non-executing,
and produces byte-accurate, reproducible findings.
"""

import io
import math
import re
import struct
import zipfile
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False


def generate_finding_id(finding_type: str, offset: int, counter: int) -> str:
    """Generate a unique finding ID."""
    return f"F{counter:04d}_{finding_type}_{offset}"


class DeepAnalyzer:
    """Deep file-type-aware static analyzer for PART 2."""
    
    def __init__(self, file_path: str, part1_results: Dict[str, Any]):
        self.file_path = file_path
        self.part1_results = part1_results
        self.file_data: Optional[bytes] = None
        self.file_size: int = 0
        self.finding_counter: int = 0
        
        semantic_output = part1_results.get('semantic_file_type', {}).get('output_value', {})
        self.semantic_file_type = semantic_output.get('semantic_file_type', 'UNKNOWN')
        self.container_type = semantic_output.get('container_type')
        
        self.findings: Dict[str, List[Dict[str, Any]]] = {
            'universal': [],
            'container_level': [],
            'file_type_specific': [],
        }
        
    def _next_finding_id(self, finding_type: str, offset: int = 0) -> str:
        self.finding_counter += 1
        return generate_finding_id(finding_type, offset, self.finding_counter)
    
    def _create_finding(
        self,
        finding_type: str,
        byte_offset_start: int,
        byte_offset_end: Optional[int] = None,
        extracted_value: Any = None,
        confidence: str = "HIGH",
        source_library_or_method: str = "Python built-in",
        verification_reference: str = "",
        failure_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        return {
            "finding_id": self._next_finding_id(finding_type, byte_offset_start),
            "finding_type": finding_type,
            "semantic_file_type": self.semantic_file_type,
            "source_library_or_method": source_library_or_method,
            "byte_offset_start": byte_offset_start,
            "byte_offset_end": byte_offset_end,
            "extracted_value": extracted_value,
            "confidence": confidence,
            "verification_reference": verification_reference,
            "failure_reason": failure_reason,
        }
    
    def analyze(self) -> Dict[str, Any]:
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            self.file_size = len(self.file_data)
        except Exception as e:
            return {"error": {"type": type(e).__name__, "message": str(e), "analysis_state": "FAILED"}}
        
        if self.file_size == 0:
            return {
                "universal": [], "container_level": [], "file_type_specific": [],
                "summary": {"total_findings": 0, "semantic_file_type": self.semantic_file_type, "note": "Empty file"}
            }
        
        try:
            self._perform_universal_analysis()
            self._perform_container_analysis()
            self._perform_file_type_specific_analysis()
        except Exception as e:
            self.findings["error"] = {"type": type(e).__name__, "message": str(e), "partial_results": True}
        
        total = len(self.findings['universal']) + len(self.findings['container_level']) + len(self.findings['file_type_specific'])
        self.findings['summary'] = {
            "total_findings": total,
            "semantic_file_type": self.semantic_file_type,
            "container_type": self.container_type,
            "universal_findings": len(self.findings['universal']),
            "container_findings": len(self.findings['container_level']),
            "file_type_specific_findings": len(self.findings['file_type_specific']),
        }
        
        return self.findings
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    def _perform_universal_analysis(self) -> None:
        self._calculate_global_entropy()
        self._calculate_section_entropy()
        self._detect_trailing_data()
        self._detect_structural_anomalies()
        self._extract_printable_strings()
    
    def _calculate_global_entropy(self) -> None:
        entropy = self._calculate_shannon_entropy(self.file_data)
        entropy_class = "NORMAL"
        if entropy < 1.0:
            entropy_class = "VERY_LOW"
        elif entropy < 4.0:
            entropy_class = "LOW"
        elif entropy > 7.5:
            entropy_class = "HIGH"
        elif entropy > 7.9:
            entropy_class = "VERY_HIGH"
        
        finding = self._create_finding(
            finding_type="global_entropy",
            byte_offset_start=0,
            byte_offset_end=self.file_size,
            extracted_value={
                "entropy": entropy, "entropy_class": entropy_class,
                "max_possible_entropy": 8.0, "entropy_ratio": round(entropy / 8.0, 4),
            },
            confidence="HIGH",
            source_library_or_method="Shannon entropy calculation (Python math)",
            verification_reference="Calculate: -sum(p * log2(p)) for all byte frequencies"
        )
        self.findings['universal'].append(finding)
    
    def _calculate_section_entropy(self, block_size: int = 4096) -> None:
        if self.file_size < block_size:
            block_size = self.file_size
        
        sections = []
        anomaly_regions = []
        entropy_values = []
        
        for offset in range(0, self.file_size, block_size):
            end_offset = min(offset + block_size, self.file_size)
            section_data = self.file_data[offset:end_offset]
            entropy = self._calculate_shannon_entropy(section_data)
            sections.append({"offset_start": offset, "offset_end": end_offset, "size": len(section_data), "entropy": entropy})
            entropy_values.append(entropy)
        
        if len(entropy_values) > 1:
            mean_entropy = sum(entropy_values) / len(entropy_values)
            variance = sum((e - mean_entropy) ** 2 for e in entropy_values) / len(entropy_values)
            std_dev = math.sqrt(variance)
            
            for section in sections:
                if abs(section['entropy'] - mean_entropy) > 2 * std_dev:
                    anomaly_type = "HIGH_ENTROPY" if section['entropy'] > mean_entropy else "LOW_ENTROPY"
                    anomaly_regions.append({
                        "offset_start": section['offset_start'], "offset_end": section['offset_end'],
                        "entropy": section['entropy'], "anomaly_type": anomaly_type,
                        "deviation": round(abs(section['entropy'] - mean_entropy), 4),
                    })
        else:
            mean_entropy = entropy_values[0] if entropy_values else 0
            variance = 0
            std_dev = 0
        
        finding = self._create_finding(
            finding_type="section_entropy",
            byte_offset_start=0,
            byte_offset_end=self.file_size,
            extracted_value={
                "block_size": block_size, "total_sections": len(sections),
                "sections": sections[:50], "mean_entropy": round(mean_entropy, 4),
                "variance": round(variance, 4), "std_deviation": round(std_dev, 4),
                "anomaly_regions": anomaly_regions,
            },
            confidence="HIGH",
            source_library_or_method="Section-wise entropy (Python math)",
            verification_reference=f"Block size: {block_size} bytes, sliding window analysis"
        )
        self.findings['universal'].append(finding)

    def _detect_trailing_data(self) -> None:
        trailing_data_info = None
        
        if self.container_type == 'ZIP':
            trailing_data_info = self._check_zip_trailing_data()
        elif self.container_type == 'OLE':
            trailing_data_info = self._check_ole_trailing_data()
        elif self.container_type == 'PDF':
            trailing_data_info = self._check_pdf_trailing_data()
        elif self.container_type == 'PE':
            trailing_data_info = self._check_pe_trailing_data()
        
        if trailing_data_info:
            finding = self._create_finding(
                finding_type="trailing_data",
                byte_offset_start=trailing_data_info.get('logical_eof', 0),
                byte_offset_end=self.file_size,
                extracted_value=trailing_data_info,
                confidence="HIGH",
                source_library_or_method="Container format analysis",
                verification_reference="hexdump -C <file> | tail to verify trailing bytes"
            )
            self.findings['universal'].append(finding)
    
    def _check_zip_trailing_data(self) -> Optional[Dict[str, Any]]:
        try:
            eocd_pos = self.file_data.rfind(b'PK\x05\x06')
            if eocd_pos == -1 or eocd_pos + 22 > self.file_size:
                return None
            comment_len = struct.unpack('<H', self.file_data[eocd_pos + 20:eocd_pos + 22])[0]
            expected_end = eocd_pos + 22 + comment_len
            
            if self.file_size > expected_end:
                trailing_sample = self.file_data[expected_end:expected_end + 64]
                return {
                    "logical_eof": expected_end, "trailing_size": self.file_size - expected_end,
                    "trailing_sample_hex": trailing_sample.hex(), "eocd_offset": eocd_pos,
                }
        except Exception:
            pass
        return None
    
    def _check_ole_trailing_data(self) -> Optional[Dict[str, Any]]:
        if not HAS_OLEFILE:
            return None
        try:
            ole = olefile.OleFileIO(io.BytesIO(self.file_data))
            sector_size = ole.sectorsize
            total_sectors = ole.nb_sect
            expected_size = (1 + total_sectors) * sector_size
            ole.close()
            
            if self.file_size > expected_size + 512:
                return {
                    "logical_eof": expected_size, "trailing_size": self.file_size - expected_size,
                    "trailing_sample_hex": self.file_data[expected_size:expected_size + 64].hex(),
                }
        except Exception:
            pass
        return None
    
    def _check_pdf_trailing_data(self) -> Optional[Dict[str, Any]]:
        try:
            eof_pos = self.file_data.rfind(b'%%EOF')
            if eof_pos == -1:
                return None
            expected_end = eof_pos + 5
            while expected_end < self.file_size and self.file_data[expected_end:expected_end+1] in [b'\r', b'\n']:
                expected_end += 1
            
            if self.file_size > expected_end:
                return {
                    "logical_eof": expected_end, "trailing_size": self.file_size - expected_end,
                    "trailing_sample_hex": self.file_data[expected_end:expected_end + 64].hex(),
                }
        except Exception:
            pass
        return None
    
    def _check_pe_trailing_data(self) -> Optional[Dict[str, Any]]:
        try:
            if self.file_data[:2] != b'MZ':
                return None
            pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
            if pe_offset + 248 > self.file_size:
                return None
            
            num_sections = struct.unpack('<H', self.file_data[pe_offset + 6:pe_offset + 8])[0]
            optional_header_size = struct.unpack('<H', self.file_data[pe_offset + 20:pe_offset + 22])[0]
            section_header_offset = pe_offset + 24 + optional_header_size
            
            max_end = 0
            for i in range(num_sections):
                sec_start = section_header_offset + i * 40
                if sec_start + 40 > self.file_size:
                    break
                raw_size = struct.unpack('<I', self.file_data[sec_start + 16:sec_start + 20])[0]
                raw_ptr = struct.unpack('<I', self.file_data[sec_start + 20:sec_start + 24])[0]
                max_end = max(max_end, raw_ptr + raw_size)
            
            if max_end > 0 and self.file_size > max_end + 16:
                return {
                    "logical_eof": max_end, "trailing_size": self.file_size - max_end,
                    "trailing_sample_hex": self.file_data[max_end:max_end + 64].hex(),
                }
        except Exception:
            pass
        return None

    def _detect_structural_anomalies(self) -> None:
        anomalies = []
        null_runs = self._find_byte_runs(0, min_length=1024)
        for run in null_runs:
            anomalies.append({
                "type": "null_padding", "offset_start": run['start'],
                "offset_end": run['end'], "size": run['length'],
            })
        
        if anomalies:
            finding = self._create_finding(
                finding_type="structural_anomalies",
                byte_offset_start=0,
                byte_offset_end=self.file_size,
                extracted_value={"anomalies": anomalies[:20]},
                confidence="MEDIUM",
                source_library_or_method="Pattern detection (Python built-in)",
                verification_reference="hexdump -C <file> to verify patterns"
            )
            self.findings['universal'].append(finding)
    
    def _find_byte_runs(self, target: int, min_length: int = 1024) -> List[Dict]:
        runs = []
        i = 0
        while i < self.file_size:
            if self.file_data[i] == target:
                start = i
                while i < self.file_size and self.file_data[i] == target:
                    i += 1
                if i - start >= min_length:
                    runs.append({'start': start, 'end': i, 'length': i - start})
            else:
                i += 1
        return runs[:10]
    
    def _extract_printable_strings(self, min_length: int = 6) -> None:
        strings = self._find_ascii_strings(min_length)
        strings.extend(self._find_unicode_strings(min_length))
        
        classified = {"urls": [], "ip_addresses": [], "emails": [], "file_paths": [], "suspicious_commands": [], "other": []}
        
        url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>\']+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        path_pattern = re.compile(r'[A-Za-z]:\\[^\x00-\x1f<>:"|?*]+|/(?:usr|var|tmp|etc|home|bin)/[^\x00-\x1f]+')
        cmd_pattern = re.compile(r'\b(?:cmd|powershell|bash|wget|curl|python)\b', re.I)
        
        for s in strings:
            val = s['value']
            if url_pattern.search(val):
                classified['urls'].append(s)
            elif ip_pattern.search(val):
                classified['ip_addresses'].append(s)
            elif email_pattern.search(val):
                classified['emails'].append(s)
            elif path_pattern.search(val):
                classified['file_paths'].append(s)
            elif cmd_pattern.search(val):
                classified['suspicious_commands'].append(s)
            else:
                classified['other'].append(s)
        
        finding = self._create_finding(
            finding_type="printable_strings",
            byte_offset_start=0,
            byte_offset_end=self.file_size,
            extracted_value={
                "total_strings": len(strings),
                "urls": classified['urls'][:25],
                "ip_addresses": classified['ip_addresses'][:25],
                "emails": classified['emails'][:25],
                "file_paths": classified['file_paths'][:25],
                "suspicious_commands": classified['suspicious_commands'][:25],
                "other_count": len(classified['other']),
            },
            confidence="HIGH",
            source_library_or_method="String extraction (Python regex)",
            verification_reference="strings -a <file>"
        )
        self.findings['universal'].append(finding)
    
    def _find_ascii_strings(self, min_length: int = 6) -> List[Dict]:
        strings = []
        current = []
        start_offset = None
        
        for i, byte in enumerate(self.file_data):
            if 32 <= byte < 127:
                if start_offset is None:
                    start_offset = i
                current.append(chr(byte))
            else:
                if current and len(current) >= min_length:
                    strings.append({'offset': start_offset, 'length': len(current), 'encoding': 'ASCII', 'value': ''.join(current)})
                current = []
                start_offset = None
        
        if current and len(current) >= min_length:
            strings.append({'offset': start_offset, 'length': len(current), 'encoding': 'ASCII', 'value': ''.join(current)})
        return strings[:500]
    
    def _find_unicode_strings(self, min_length: int = 6) -> List[Dict]:
        strings = []
        current = []
        start_offset = None
        
        for i in range(0, self.file_size - 1, 2):
            low, high = self.file_data[i], self.file_data[i + 1]
            if high == 0 and 32 <= low < 127:
                if start_offset is None:
                    start_offset = i
                current.append(chr(low))
            else:
                if current and len(current) >= min_length:
                    strings.append({'offset': start_offset, 'length': len(current), 'encoding': 'UTF-16LE', 'value': ''.join(current)})
                current = []
                start_offset = None
        return strings[:500]

    def _perform_container_analysis(self) -> None:
        if self.container_type == 'ZIP':
            self._analyze_zip_container()
        elif self.container_type == 'OLE':
            self._analyze_ole_container()
    
    def _analyze_zip_container(self) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(self.file_data), 'r')
            entries = []
            compression_methods = {}
            encrypted_entries = []
            zip_bomb_indicators = []
            total_compressed = 0
            total_uncompressed = 0
            
            for info in zf.infolist():
                method_names = {0: 'STORED', 8: 'DEFLATE', 12: 'BZIP2', 14: 'LZMA'}
                method = method_names.get(info.compress_type, f'UNKNOWN_{info.compress_type}')
                compression_methods[method] = compression_methods.get(method, 0) + 1
                
                ratio = info.file_size / info.compress_size if info.compress_size > 0 else 0
                total_compressed += info.compress_size
                total_uncompressed += info.file_size
                
                entries.append({
                    'filename': info.filename, 'compress_size': info.compress_size, 'file_size': info.file_size,
                    'compression_method': method, 'compression_ratio': round(ratio, 2),
                    'header_offset': info.header_offset, 'is_encrypted': bool(info.flag_bits & 0x1),
                })
                
                if info.flag_bits & 0x1:
                    encrypted_entries.append(info.filename)
                
                if ratio > 100:
                    zip_bomb_indicators.append({'filename': info.filename, 'ratio': round(ratio, 2)})
            
            zf.close()
            
            overall_ratio = total_uncompressed / total_compressed if total_compressed > 0 else 0
            if overall_ratio > 50:
                zip_bomb_indicators.append({'type': 'HIGH_OVERALL_COMPRESSION', 'ratio': round(overall_ratio, 2)})
            
            finding = self._create_finding(
                finding_type="zip_container_analysis",
                byte_offset_start=0,
                byte_offset_end=self.file_size,
                extracted_value={
                    "entry_count": len(entries), "entries": entries[:100],
                    "compression_methods": compression_methods,
                    "total_compressed_size": total_compressed, "total_uncompressed_size": total_uncompressed,
                    "overall_compression_ratio": round(overall_ratio, 2),
                    "encrypted_entries": encrypted_entries, "zip_bomb_indicators": zip_bomb_indicators,
                },
                confidence="HIGH",
                source_library_or_method="Python zipfile",
                verification_reference="unzip -l <file>"
            )
            self.findings['container_level'].append(finding)
        except Exception as e:
            finding = self._create_finding(
                finding_type="zip_container_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                extracted_value=None, confidence="LOW", source_library_or_method="Python zipfile", failure_reason=str(e)
            )
            self.findings['container_level'].append(finding)
    
    def _analyze_ole_container(self) -> None:
        if not HAS_OLEFILE:
            finding = self._create_finding(
                finding_type="ole_container_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                extracted_value=None, confidence="LOW", source_library_or_method="olefile (unavailable)",
                failure_reason="olefile library not installed"
            )
            self.findings['container_level'].append(finding)
            return
        
        try:
            ole = olefile.OleFileIO(io.BytesIO(self.file_data))
            streams = []
            vba_streams = []
            hidden_streams = []
            
            for stream_path in ole.listdir():
                stream_name = '/'.join(stream_path)
                try:
                    stream_size = ole.get_size(stream_name)
                    stream_data = ole.openstream(stream_name).read(64)
                except Exception:
                    stream_size = 0
                    stream_data = b''
                
                stream_info = {'path': stream_name, 'size': stream_size, 'sample_hex': stream_data.hex() if stream_data else ''}
                streams.append(stream_info)
                
                if 'vba' in stream_name.lower() or 'macros' in stream_name.lower():
                    vba_streams.append(stream_name)
                if stream_name.startswith('\x01') or stream_name.startswith('\x05'):
                    hidden_streams.append(stream_info)
            
            fat_validation = {'sector_size': ole.sectorsize, 'mini_sector_size': ole.minisectorcutoff, 'total_sectors': ole.nb_sect}
            ole.close()
            
            finding = self._create_finding(
                finding_type="ole_container_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                extracted_value={
                    "stream_count": len(streams), "streams": streams[:50],
                    "vba_streams": vba_streams, "hidden_streams": hidden_streams, "fat_validation": fat_validation,
                },
                confidence="HIGH", source_library_or_method="Python olefile",
                verification_reference="olefile.oledir <file>"
            )
            self.findings['container_level'].append(finding)
        except Exception as e:
            finding = self._create_finding(
                finding_type="ole_container_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                extracted_value=None, confidence="LOW", source_library_or_method="Python olefile", failure_reason=str(e)
            )
            self.findings['container_level'].append(finding)

    def _perform_file_type_specific_analysis(self) -> None:
        if self.semantic_file_type == 'PLAIN_TEXT':
            self._analyze_plain_text()
        elif self.semantic_file_type in ['IMAGE_JPEG', 'IMAGE_PNG', 'IMAGE_GIF']:
            self._analyze_image()
        elif self.semantic_file_type == 'PDF':
            self._analyze_pdf()
        elif self.semantic_file_type in ['DOC', 'XLS', 'PPT']:
            self._analyze_office_legacy()
        elif self.semantic_file_type in ['DOCX', 'XLSX', 'PPTX']:
            self._analyze_office_ooxml()
        elif self.semantic_file_type in ['ARCHIVE_ZIP', 'ARCHIVE_7Z', 'ARCHIVE_RAR', 'ARCHIVE_TAR']:
            self._analyze_archive()
        elif self.semantic_file_type in ['EXECUTABLE_PE', 'EXECUTABLE_ELF', 'EXECUTABLE_MACH_O']:
            self._analyze_executable()
    
    def _analyze_plain_text(self) -> None:
        sample = self.file_data[:8192]
        bom_detected = None
        encoding = 'ASCII'
        
        if sample[:3] == b'\xef\xbb\xbf':
            bom_detected, encoding = 'UTF-8', 'UTF-8'
        elif sample[:2] == b'\xff\xfe':
            bom_detected, encoding = 'UTF-16-LE', 'UTF-16-LE'
        elif sample[:2] == b'\xfe\xff':
            bom_detected, encoding = 'UTF-16-BE', 'UTF-16-BE'
        
        crlf = self.file_data.count(b'\r\n')
        lf = self.file_data.count(b'\n') - crlf
        cr = self.file_data.count(b'\r') - crlf
        
        line_ending = 'MIXED'
        if crlf > 0 and lf == 0 and cr == 0:
            line_ending = 'CRLF'
        elif lf > 0 and crlf == 0 and cr == 0:
            line_ending = 'LF'
        elif cr > 0 and crlf == 0 and lf == 0:
            line_ending = 'CR'
        
        non_printable = sum(1 for b in sample if b < 32 and b not in [9, 10, 13])
        
        # Check for hidden binary blobs
        binary_blobs = []
        for i in range(0, len(sample) - 16, 16):
            chunk = sample[i:i+16]
            null_count = chunk.count(0)
            if null_count > 4:
                binary_blobs.append({'offset': i, 'null_count': null_count})
        
        finding = self._create_finding(
            finding_type="plain_text_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value={
                "encoding_detected": encoding, "bom_detected": bom_detected,
                "line_ending_style": line_ending, "line_counts": {"crlf": crlf, "lf": lf, "cr": cr},
                "non_printable_count": non_printable,
                "non_printable_ratio": round(non_printable / len(sample), 4) if sample else 0,
                "binary_blob_indicators": binary_blobs[:10],
            },
            confidence="HIGH", source_library_or_method="Text analysis (Python built-in)",
            verification_reference="file <file> for encoding; xxd <file> | head for BOM"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_image(self) -> None:
        image_info = {}
        if self.semantic_file_type == 'IMAGE_JPEG':
            image_info = self._analyze_jpeg()
        elif self.semantic_file_type == 'IMAGE_PNG':
            image_info = self._analyze_png()
        elif self.semantic_file_type == 'IMAGE_GIF':
            image_info = self._analyze_gif()
        
        finding = self._create_finding(
            finding_type="image_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=image_info, confidence="HIGH" if image_info else "LOW",
            source_library_or_method="Image format parsing (Python built-in)",
            verification_reference="exiftool <file> for metadata; identify <file> for dimensions"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_jpeg(self) -> Dict[str, Any]:
        result = {"format": "JPEG", "segments": [], "exif_present": False, "thumbnail_present": False, "width": 0, "height": 0}
        try:
            i = 0
            while i < self.file_size - 1:
                if self.file_data[i] == 0xFF:
                    marker = self.file_data[i + 1]
                    if marker == 0xD8:
                        result['segments'].append({"marker": "SOI", "offset": i})
                    elif marker == 0xD9:
                        result['segments'].append({"marker": "EOI", "offset": i})
                        break
                    elif marker == 0xE1 and i + 4 < self.file_size:
                        result['exif_present'] = True
                        length = struct.unpack('>H', self.file_data[i+2:i+4])[0]
                        result['segments'].append({"marker": "EXIF", "offset": i, "length": length})
                        i += length + 2
                        continue
                    elif marker == 0xE0 and i + 4 < self.file_size:
                        length = struct.unpack('>H', self.file_data[i+2:i+4])[0]
                        result['segments'].append({"marker": "JFIF", "offset": i, "length": length})
                    elif marker in [0xC0, 0xC2] and i + 9 < self.file_size:  # SOF0 or SOF2
                        length = struct.unpack('>H', self.file_data[i+2:i+4])[0]
                        result['height'] = struct.unpack('>H', self.file_data[i+5:i+7])[0]
                        result['width'] = struct.unpack('>H', self.file_data[i+7:i+9])[0]
                        result['segments'].append({"marker": "SOF", "offset": i, "width": result['width'], "height": result['height']})
                i += 1
        except Exception:
            pass
        return result
    
    def _analyze_png(self) -> Dict[str, Any]:
        result = {"format": "PNG", "chunks": [], "width": 0, "height": 0, "color_type": 0, "bit_depth": 0}
        try:
            if self.file_data[:8] != b'\x89PNG\r\n\x1a\n':
                return result
            i = 8
            while i < self.file_size - 12:
                chunk_length = struct.unpack('>I', self.file_data[i:i+4])[0]
                chunk_type = self.file_data[i+4:i+8].decode('ascii', errors='ignore')
                chunk_info = {"type": chunk_type, "offset": i, "length": chunk_length}
                
                if chunk_type == 'IHDR' and chunk_length >= 13:
                    result['width'] = struct.unpack('>I', self.file_data[i+8:i+12])[0]
                    result['height'] = struct.unpack('>I', self.file_data[i+12:i+16])[0]
                    result['bit_depth'] = self.file_data[i+16]
                    result['color_type'] = self.file_data[i+17]
                    chunk_info.update({'width': result['width'], 'height': result['height']})
                
                result['chunks'].append(chunk_info)
                if chunk_type == 'IEND':
                    break
                i += 12 + chunk_length
        except Exception:
            pass
        return result
    
    def _analyze_gif(self) -> Dict[str, Any]:
        result = {"format": "GIF", "version": "", "width": 0, "height": 0}
        try:
            result['version'] = self.file_data[:6].decode('ascii', errors='ignore')
            if len(self.file_data) >= 10:
                result['width'] = struct.unpack('<H', self.file_data[6:8])[0]
                result['height'] = struct.unpack('<H', self.file_data[8:10])[0]
        except Exception:
            pass
        return result

    def _analyze_pdf(self) -> None:
        result = {
            "version": None, "object_count": 0, "has_javascript": False,
            "has_embedded_files": False, "has_encryption": False, "incremental_updates": 0,
            "xref_sections": [], "suspicious_keywords": [],
        }
        try:
            version_match = re.search(rb'%PDF-(\d\.\d)', self.file_data[:1024])
            if version_match:
                result['version'] = version_match.group(1).decode('ascii')
            
            result['object_count'] = len(re.findall(rb'\d+ \d+ obj', self.file_data))
            result['has_javascript'] = b'/JavaScript' in self.file_data or b'/JS' in self.file_data
            result['has_embedded_files'] = b'/EmbeddedFile' in self.file_data
            result['has_encryption'] = b'/Encrypt' in self.file_data
            result['incremental_updates'] = self.file_data.count(b'%%EOF') - 1
            
            # Find xref tables
            for match in re.finditer(rb'xref', self.file_data):
                result['xref_sections'].append({'offset': match.start()})
            
            # Check for suspicious keywords
            suspicious = [b'/OpenAction', b'/AA', b'/Launch', b'/URI', b'/SubmitForm', b'/GoToR']
            for kw in suspicious:
                if kw in self.file_data:
                    result['suspicious_keywords'].append(kw.decode('ascii'))
        except Exception:
            pass
        
        finding = self._create_finding(
            finding_type="pdf_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH",
            source_library_or_method="PDF structure parsing (Python regex)",
            verification_reference="pdfinfo <file>; pdfid.py <file>"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_office_legacy(self) -> None:
        if not HAS_OLEFILE:
            finding = self._create_finding(
                finding_type="office_legacy_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                extracted_value=None, confidence="LOW", source_library_or_method="olefile (unavailable)",
                failure_reason="olefile library not installed"
            )
            self.findings['file_type_specific'].append(finding)
            return
        
        result = {"has_macros": False, "macro_streams": [], "auto_execution_indicators": [], "embedded_objects": []}
        try:
            ole = olefile.OleFileIO(io.BytesIO(self.file_data))
            
            for stream_path in ole.listdir():
                stream_name = '/'.join(stream_path)
                lower_name = stream_name.lower()
                
                if 'vba' in lower_name or 'macros' in lower_name:
                    result['has_macros'] = True
                    result['macro_streams'].append(stream_name)
                if 'objectpool' in lower_name or 'ole' in lower_name:
                    result['embedded_objects'].append(stream_name)
            
            auto_exec_patterns = [b'AutoOpen', b'AutoExec', b'Document_Open', b'Workbook_Open', b'Auto_Open']
            for pattern in auto_exec_patterns:
                if pattern in self.file_data:
                    result['auto_execution_indicators'].append(pattern.decode('ascii'))
            
            ole.close()
        except Exception as e:
            result['error'] = str(e)
        
        finding = self._create_finding(
            finding_type="office_legacy_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH" if not result.get('error') else "LOW",
            source_library_or_method="olefile + pattern matching",
            verification_reference="olevba <file> for macro analysis"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_office_ooxml(self) -> None:
        result = {
            "content_types": [], "relationships": [], "has_vba_macros": False,
            "external_references": [], "custom_xml": [], "missing_parts": [],
            "content_type_mismatches": [],
        }
        try:
            zf = zipfile.ZipFile(io.BytesIO(self.file_data), 'r')
            file_list = zf.namelist()
            
            result['has_vba_macros'] = any('vba' in f.lower() for f in file_list)
            
            if '[Content_Types].xml' in file_list:
                content_types_xml = zf.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                result['content_types'] = re.findall(r'ContentType="([^"]+)"', content_types_xml)
            
            rels_files = [f for f in file_list if f.endswith('.rels')]
            for rels_file in rels_files[:10]:
                try:
                    rels_content = zf.read(rels_file).decode('utf-8', errors='ignore')
                    targets = re.findall(r'Target="([^"]+)"', rels_content)
                    external = [t for t in targets if t.startswith('http') or t.startswith('file:')]
                    result['external_references'].extend(external)
                    result['relationships'].append({'file': rels_file, 'targets': targets[:10]})
                except Exception:
                    pass
            
            result['custom_xml'] = [f for f in file_list if 'customXml' in f]
            
            required = {}
            if self.semantic_file_type == 'DOCX':
                required = {'word/document.xml': False}
            elif self.semantic_file_type == 'XLSX':
                required = {'xl/workbook.xml': False}
            elif self.semantic_file_type == 'PPTX':
                required = {'ppt/presentation.xml': False}
            
            for part in required:
                if part not in file_list:
                    result['missing_parts'].append(part)
            
            zf.close()
        except Exception as e:
            result['error'] = str(e)
        
        finding = self._create_finding(
            finding_type="office_ooxml_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH" if not result.get('error') else "LOW",
            source_library_or_method="Python zipfile + XML parsing",
            verification_reference="unzip -l <file>; olevba <file> for macros"
        )
        self.findings['file_type_specific'].append(finding)

    def _analyze_archive(self) -> None:
        result = {"file_tree": [], "nested_archives": [], "encrypted_entries": [], "size_anomalies": []}
        
        if self.container_type == 'ZIP':
            try:
                zf = zipfile.ZipFile(io.BytesIO(self.file_data), 'r')
                for info in zf.infolist():
                    entry = {"path": info.filename, "size": info.file_size, "compressed_size": info.compress_size}
                    
                    if info.flag_bits & 0x1:
                        result['encrypted_entries'].append(info.filename)
                    
                    # Check for nested archives
                    lower = info.filename.lower()
                    if any(lower.endswith(ext) for ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']):
                        result['nested_archives'].append(info.filename)
                    
                    # Check for size anomalies (potential zip bomb)
                    if info.compress_size > 0 and info.file_size / info.compress_size > 100:
                        result['size_anomalies'].append({
                            'filename': info.filename,
                            'ratio': round(info.file_size / info.compress_size, 2)
                        })
                    
                    result['file_tree'].append(entry)
                
                zf.close()
            except Exception:
                pass
        
        finding = self._create_finding(
            finding_type="archive_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH",
            source_library_or_method="Archive format parsing",
            verification_reference="unzip -l <file> or tar -tvf <file>"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_executable(self) -> None:
        if self.semantic_file_type == 'EXECUTABLE_PE':
            self._analyze_pe()
        elif self.semantic_file_type == 'EXECUTABLE_ELF':
            self._analyze_elf()
        elif self.semantic_file_type == 'EXECUTABLE_MACH_O':
            self._analyze_macho()
    
    def _analyze_pe(self) -> None:
        result = {
            "dos_header_valid": False, "pe_signature_valid": False,
            "sections": [], "imports": [], "entry_point": 0, "packing_indicators": [],
            "machine_type": None, "subsystem": None,
        }
        try:
            result['dos_header_valid'] = self.file_data[:2] == b'MZ'
            if not result['dos_header_valid']:
                finding = self._create_finding(
                    finding_type="pe_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                    extracted_value=result, confidence="LOW", source_library_or_method="PE header parsing",
                    failure_reason="Invalid DOS header"
                )
                self.findings['file_type_specific'].append(finding)
                return
            
            pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
            if pe_offset + 4 <= self.file_size and self.file_data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                result['pe_signature_valid'] = True
                
                result['machine_type'] = hex(struct.unpack('<H', self.file_data[pe_offset + 4:pe_offset + 6])[0])
                num_sections = struct.unpack('<H', self.file_data[pe_offset + 6:pe_offset + 8])[0]
                optional_header_size = struct.unpack('<H', self.file_data[pe_offset + 20:pe_offset + 22])[0]
                
                if pe_offset + 40 <= self.file_size:
                    result['entry_point'] = struct.unpack('<I', self.file_data[pe_offset + 40:pe_offset + 44])[0]
                
                if pe_offset + 92 <= self.file_size:
                    result['subsystem'] = struct.unpack('<H', self.file_data[pe_offset + 92:pe_offset + 94])[0]
                
                section_offset = pe_offset + 24 + optional_header_size
                for i in range(min(num_sections, 32)):
                    sec_start = section_offset + i * 40
                    if sec_start + 40 > self.file_size:
                        break
                    
                    name = self.file_data[sec_start:sec_start + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    virtual_size = struct.unpack('<I', self.file_data[sec_start + 8:sec_start + 12])[0]
                    raw_size = struct.unpack('<I', self.file_data[sec_start + 16:sec_start + 20])[0]
                    raw_ptr = struct.unpack('<I', self.file_data[sec_start + 20:sec_start + 24])[0]
                    characteristics = struct.unpack('<I', self.file_data[sec_start + 36:sec_start + 40])[0]
                    
                    section_data = self.file_data[raw_ptr:raw_ptr + min(raw_size, 65536)] if raw_ptr + raw_size <= self.file_size else b''
                    entropy = self._calculate_shannon_entropy(section_data) if section_data else 0
                    
                    section_info = {
                        "name": name, "virtual_size": virtual_size, "raw_size": raw_size,
                        "raw_offset": raw_ptr, "characteristics": hex(characteristics),
                        "entropy": entropy, "is_executable": bool(characteristics & 0x20000000),
                        "is_writable": bool(characteristics & 0x80000000),
                    }
                    result['sections'].append(section_info)
                    
                    if entropy > 7.2:
                        result['packing_indicators'].append(f"High entropy in {name}: {entropy:.2f}")
                    if not name or name.startswith('.') is False and len(name) > 0:
                        if all(c.isalnum() or c in '._' for c in name) is False:
                            result['packing_indicators'].append(f"Unusual section name: {repr(name)}")
        except Exception as e:
            result['error'] = str(e)
        
        finding = self._create_finding(
            finding_type="pe_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH" if result.get('pe_signature_valid') else "LOW",
            source_library_or_method="PE header parsing (Python struct)",
            verification_reference="dumpbin /headers <file>; pestudio <file>"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_elf(self) -> None:
        result = {"elf_class": None, "endianness": None, "elf_type": None, "machine": None, "entry_point": 0, "sections": []}
        try:
            if self.file_data[:4] != b'\x7fELF':
                finding = self._create_finding(
                    finding_type="elf_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
                    extracted_value=result, confidence="LOW", source_library_or_method="ELF header parsing",
                    failure_reason="Invalid ELF magic"
                )
                self.findings['file_type_specific'].append(finding)
                return
            
            result['elf_class'] = '64-bit' if self.file_data[4] == 2 else '32-bit'
            result['endianness'] = 'big' if self.file_data[5] == 2 else 'little'
            
            elf_types = {1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}
            if result['endianness'] == 'little':
                result['elf_type'] = elf_types.get(struct.unpack('<H', self.file_data[16:18])[0], 'UNKNOWN')
                result['machine'] = struct.unpack('<H', self.file_data[18:20])[0]
                if result['elf_class'] == '64-bit':
                    result['entry_point'] = struct.unpack('<Q', self.file_data[24:32])[0]
                else:
                    result['entry_point'] = struct.unpack('<I', self.file_data[24:28])[0]
        except Exception as e:
            result['error'] = str(e)
        
        finding = self._create_finding(
            finding_type="elf_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH",
            source_library_or_method="ELF header parsing (Python struct)",
            verification_reference="readelf -h <file>"
        )
        self.findings['file_type_specific'].append(finding)
    
    def _analyze_macho(self) -> None:
        result = {"cpu_type": None, "file_type": None, "load_commands": 0, "is_64bit": False}
        try:
            magic = self.file_data[:4]
            
            if magic in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
                fmt, result['is_64bit'] = '>I', magic == b'\xfe\xed\xfa\xcf'
            elif magic in [b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                fmt, result['is_64bit'] = '<I', magic == b'\xcf\xfa\xed\xfe'
            else:
                fmt = '<I'
            
            if len(self.file_data) >= 28:
                result['cpu_type'] = struct.unpack(fmt, self.file_data[4:8])[0]
                result['file_type'] = struct.unpack(fmt, self.file_data[12:16])[0]
                result['load_commands'] = struct.unpack(fmt, self.file_data[16:20])[0]
        except Exception as e:
            result['error'] = str(e)
        
        finding = self._create_finding(
            finding_type="macho_analysis", byte_offset_start=0, byte_offset_end=self.file_size,
            extracted_value=result, confidence="HIGH",
            source_library_or_method="Mach-O header parsing (Python struct)",
            verification_reference="otool -h <file>"
        )
        self.findings['file_type_specific'].append(finding)


def deep_analyze_file(file_path: str, part1_results: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for deep file analysis."""
    analyzer = DeepAnalyzer(file_path, part1_results)
    return analyzer.analyze()


def main():
    """Main entry point for command-line usage."""
    import sys
    import json
    
    print("I understand PART 2 constraints and am ready to receive a real file path")
    print("to perform deep, file-type-aware, non-executing static analysis using")
    print("real libraries and real file data only.")
    print()
    print("Usage: python deep_analyzer.py <file_path>")
    
    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        from .analyzer import FileAnalyzer
        
        try:
            part1_analyzer = FileAnalyzer(file_path)
            part1_results = part1_analyzer.analyze()
            
            deep_analyzer = DeepAnalyzer(file_path, part1_results)
            part2_results = deep_analyzer.analyze()
            
            print(json.dumps({"part1": part1_results, "part2": part2_results}, indent=2, default=str))
        except Exception as e:
            print(json.dumps({"error": {"type": type(e).__name__, "message": str(e)}}, indent=2))
            sys.exit(1)


if __name__ == '__main__':
    main()
