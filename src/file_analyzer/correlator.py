"""
Correlator - PART 3: Session-Level Correlation

This module implements session-level correlation across multiple files
within the same analysis session. It detects relationships such as:
- Identical or similar fuzzy hashes
- Shared embedded objects
- Reused macros or scripts
- Common structural patterns

All correlations reference concrete evidence IDs.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def generate_correlation_id(correlation_type: str, counter: int) -> str:
    """Generate a unique correlation ID."""
    return f"C{counter:04d}_{correlation_type}"


class FileSession:
    """Represents a single file's analysis results in a session."""
    
    def __init__(self, file_id: str, file_path: str, analysis_results: Dict[str, Any]):
        """
        Initialize file session data.
        
        Args:
            file_id: Unique identifier for this file in the session.
            file_path: Path to the file.
            analysis_results: Combined PART 1, 2, 3 results.
        """
        self.file_id = file_id
        self.file_path = file_path
        self.results = analysis_results
        
        # Extract key data for correlation
        self._extract_correlation_data()
    
    def _extract_correlation_data(self) -> None:
        """Extract data relevant for correlation."""
        # Fuzzy hashes
        self.fuzzy_hashes = {}
        rule_engine = self.results.get("rule_engine", {})
        fuzzy = rule_engine.get("fuzzy_hashes", {})
        if "ssdeep" in fuzzy:
            self.fuzzy_hashes["ssdeep"] = fuzzy["ssdeep"].get("value", "")
        if "tlsh" in fuzzy:
            self.fuzzy_hashes["tlsh"] = fuzzy["tlsh"].get("value", "")
        
        # Cryptographic hashes
        self.crypto_hashes = {}
        part1 = self.results.get("part1", {})
        crypto = part1.get("cryptographic_identity", {})
        for h in crypto.get("hashes", []):
            algo = h.get("evidence", {}).get("algorithm", "").lower()
            if algo:
                self.crypto_hashes[algo] = h.get("output_value", "")
        
        # Semantic type
        semantic = part1.get("semantic_file_type", {}).get("output_value", {})
        self.semantic_type = semantic.get("semantic_file_type", "UNKNOWN")
        
        # Embedded URLs
        self.urls: Set[str] = set()
        part2 = self.results.get("part2", {})
        for finding in part2.get("universal", []):
            if finding.get("finding_type") == "printable_strings":
                urls = finding.get("extracted_value", {}).get("urls", [])
                for url in urls:
                    if isinstance(url, dict):
                        self.urls.add(url.get("value", ""))
                    else:
                        self.urls.add(str(url))
        
        # Embedded IP addresses
        self.ip_addresses: Set[str] = set()
        for finding in part2.get("universal", []):
            if finding.get("finding_type") == "printable_strings":
                ips = finding.get("extracted_value", {}).get("ip_addresses", [])
                for ip in ips:
                    if isinstance(ip, dict):
                        self.ip_addresses.add(ip.get("value", ""))
                    else:
                        self.ip_addresses.add(str(ip))
        
        # VBA/Macro indicators
        self.has_macros = False
        self.macro_streams: Set[str] = set()
        
        for finding in part2.get("file_type_specific", []):
            if finding.get("finding_type") == "office_ooxml_analysis":
                value = finding.get("extracted_value", {})
                if value.get("has_vba_macros"):
                    self.has_macros = True
            elif finding.get("finding_type") == "office_legacy_analysis":
                value = finding.get("extracted_value", {})
                if value.get("has_macros"):
                    self.has_macros = True
                    self.macro_streams.update(value.get("macro_streams", []))
        
        # Archive entries (for nested file detection)
        self.archive_entries: Set[str] = set()
        for finding in part2.get("file_type_specific", []):
            if finding.get("finding_type") == "archive_analysis":
                tree = finding.get("extracted_value", {}).get("file_tree", [])
                for entry in tree:
                    if isinstance(entry, dict):
                        self.archive_entries.add(entry.get("path", ""))
                    else:
                        self.archive_entries.add(str(entry))
        
        # OOXML content types
        self.content_types: Set[str] = set()
        for finding in part2.get("file_type_specific", []):
            if finding.get("finding_type") == "office_ooxml_analysis":
                cts = finding.get("extracted_value", {}).get("content_types", [])
                self.content_types.update(cts)


class SessionCorrelator:
    """
    Session-level correlation engine for PART 3.
    
    Correlates findings across multiple files within the same
    analysis session. All correlations reference concrete evidence.
    """
    
    def __init__(self):
        """Initialize the correlator."""
        self.files: Dict[str, FileSession] = {}
        self.correlation_counter = 0
        self.correlations: List[Dict[str, Any]] = []
    
    def _next_correlation_id(self, correlation_type: str) -> str:
        """Generate next correlation ID."""
        self.correlation_counter += 1
        return generate_correlation_id(correlation_type, self.correlation_counter)
    
    def add_file(
        self,
        file_id: str,
        file_path: str,
        analysis_results: Dict[str, Any]
    ) -> None:
        """
        Add a file's analysis results to the session.
        
        Args:
            file_id: Unique identifier for this file.
            file_path: Path to the file.
            analysis_results: Combined PART 1, 2, 3 results.
        """
        self.files[file_id] = FileSession(file_id, file_path, analysis_results)
    
    def correlate(self) -> Dict[str, Any]:
        """
        Perform correlation across all files in the session.
        
        Returns:
            Dict containing all correlations found.
        """
        self.correlations = []
        
        if len(self.files) < 2:
            return {
                "correlations": [],
                "files_analyzed": len(self.files),
                "note": "At least 2 files required for correlation",
            }
        
        file_ids = list(self.files.keys())
        
        # Correlate fuzzy hashes
        self._correlate_fuzzy_hashes(file_ids)
        
        # Correlate cryptographic hashes
        self._correlate_crypto_hashes(file_ids)
        
        # Correlate shared URLs
        self._correlate_urls(file_ids)
        
        # Correlate shared IP addresses
        self._correlate_ip_addresses(file_ids)
        
        # Correlate macro presence
        self._correlate_macros(file_ids)
        
        # Correlate semantic types
        self._correlate_semantic_types(file_ids)
        
        # Correlate archive entries (nested file patterns)
        self._correlate_archive_entries(file_ids)
        
        return {
            "correlations": self.correlations,
            "files_analyzed": len(self.files),
            "correlation_count": len(self.correlations),
            "correlation_types": list(set(c["correlation_type"] for c in self.correlations)),
        }
    
    def _correlate_fuzzy_hashes(self, file_ids: List[str]) -> None:
        """Correlate files by fuzzy hash similarity."""
        # ssdeep comparison
        ssdeep_files = {
            fid: self.files[fid].fuzzy_hashes.get("ssdeep", "")
            for fid in file_ids
            if self.files[fid].fuzzy_hashes.get("ssdeep")
        }
        
        if len(ssdeep_files) >= 2:
            compared = set()
            for fid1, hash1 in ssdeep_files.items():
                for fid2, hash2 in ssdeep_files.items():
                    if fid1 >= fid2:
                        continue
                    pair = tuple(sorted([fid1, fid2]))
                    if pair in compared:
                        continue
                    compared.add(pair)
                    
                    # Try to compute similarity (requires ssdeep library)
                    try:
                        import ssdeep
                        score = ssdeep.compare(hash1, hash2)
                        if score > 0:
                            self.correlations.append({
                                "id": self._next_correlation_id("fuzzy_hash"),
                                "type": "correlation",
                                "correlation_type": "fuzzy_hash_similarity",
                                "algorithm": "ssdeep",
                                "file_ids": [fid1, fid2],
                                "file_paths": [
                                    self.files[fid1].file_path,
                                    self.files[fid2].file_path
                                ],
                                "similarity_score": score,
                                "hashes": [hash1, hash2],
                                "confidence": "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW",
                                "severity": "medium" if score >= 80 else "low",
                                "explanation": f"Files share {score}% ssdeep similarity",
                                "evidence_references": [
                                    f"{fid1}.fuzzy_hashes.ssdeep",
                                    f"{fid2}.fuzzy_hashes.ssdeep"
                                ],
                                "logic_applied": "ssdeep fuzzy hash comparison",
                                "failure_reason": None,
                            })
                    except ImportError:
                        # Without ssdeep, just note identical hashes
                        if hash1 == hash2:
                            self.correlations.append({
                                "id": self._next_correlation_id("fuzzy_hash"),
                                "type": "correlation",
                                "correlation_type": "identical_fuzzy_hash",
                                "algorithm": "ssdeep",
                                "file_ids": [fid1, fid2],
                                "file_paths": [
                                    self.files[fid1].file_path,
                                    self.files[fid2].file_path
                                ],
                                "similarity_score": 100,
                                "hashes": [hash1],
                                "confidence": "HIGH",
                                "severity": "high",
                                "explanation": "Files have identical ssdeep hashes",
                                "evidence_references": [
                                    f"{fid1}.fuzzy_hashes.ssdeep",
                                    f"{fid2}.fuzzy_hashes.ssdeep"
                                ],
                                "logic_applied": "ssdeep hash equality check",
                                "failure_reason": None,
                            })
        
        # TLSH comparison (similar logic)
        tlsh_files = {
            fid: self.files[fid].fuzzy_hashes.get("tlsh", "")
            for fid in file_ids
            if self.files[fid].fuzzy_hashes.get("tlsh")
        }
        
        if len(tlsh_files) >= 2:
            compared = set()
            for fid1, hash1 in tlsh_files.items():
                for fid2, hash2 in tlsh_files.items():
                    if fid1 >= fid2:
                        continue
                    pair = tuple(sorted([fid1, fid2]))
                    if pair in compared:
                        continue
                    compared.add(pair)
                    
                    try:
                        import tlsh
                        distance = tlsh.diff(hash1, hash2)
                        if distance <= 100:
                            self.correlations.append({
                                "id": self._next_correlation_id("fuzzy_hash"),
                                "type": "correlation",
                                "correlation_type": "fuzzy_hash_similarity",
                                "algorithm": "TLSH",
                                "file_ids": [fid1, fid2],
                                "file_paths": [
                                    self.files[fid1].file_path,
                                    self.files[fid2].file_path
                                ],
                                "tlsh_distance": distance,
                                "similarity_score": max(0, 100 - distance),
                                "hashes": [hash1, hash2],
                                "confidence": "HIGH" if distance <= 30 else "MEDIUM" if distance <= 70 else "LOW",
                                "severity": "medium" if distance <= 30 else "low",
                                "explanation": f"Files have TLSH distance of {distance} (lower = more similar)",
                                "evidence_references": [
                                    f"{fid1}.fuzzy_hashes.tlsh",
                                    f"{fid2}.fuzzy_hashes.tlsh"
                                ],
                                "logic_applied": "TLSH distance comparison",
                                "failure_reason": None,
                            })
                    except ImportError:
                        if hash1 == hash2:
                            self.correlations.append({
                                "id": self._next_correlation_id("fuzzy_hash"),
                                "type": "correlation",
                                "correlation_type": "identical_fuzzy_hash",
                                "algorithm": "TLSH",
                                "file_ids": [fid1, fid2],
                                "file_paths": [
                                    self.files[fid1].file_path,
                                    self.files[fid2].file_path
                                ],
                                "tlsh_distance": 0,
                                "similarity_score": 100,
                                "hashes": [hash1],
                                "confidence": "HIGH",
                                "severity": "high",
                                "explanation": "Files have identical TLSH hashes",
                                "evidence_references": [
                                    f"{fid1}.fuzzy_hashes.tlsh",
                                    f"{fid2}.fuzzy_hashes.tlsh"
                                ],
                                "logic_applied": "TLSH hash equality check",
                                "failure_reason": None,
                            })
    
    def _correlate_crypto_hashes(self, file_ids: List[str]) -> None:
        """Correlate files by identical cryptographic hashes."""
        hash_algos = ["sha256", "sha1", "md5"]
        
        for algo in hash_algos:
            hash_to_files: Dict[str, List[str]] = {}
            
            for fid in file_ids:
                hash_val = self.files[fid].crypto_hashes.get(algo, "")
                if hash_val:
                    if hash_val not in hash_to_files:
                        hash_to_files[hash_val] = []
                    hash_to_files[hash_val].append(fid)
            
            # Find duplicate hashes
            for hash_val, fids in hash_to_files.items():
                if len(fids) > 1:
                    self.correlations.append({
                        "id": self._next_correlation_id("identical_hash"),
                        "type": "correlation",
                        "correlation_type": "identical_cryptographic_hash",
                        "algorithm": algo.upper(),
                        "file_ids": fids,
                        "file_paths": [self.files[fid].file_path for fid in fids],
                        "hash_value": hash_val,
                        "confidence": "HIGH",
                        "severity": "high",
                        "explanation": f"{len(fids)} files have identical {algo.upper()} hash",
                        "evidence_references": [f"{fid}.crypto_hashes.{algo}" for fid in fids],
                        "logic_applied": f"{algo.upper()} hash equality check",
                        "failure_reason": None,
                    })
    
    def _correlate_urls(self, file_ids: List[str]) -> None:
        """Correlate files by shared embedded URLs."""
        url_to_files: Dict[str, List[str]] = {}
        
        for fid in file_ids:
            for url in self.files[fid].urls:
                if url:
                    if url not in url_to_files:
                        url_to_files[url] = []
                    url_to_files[url].append(fid)
        
        # Find shared URLs
        for url, fids in url_to_files.items():
            if len(fids) > 1:
                self.correlations.append({
                    "id": self._next_correlation_id("shared_url"),
                    "type": "correlation",
                    "correlation_type": "shared_embedded_url",
                    "file_ids": fids,
                    "file_paths": [self.files[fid].file_path for fid in fids],
                    "shared_url": url,
                    "confidence": "HIGH",
                    "severity": "medium",
                    "explanation": f"{len(fids)} files contain the same embedded URL",
                    "evidence_references": [f"{fid}.urls" for fid in fids],
                    "logic_applied": "URL string equality across files",
                    "failure_reason": None,
                })
    
    def _correlate_ip_addresses(self, file_ids: List[str]) -> None:
        """Correlate files by shared embedded IP addresses."""
        ip_to_files: Dict[str, List[str]] = {}
        
        for fid in file_ids:
            for ip in self.files[fid].ip_addresses:
                if ip:
                    if ip not in ip_to_files:
                        ip_to_files[ip] = []
                    ip_to_files[ip].append(fid)
        
        for ip, fids in ip_to_files.items():
            if len(fids) > 1:
                self.correlations.append({
                    "id": self._next_correlation_id("shared_ip"),
                    "type": "correlation",
                    "correlation_type": "shared_embedded_ip",
                    "file_ids": fids,
                    "file_paths": [self.files[fid].file_path for fid in fids],
                    "shared_ip": ip,
                    "confidence": "HIGH",
                    "severity": "medium",
                    "explanation": f"{len(fids)} files contain the same embedded IP address",
                    "evidence_references": [f"{fid}.ip_addresses" for fid in fids],
                    "logic_applied": "IP address string equality across files",
                    "failure_reason": None,
                })
    
    def _correlate_macros(self, file_ids: List[str]) -> None:
        """Correlate files by shared macro presence."""
        macro_files = [fid for fid in file_ids if self.files[fid].has_macros]
        
        if len(macro_files) > 1:
            self.correlations.append({
                "id": self._next_correlation_id("macro_pattern"),
                "type": "correlation",
                "correlation_type": "multiple_files_with_macros",
                "file_ids": macro_files,
                "file_paths": [self.files[fid].file_path for fid in macro_files],
                "confidence": "MEDIUM",
                "severity": "medium",
                "explanation": f"{len(macro_files)} files in session contain macros",
                "evidence_references": [f"{fid}.has_macros" for fid in macro_files],
                "logic_applied": "Macro presence check across files",
                "failure_reason": None,
            })
    
    def _correlate_semantic_types(self, file_ids: List[str]) -> None:
        """Correlate files by semantic type patterns."""
        type_to_files: Dict[str, List[str]] = {}
        
        for fid in file_ids:
            sem_type = self.files[fid].semantic_type
            if sem_type and sem_type != "UNKNOWN":
                if sem_type not in type_to_files:
                    type_to_files[sem_type] = []
                type_to_files[sem_type].append(fid)
        
        # Note significant patterns (e.g., all executables)
        suspicious_types = ["EXECUTABLE_PE", "EXECUTABLE_ELF", "EXECUTABLE_MACH_O"]
        
        for sem_type in suspicious_types:
            if sem_type in type_to_files and len(type_to_files[sem_type]) > 1:
                fids = type_to_files[sem_type]
                self.correlations.append({
                    "id": self._next_correlation_id("type_pattern"),
                    "type": "correlation",
                    "correlation_type": "multiple_executables",
                    "semantic_type": sem_type,
                    "file_ids": fids,
                    "file_paths": [self.files[fid].file_path for fid in fids],
                    "confidence": "MEDIUM",
                    "severity": "informational",
                    "explanation": f"{len(fids)} executable files ({sem_type}) in session",
                    "evidence_references": [f"{fid}.semantic_type" for fid in fids],
                    "logic_applied": "Semantic type pattern analysis",
                    "failure_reason": None,
                })
    
    def _correlate_archive_entries(self, file_ids: List[str]) -> None:
        """Correlate files by shared archive entry names."""
        entry_to_files: Dict[str, List[str]] = {}
        
        for fid in file_ids:
            for entry in self.files[fid].archive_entries:
                if entry and not entry.endswith('/'):  # Skip directory entries
                    if entry not in entry_to_files:
                        entry_to_files[entry] = []
                    entry_to_files[entry].append(fid)
        
        # Find shared entries (excluding common names)
        common_names = {'readme.txt', 'license.txt', 'manifest.xml', '[content_types].xml'}
        
        for entry, fids in entry_to_files.items():
            if len(fids) > 1 and entry.lower() not in common_names:
                self.correlations.append({
                    "id": self._next_correlation_id("shared_entry"),
                    "type": "correlation",
                    "correlation_type": "shared_archive_entry",
                    "file_ids": fids,
                    "file_paths": [self.files[fid].file_path for fid in fids],
                    "shared_entry": entry,
                    "confidence": "MEDIUM",
                    "severity": "low",
                    "explanation": f"{len(fids)} archives contain entry '{entry}'",
                    "evidence_references": [f"{fid}.archive_entries" for fid in fids],
                    "logic_applied": "Archive entry name comparison",
                    "failure_reason": None,
                })


def correlate_session(
    files: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function to correlate multiple files.
    
    Args:
        files: List of dicts with 'file_id', 'file_path', and 'analysis_results'.
    
    Returns:
        Dict containing all correlations found.
    """
    correlator = SessionCorrelator()
    
    for file_data in files:
        correlator.add_file(
            file_id=file_data["file_id"],
            file_path=file_data["file_path"],
            analysis_results=file_data["analysis_results"]
        )
    
    return correlator.correlate()
