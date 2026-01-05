"""
Rule Engine - PART 3: YARA Rule Detection and Fuzzy Hashing

This module implements rule-based detection using YARA rules and
fuzzy hashing (ssdeep, TLSH) for similarity comparison.

All operations are deterministic, evidence-based, and reproducible.
"""

import io
import os
from typing import Any, Dict, List, Optional, Tuple

# Optional imports with fallback handling
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False

try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False


def generate_detection_id(detection_type: str, counter: int) -> str:
    """Generate a unique detection ID."""
    return f"D{counter:04d}_{detection_type}"


class RuleEngine:
    """
    Rule-based detection engine for PART 3.
    
    Applies YARA rules to file data and computes fuzzy hashes
    for similarity comparison. All detections are evidence-based
    and include byte-accurate offset information.
    """
    
    def __init__(self, file_path: str, file_data: bytes, semantic_file_type: str):
        """
        Initialize the rule engine.
        
        Args:
            file_path: Path to the file being analyzed.
            file_data: Raw bytes of the file.
            semantic_file_type: Semantic file type from PART 1.
        """
        self.file_path = file_path
        self.file_data = file_data
        self.file_size = len(file_data)
        self.semantic_file_type = semantic_file_type
        self.detection_counter = 0
        
        self.detections: List[Dict[str, Any]] = []
        self.fuzzy_hashes: Dict[str, Any] = {}
    
    def _next_detection_id(self, detection_type: str) -> str:
        """Generate next detection ID."""
        self.detection_counter += 1
        return generate_detection_id(detection_type, self.detection_counter)
    
    def analyze(self, yara_rules_path: Optional[str] = None,
                reference_hashes: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        """
        Perform rule-based analysis.
        
        Args:
            yara_rules_path: Optional path to YARA rules file or directory.
            reference_hashes: Optional dict of reference hashes for similarity comparison.
                              Format: {"ssdeep": ["hash1", "hash2"], "tlsh": ["hash1"]}
        
        Returns:
            Dict containing all rule-based detections and fuzzy hashes.
        """
        results = {
            "yara_detections": [],
            "fuzzy_hashes": {},
            "similarity_matches": [],
            "library_status": {
                "yara_available": HAS_YARA,
                "ssdeep_available": HAS_SSDEEP,
                "tlsh_available": HAS_TLSH,
            },
            "failure_reasons": [],
        }
        
        # Apply YARA rules if available
        if yara_rules_path:
            yara_results = self._apply_yara_rules(yara_rules_path)
            results["yara_detections"] = yara_results.get("detections", [])
            if yara_results.get("failure_reason"):
                results["failure_reasons"].append(yara_results["failure_reason"])
        
        # Compute fuzzy hashes
        fuzzy_results = self._compute_fuzzy_hashes()
        results["fuzzy_hashes"] = fuzzy_results.get("hashes", {})
        if fuzzy_results.get("failure_reasons"):
            results["failure_reasons"].extend(fuzzy_results["failure_reasons"])
        
        # Perform similarity comparison if reference hashes provided
        if reference_hashes:
            similarity_results = self._compare_similarity(
                results["fuzzy_hashes"], reference_hashes
            )
            results["similarity_matches"] = similarity_results
        
        return results
    
    def _apply_yara_rules(self, rules_path: str) -> Dict[str, Any]:
        """
        Apply YARA rules to file data.
        
        Args:
            rules_path: Path to YARA rules file or directory.
        
        Returns:
            Dict containing YARA detections.
        """
        result = {
            "detections": [],
            "failure_reason": None,
        }
        
        if not HAS_YARA:
            result["failure_reason"] = "YARA library not available"
            return result
        
        if not os.path.exists(rules_path):
            result["failure_reason"] = f"YARA rules path does not exist: {rules_path}"
            return result
        
        try:
            # Load YARA rules
            if os.path.isfile(rules_path):
                rules = yara.compile(filepath=rules_path)
            elif os.path.isdir(rules_path):
                # Compile all .yar/.yara files in directory
                rule_files = {}
                for filename in os.listdir(rules_path):
                    if filename.endswith(('.yar', '.yara')):
                        namespace = os.path.splitext(filename)[0]
                        rule_files[namespace] = os.path.join(rules_path, filename)
                
                if not rule_files:
                    result["failure_reason"] = f"No YARA rule files found in: {rules_path}"
                    return result
                
                rules = yara.compile(filepaths=rule_files)
            else:
                result["failure_reason"] = f"Invalid YARA rules path: {rules_path}"
                return result
            
            # Match rules against file data
            matches = rules.match(data=self.file_data)
            
            for match in matches:
                detection = {
                    "id": self._next_detection_id("yara"),
                    "type": "rule",
                    "semantic_file_type": self.semantic_file_type,
                    "rule_id": match.rule,
                    "namespace": match.namespace if hasattr(match, 'namespace') else "default",
                    "tags": list(match.tags) if hasattr(match, 'tags') else [],
                    "meta": dict(match.meta) if hasattr(match, 'meta') else {},
                    "matched_strings": [],
                    "score_contribution": 0,  # Will be set by risk scorer
                    "confidence": "HIGH",
                    "severity": "informational",  # Default, can be overridden by meta
                    "explanation": f"YARA rule '{match.rule}' matched file content",
                    "verification_reference": f"yara {rules_path} {self.file_path}",
                    "failure_reason": None,
                }
                
                # Extract matched strings with byte offsets
                if hasattr(match, 'strings'):
                    for string_match in match.strings:
                        # YARA 4.x returns (offset, identifier, data) tuples
                        if isinstance(string_match, tuple) and len(string_match) >= 3:
                            offset, identifier, data = string_match[0], string_match[1], string_match[2]
                        else:
                            # Handle different YARA versions
                            offset = getattr(string_match, 'offset', 0)
                            identifier = getattr(string_match, 'identifier', str(string_match))
                            data = getattr(string_match, 'data', b'')
                        
                        detection["matched_strings"].append({
                            "identifier": str(identifier),
                            "offset": offset,
                            "data_hex": data.hex() if isinstance(data, bytes) else str(data),
                            "data_length": len(data) if isinstance(data, bytes) else 0,
                        })
                
                # Set severity from rule meta if available
                if "severity" in detection["meta"]:
                    severity = detection["meta"]["severity"].lower()
                    if severity in ["informational", "low", "medium", "high", "critical"]:
                        detection["severity"] = severity
                
                result["detections"].append(detection)
                
        except yara.Error as e:
            result["failure_reason"] = f"YARA error: {str(e)}"
        except Exception as e:
            result["failure_reason"] = f"Unexpected error applying YARA rules: {str(e)}"
        
        return result
    
    def _compute_fuzzy_hashes(self) -> Dict[str, Any]:
        """
        Compute fuzzy hashes (ssdeep, TLSH) for the file.
        
        Returns:
            Dict containing fuzzy hash values.
        """
        result = {
            "hashes": {},
            "failure_reasons": [],
        }
        
        # Compute ssdeep hash
        if HAS_SSDEEP:
            try:
                ssdeep_hash = ssdeep.hash(self.file_data)
                result["hashes"]["ssdeep"] = {
                    "value": ssdeep_hash,
                    "algorithm": "ssdeep",
                    "library_version": getattr(ssdeep, '__version__', 'unknown'),
                    "input_byte_range": f"0-{self.file_size}",
                    "verification_reference": f"ssdeep {self.file_path}",
                }
            except Exception as e:
                result["failure_reasons"].append(f"ssdeep computation failed: {str(e)}")
        else:
            result["failure_reasons"].append("ssdeep library not available")
        
        # Compute TLSH hash
        if HAS_TLSH:
            try:
                # TLSH requires minimum 50 bytes
                if self.file_size >= 50:
                    tlsh_hash = tlsh.hash(self.file_data)
                    if tlsh_hash:  # TLSH returns empty string for small/uniform files
                        result["hashes"]["tlsh"] = {
                            "value": tlsh_hash,
                            "algorithm": "TLSH",
                            "library_version": getattr(tlsh, '__version__', 'unknown'),
                            "input_byte_range": f"0-{self.file_size}",
                            "verification_reference": f"tlsh -f {self.file_path}",
                        }
                    else:
                        result["failure_reasons"].append(
                            "TLSH hash not computed: file too uniform or simple"
                        )
                else:
                    result["failure_reasons"].append(
                        f"TLSH requires minimum 50 bytes, file has {self.file_size}"
                    )
            except Exception as e:
                result["failure_reasons"].append(f"TLSH computation failed: {str(e)}")
        else:
            result["failure_reasons"].append("TLSH library not available")
        
        return result
    
    def _compare_similarity(
        self,
        computed_hashes: Dict[str, Dict],
        reference_hashes: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Compare computed fuzzy hashes against reference hashes.
        
        Args:
            computed_hashes: Dict of computed hash values.
            reference_hashes: Dict of reference hashes to compare against.
        
        Returns:
            List of similarity match results.
        """
        matches = []
        
        # Compare ssdeep hashes
        if HAS_SSDEEP and "ssdeep" in computed_hashes and "ssdeep" in reference_hashes:
            computed = computed_hashes["ssdeep"]["value"]
            for ref_hash in reference_hashes["ssdeep"]:
                try:
                    score = ssdeep.compare(computed, ref_hash)
                    if score > 0:  # Score of 0 means no similarity
                        matches.append({
                            "id": self._next_detection_id("similarity"),
                            "type": "correlation",
                            "semantic_file_type": self.semantic_file_type,
                            "algorithm": "ssdeep",
                            "computed_hash": computed,
                            "reference_hash": ref_hash,
                            "similarity_score": score,
                            "similarity_percentage": score,  # ssdeep returns 0-100
                            "confidence": "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW",
                            "severity": "informational",
                            "explanation": f"ssdeep similarity match: {score}% similar to reference",
                            "logic_applied": "ssdeep fuzzy hash comparison",
                            "verification_reference": "ssdeep -m reference.txt file",
                            "failure_reason": None,
                        })
                except Exception:
                    pass
        
        # Compare TLSH hashes
        if HAS_TLSH and "tlsh" in computed_hashes and "tlsh" in reference_hashes:
            computed = computed_hashes["tlsh"]["value"]
            for ref_hash in reference_hashes["tlsh"]:
                try:
                    # TLSH returns distance (lower = more similar)
                    # 0 = identical, higher = less similar
                    distance = tlsh.diff(computed, ref_hash)
                    if distance <= 100:  # Threshold for potential match
                        # Convert distance to similarity percentage (rough approximation)
                        similarity = max(0, 100 - distance)
                        matches.append({
                            "id": self._next_detection_id("similarity"),
                            "type": "correlation",
                            "semantic_file_type": self.semantic_file_type,
                            "algorithm": "TLSH",
                            "computed_hash": computed,
                            "reference_hash": ref_hash,
                            "tlsh_distance": distance,
                            "similarity_percentage": similarity,
                            "confidence": "HIGH" if distance <= 30 else "MEDIUM" if distance <= 70 else "LOW",
                            "severity": "informational",
                            "explanation": f"TLSH similarity match: distance {distance} (lower = more similar)",
                            "logic_applied": "TLSH fuzzy hash distance comparison",
                            "verification_reference": "tlsh -c computed_hash -f reference_hash",
                            "failure_reason": None,
                        })
                except Exception:
                    pass
        
        return matches


def apply_yara_rules(file_path: str, file_data: bytes, semantic_file_type: str,
                     rules_path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to apply YARA rules to a file.
    
    Args:
        file_path: Path to the file.
        file_data: Raw file bytes.
        semantic_file_type: Semantic file type from PART 1.
        rules_path: Path to YARA rules.
    
    Returns:
        List of YARA detection results.
    """
    engine = RuleEngine(file_path, file_data, semantic_file_type)
    results = engine.analyze(yara_rules_path=rules_path)
    return results.get("yara_detections", [])


def compute_fuzzy_hashes(file_data: bytes) -> Dict[str, Dict]:
    """
    Convenience function to compute fuzzy hashes.
    
    Args:
        file_data: Raw file bytes.
    
    Returns:
        Dict containing fuzzy hash values.
    """
    engine = RuleEngine("", file_data, "UNKNOWN")
    results = engine._compute_fuzzy_hashes()
    return results.get("hashes", {})
