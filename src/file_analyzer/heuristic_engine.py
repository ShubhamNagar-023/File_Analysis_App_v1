"""
Heuristic Engine - PART 3: Deterministic Heuristic Evaluation

This module implements deterministic heuristic evaluation based on
evidence from PART 1 and PART 2 outputs. Each heuristic has explicit
trigger conditions, required evidence IDs, and weight contributions.

All heuristics are documented, reproducible, and evidence-backed.
"""

import math
from typing import Any, Dict, List, Optional, Tuple


def generate_heuristic_id(heuristic_name: str, counter: int) -> str:
    """Generate a unique heuristic ID."""
    return f"H{counter:04d}_{heuristic_name}"


# Heuristic definitions with explicit trigger conditions
HEURISTIC_DEFINITIONS = {
    "high_entropy_executable": {
        "name": "High Entropy in Executable Section",
        "description": "Detects executable files with unusually high entropy, potentially indicating packing or encryption",
        "trigger_conditions": [
            "File is executable type (PE, ELF, Mach-O)",
            "Any section has entropy > 7.2",
        ],
        "required_evidence_types": ["semantic_file_type", "section_entropy"],
        "weight": 25,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "macro_with_auto_exec": {
        "name": "Macro with Auto-Execution Indicator",
        "description": "Detects Office documents containing macros with auto-execution triggers",
        "trigger_conditions": [
            "File contains VBA macros",
            "Auto-execution keywords detected (AutoOpen, Workbook_Open, etc.)",
        ],
        "required_evidence_types": ["office_legacy_analysis", "office_ooxml_analysis"],
        "weight": 40,
        "severity": "high",
        "confidence": "HIGH",
    },
    "ooxml_external_relationship": {
        "name": "OOXML External Relationship",
        "description": "Detects OOXML documents with external relationships (potential data exfiltration)",
        "trigger_conditions": [
            "File is OOXML type (DOCX, XLSX, PPTX)",
            "External relationships found (http://, file://, etc.)",
        ],
        "required_evidence_types": ["office_ooxml_analysis"],
        "weight": 30,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "pdf_javascript": {
        "name": "PDF with JavaScript",
        "description": "Detects PDF documents containing JavaScript code",
        "trigger_conditions": [
            "File is PDF type",
            "/JavaScript or /JS keyword detected",
        ],
        "required_evidence_types": ["pdf_analysis"],
        "weight": 35,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "pdf_auto_action": {
        "name": "PDF with Auto-Action",
        "description": "Detects PDF documents with automatic action triggers",
        "trigger_conditions": [
            "File is PDF type",
            "Auto-action keywords detected (/OpenAction, /AA, /Launch)",
        ],
        "required_evidence_types": ["pdf_analysis"],
        "weight": 30,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "pdf_incremental_updates": {
        "name": "PDF with Multiple Incremental Updates",
        "description": "Detects PDF documents with multiple incremental updates (potential tampering)",
        "trigger_conditions": [
            "File is PDF type",
            "More than 2 %%EOF markers detected",
        ],
        "required_evidence_types": ["pdf_analysis"],
        "weight": 15,
        "severity": "low",
        "confidence": "MEDIUM",
    },
    "extension_mismatch": {
        "name": "Extension Mismatch",
        "description": "Detects files where the extension does not match the actual file type",
        "trigger_conditions": [
            "File extension does not match detected semantic type",
        ],
        "required_evidence_types": ["extension_analysis", "semantic_file_type"],
        "weight": 20,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "double_extension": {
        "name": "Double Extension Detected",
        "description": "Detects files with double extensions (common evasion technique)",
        "trigger_conditions": [
            "Filename contains multiple extensions (e.g., .txt.exe)",
        ],
        "required_evidence_types": ["extension_analysis"],
        "weight": 25,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "unicode_deception": {
        "name": "Unicode Deception Characters",
        "description": "Detects Unicode characters used for filename deception (RLO, homoglyphs)",
        "trigger_conditions": [
            "Filename contains RLO/LRO characters",
            "Filename contains homoglyph characters",
        ],
        "required_evidence_types": ["extension_analysis"],
        "weight": 35,
        "severity": "high",
        "confidence": "HIGH",
    },
    "polyglot_file": {
        "name": "Polyglot File Detected",
        "description": "Detects files valid as multiple formats (potential evasion)",
        "trigger_conditions": [
            "Multiple valid format signatures at different offsets",
        ],
        "required_evidence_types": ["magic_detection"],
        "weight": 40,
        "severity": "high",
        "confidence": "HIGH",
    },
    "trailing_data": {
        "name": "Trailing Data After EOF",
        "description": "Detects files with data appended after the logical end-of-file",
        "trigger_conditions": [
            "File contains data after container EOF marker",
        ],
        "required_evidence_types": ["trailing_data", "advanced_checks"],
        "weight": 20,
        "severity": "medium",
        "confidence": "HIGH",
    },
    "zip_bomb_indicator": {
        "name": "Zip Bomb Indicator",
        "description": "Detects archives with high compression ratios indicating potential zip bomb",
        "trigger_conditions": [
            "Archive file with compression ratio > 100:1",
            "Overall compression ratio > 50:1",
        ],
        "required_evidence_types": ["zip_container_analysis"],
        "weight": 45,
        "severity": "high",
        "confidence": "HIGH",
    },
    "encrypted_archive_entries": {
        "name": "Encrypted Archive Entries",
        "description": "Detects archives containing encrypted entries (potential payload hiding)",
        "trigger_conditions": [
            "Archive contains one or more encrypted entries",
        ],
        "required_evidence_types": ["zip_container_analysis"],
        "weight": 15,
        "severity": "low",
        "confidence": "HIGH",
    },
    "suspicious_strings": {
        "name": "Suspicious Strings Detected",
        "description": "Detects suspicious command strings in file content",
        "trigger_conditions": [
            "File contains suspicious command keywords (cmd, powershell, wget, curl)",
        ],
        "required_evidence_types": ["printable_strings"],
        "weight": 20,
        "severity": "medium",
        "confidence": "MEDIUM",
    },
    "embedded_urls": {
        "name": "Embedded URLs Detected",
        "description": "Detects URLs embedded in file content",
        "trigger_conditions": [
            "File contains one or more embedded URLs",
        ],
        "required_evidence_types": ["printable_strings"],
        "weight": 10,
        "severity": "low",
        "confidence": "HIGH",
    },
    "pe_packing_indicators": {
        "name": "PE Packing Indicators",
        "description": "Detects PE executables with signs of packing or obfuscation",
        "trigger_conditions": [
            "PE file with high entropy sections (> 7.2)",
            "Unusual section names",
        ],
        "required_evidence_types": ["pe_analysis"],
        "weight": 30,
        "severity": "medium",
        "confidence": "MEDIUM",
    },
    "ole_hidden_streams": {
        "name": "OLE Hidden Streams",
        "description": "Detects OLE documents with hidden streams (potential payload hiding)",
        "trigger_conditions": [
            "OLE container with streams starting with control characters",
        ],
        "required_evidence_types": ["ole_container_analysis"],
        "weight": 25,
        "severity": "medium",
        "confidence": "MEDIUM",
    },
}


class HeuristicEngine:
    """
    Deterministic heuristic evaluation engine for PART 3.
    
    Evaluates explicit heuristics based on evidence from PART 1 and PART 2.
    Each heuristic trigger is documented with conditions and weights.
    """
    
    def __init__(
        self,
        part1_results: Dict[str, Any],
        part2_results: Dict[str, Any],
        semantic_file_type: str
    ):
        """
        Initialize the heuristic engine.
        
        Args:
            part1_results: Results from PART 1 analysis.
            part2_results: Results from PART 2 analysis.
            semantic_file_type: Semantic file type from PART 1.
        """
        self.part1 = part1_results
        self.part2 = part2_results
        self.semantic_file_type = semantic_file_type
        self.heuristic_counter = 0
        
        self.triggered_heuristics: List[Dict[str, Any]] = []
        self.failed_heuristics: List[Dict[str, Any]] = []
    
    def _next_heuristic_id(self, heuristic_name: str) -> str:
        """Generate next heuristic ID."""
        self.heuristic_counter += 1
        return generate_heuristic_id(heuristic_name, self.heuristic_counter)
    
    def _get_evidence_value(self, evidence_type: str) -> Optional[Any]:
        """
        Extract evidence value from PART 1 or PART 2 results.
        
        Args:
            evidence_type: Type of evidence to retrieve.
        
        Returns:
            Evidence value or None if not found.
        """
        # Check PART 1 results
        if evidence_type in self.part1:
            return self.part1[evidence_type]
        
        # Check for output_value wrapper in PART 1
        for key, value in self.part1.items():
            if isinstance(value, dict) and 'output_value' in value:
                if key == evidence_type:
                    return value['output_value']
        
        # Check PART 2 results
        if evidence_type in self.part2:
            return self.part2[evidence_type]
        
        # Check universal findings in PART 2
        if 'universal' in self.part2:
            for finding in self.part2['universal']:
                if finding.get('finding_type') == evidence_type:
                    return finding.get('extracted_value')
        
        # Check container_level findings in PART 2
        if 'container_level' in self.part2:
            for finding in self.part2['container_level']:
                if finding.get('finding_type') == evidence_type:
                    return finding.get('extracted_value')
        
        # Check file_type_specific findings in PART 2
        if 'file_type_specific' in self.part2:
            for finding in self.part2['file_type_specific']:
                if finding.get('finding_type') == evidence_type:
                    return finding.get('extracted_value')
        
        return None
    
    def _create_heuristic_result(
        self,
        heuristic_key: str,
        triggered: bool,
        evidence_refs: List[str],
        trigger_details: Dict[str, Any],
        failure_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a standardized heuristic result."""
        definition = HEURISTIC_DEFINITIONS.get(heuristic_key, {})
        
        return {
            "id": self._next_heuristic_id(heuristic_key),
            "type": "heuristic",
            "heuristic_key": heuristic_key,
            "name": definition.get("name", heuristic_key),
            "description": definition.get("description", ""),
            "semantic_file_type": self.semantic_file_type,
            "triggered": triggered,
            "trigger_conditions": definition.get("trigger_conditions", []),
            "trigger_details": trigger_details,
            "evidence_references": evidence_refs,
            "weight": definition.get("weight", 0) if triggered else 0,
            "score_contribution": definition.get("weight", 0) if triggered else 0,
            "severity": definition.get("severity", "informational"),
            "confidence": definition.get("confidence", "MEDIUM"),
            "logic_applied": f"Heuristic: {definition.get('name', heuristic_key)}",
            "explanation": self._generate_explanation(heuristic_key, triggered, trigger_details),
            "reproducibility_notes": f"Deterministic heuristic based on evidence from PART 1/2",
            "failure_reason": failure_reason,
        }
    
    def _generate_explanation(
        self,
        heuristic_key: str,
        triggered: bool,
        trigger_details: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation for heuristic result."""
        definition = HEURISTIC_DEFINITIONS.get(heuristic_key, {})
        
        if not triggered:
            return f"Heuristic '{definition.get('name', heuristic_key)}' was evaluated but conditions were not met."
        
        base_explanation = definition.get("description", "Heuristic triggered")
        
        # Add specific details based on heuristic type
        if heuristic_key == "high_entropy_executable":
            entropy = trigger_details.get("max_entropy", 0)
            return f"{base_explanation}. Highest section entropy: {entropy:.2f} (threshold: 7.2)"
        
        elif heuristic_key == "macro_with_auto_exec":
            indicators = trigger_details.get("auto_exec_indicators", [])
            return f"{base_explanation}. Auto-execution indicators found: {', '.join(indicators)}"
        
        elif heuristic_key == "ooxml_external_relationship":
            refs = trigger_details.get("external_refs", [])
            return f"{base_explanation}. External references: {', '.join(refs[:3])}" + \
                   (f" (and {len(refs) - 3} more)" if len(refs) > 3 else "")
        
        elif heuristic_key == "pdf_javascript":
            return f"{base_explanation}. JavaScript capability detected in PDF structure."
        
        elif heuristic_key == "extension_mismatch":
            actual_ext = trigger_details.get("actual_extension", "")
            expected_type = trigger_details.get("semantic_type", "")
            return f"{base_explanation}. Extension '{actual_ext}' does not match detected type '{expected_type}'"
        
        elif heuristic_key == "polyglot_file":
            types = trigger_details.get("signature_types", [])
            return f"{base_explanation}. Multiple format signatures detected: {', '.join(types)}"
        
        elif heuristic_key == "zip_bomb_indicator":
            ratio = trigger_details.get("max_ratio", 0)
            return f"{base_explanation}. Maximum compression ratio: {ratio:.1f}:1"
        
        return base_explanation
    
    def evaluate(self) -> Dict[str, Any]:
        """
        Evaluate all applicable heuristics.
        
        Returns:
            Dict containing triggered and failed heuristics.
        """
        results = {
            "triggered_heuristics": [],
            "failed_heuristics": [],
            "total_weight": 0,
            "heuristics_evaluated": 0,
        }
        
        # Evaluate each heuristic
        self._evaluate_high_entropy_executable()
        self._evaluate_macro_with_auto_exec()
        self._evaluate_ooxml_external_relationship()
        self._evaluate_pdf_javascript()
        self._evaluate_pdf_auto_action()
        self._evaluate_pdf_incremental_updates()
        self._evaluate_extension_mismatch()
        self._evaluate_double_extension()
        self._evaluate_unicode_deception()
        self._evaluate_polyglot_file()
        self._evaluate_trailing_data()
        self._evaluate_zip_bomb_indicator()
        self._evaluate_encrypted_archive_entries()
        self._evaluate_suspicious_strings()
        self._evaluate_embedded_urls()
        self._evaluate_pe_packing_indicators()
        self._evaluate_ole_hidden_streams()
        
        results["triggered_heuristics"] = self.triggered_heuristics
        results["failed_heuristics"] = self.failed_heuristics
        results["heuristics_evaluated"] = len(self.triggered_heuristics) + len(self.failed_heuristics)
        results["total_weight"] = sum(h["weight"] for h in self.triggered_heuristics)
        
        return results
    
    def _evaluate_high_entropy_executable(self) -> None:
        """Evaluate high entropy in executable sections."""
        heuristic_key = "high_entropy_executable"
        
        # Check if file is executable
        if self.semantic_file_type not in ['EXECUTABLE_PE', 'EXECUTABLE_ELF', 'EXECUTABLE_MACH_O']:
            return  # Not applicable
        
        # Get section entropy data
        section_data = self._get_evidence_value("section_entropy")
        pe_data = self._get_evidence_value("pe_analysis")
        
        evidence_refs = []
        trigger_details = {}
        triggered = False
        max_entropy = 0
        
        # Check PE analysis for section entropy
        if pe_data and isinstance(pe_data, dict):
            sections = pe_data.get("sections", [])
            for section in sections:
                entropy = section.get("entropy", 0)
                if entropy > max_entropy:
                    max_entropy = entropy
            
            if max_entropy > 7.2:
                triggered = True
                evidence_refs.append("pe_analysis.sections")
                trigger_details["max_entropy"] = max_entropy
                trigger_details["high_entropy_sections"] = [
                    s.get("name", "unknown") for s in sections if s.get("entropy", 0) > 7.2
                ]
        
        # Check universal section entropy
        if section_data and isinstance(section_data, dict):
            sections = section_data.get("sections", [])
            for section in sections:
                entropy = section.get("entropy", 0)
                if entropy > max_entropy:
                    max_entropy = entropy
            
            if max_entropy > 7.2:
                triggered = True
                evidence_refs.append("section_entropy")
                trigger_details["max_entropy"] = max_entropy
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No high entropy sections detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_macro_with_auto_exec(self) -> None:
        """Evaluate macro with auto-execution indicators."""
        heuristic_key = "macro_with_auto_exec"
        
        # Check if file is Office type
        if self.semantic_file_type not in ['DOC', 'XLS', 'PPT', 'DOCX', 'XLSX', 'PPTX', 
                                            'OLE_COMPOUND_DOCUMENT']:
            return
        
        # Get Office analysis data
        legacy_data = self._get_evidence_value("office_legacy_analysis")
        ooxml_data = self._get_evidence_value("office_ooxml_analysis")
        
        evidence_refs = []
        trigger_details = {}
        triggered = False
        
        # Check legacy Office
        if legacy_data and isinstance(legacy_data, dict):
            has_macros = legacy_data.get("has_macros", False)
            auto_exec = legacy_data.get("auto_execution_indicators", [])
            
            if has_macros and auto_exec:
                triggered = True
                evidence_refs.append("office_legacy_analysis")
                trigger_details["has_macros"] = True
                trigger_details["auto_exec_indicators"] = auto_exec
        
        # Check OOXML
        if ooxml_data and isinstance(ooxml_data, dict):
            has_vba = ooxml_data.get("has_vba_macros", False)
            if has_vba:
                evidence_refs.append("office_ooxml_analysis")
                trigger_details["has_vba_macros"] = True
                
                # For OOXML, check for auto-exec patterns in external references
                # or relationships that may indicate auto-execution behavior
                external_refs = ooxml_data.get("external_references", [])
                relationships = ooxml_data.get("relationships", [])
                
                # Check for auto-execution indicators in OOXML
                ooxml_auto_exec = []
                auto_exec_patterns = ['vbaProject', 'AutoOpen', 'AutoExec', 'Document_Open']
                
                for ref in external_refs:
                    for pattern in auto_exec_patterns:
                        if pattern.lower() in str(ref).lower():
                            ooxml_auto_exec.append(pattern)
                
                for rel in relationships:
                    targets = rel.get("targets", []) if isinstance(rel, dict) else []
                    for target in targets:
                        if 'vba' in str(target).lower():
                            ooxml_auto_exec.append("VBA reference")
                
                # Also use any auto-exec indicators from legacy analysis
                if trigger_details.get("auto_exec_indicators"):
                    ooxml_auto_exec.extend(trigger_details["auto_exec_indicators"])
                
                if ooxml_auto_exec:
                    triggered = True
                    trigger_details["auto_exec_indicators"] = list(set(ooxml_auto_exec))
                elif has_vba:
                    # VBA presence alone is still noteworthy but with lower confidence
                    # We'll still trigger but note it's just VBA presence
                    trigger_details["note"] = "VBA macros detected but no auto-execution indicators found"
        
        if evidence_refs:
            result = self._create_heuristic_result(
                heuristic_key, triggered, evidence_refs, trigger_details
            )
            
            if triggered:
                self.triggered_heuristics.append(result)
            else:
                result["failure_reason"] = "Macros found but no auto-execution indicators"
                self.failed_heuristics.append(result)
    
    def _evaluate_ooxml_external_relationship(self) -> None:
        """Evaluate OOXML external relationships."""
        heuristic_key = "ooxml_external_relationship"
        
        if self.semantic_file_type not in ['DOCX', 'XLSX', 'PPTX']:
            return
        
        ooxml_data = self._get_evidence_value("office_ooxml_analysis")
        
        if not ooxml_data or not isinstance(ooxml_data, dict):
            return
        
        external_refs = ooxml_data.get("external_references", [])
        
        triggered = len(external_refs) > 0
        evidence_refs = ["office_ooxml_analysis.external_references"] if triggered else []
        trigger_details = {"external_refs": external_refs}
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No external relationships found"
            self.failed_heuristics.append(result)
    
    def _evaluate_pdf_javascript(self) -> None:
        """Evaluate PDF with JavaScript."""
        heuristic_key = "pdf_javascript"
        
        if self.semantic_file_type != 'PDF':
            return
        
        pdf_data = self._get_evidence_value("pdf_analysis")
        
        if not pdf_data or not isinstance(pdf_data, dict):
            return
        
        has_js = pdf_data.get("has_javascript", False)
        
        triggered = has_js
        evidence_refs = ["pdf_analysis.has_javascript"] if triggered else []
        trigger_details = {"has_javascript": has_js}
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No JavaScript detected in PDF"
            self.failed_heuristics.append(result)
    
    def _evaluate_pdf_auto_action(self) -> None:
        """Evaluate PDF with auto-action triggers."""
        heuristic_key = "pdf_auto_action"
        
        if self.semantic_file_type != 'PDF':
            return
        
        pdf_data = self._get_evidence_value("pdf_analysis")
        
        if not pdf_data or not isinstance(pdf_data, dict):
            return
        
        suspicious_keywords = pdf_data.get("suspicious_keywords", [])
        auto_actions = [k for k in suspicious_keywords if k in ['/OpenAction', '/AA', '/Launch']]
        
        triggered = len(auto_actions) > 0
        evidence_refs = ["pdf_analysis.suspicious_keywords"] if triggered else []
        trigger_details = {"auto_actions": auto_actions}
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No auto-action triggers found in PDF"
            self.failed_heuristics.append(result)
    
    def _evaluate_pdf_incremental_updates(self) -> None:
        """Evaluate PDF with multiple incremental updates."""
        heuristic_key = "pdf_incremental_updates"
        
        if self.semantic_file_type != 'PDF':
            return
        
        pdf_data = self._get_evidence_value("pdf_analysis")
        
        if not pdf_data or not isinstance(pdf_data, dict):
            return
        
        incremental_updates = pdf_data.get("incremental_updates", 0)
        
        triggered = incremental_updates > 2
        evidence_refs = ["pdf_analysis.incremental_updates"] if triggered else []
        trigger_details = {"incremental_updates": incremental_updates}
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = f"Only {incremental_updates} incremental updates (threshold: >2)"
            self.failed_heuristics.append(result)
    
    def _evaluate_extension_mismatch(self) -> None:
        """Evaluate extension mismatch."""
        heuristic_key = "extension_mismatch"
        
        ext_data = self.part1.get("extension_analysis", {}).get("output_value", {})
        
        if not ext_data:
            return
        
        mismatch = ext_data.get("extension_mismatch", False)
        
        triggered = mismatch
        evidence_refs = ["extension_analysis"] if triggered else []
        trigger_details = {
            "actual_extension": ext_data.get("primary_extension", ""),
            "semantic_type": self.semantic_file_type,
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "Extension matches detected file type"
            self.failed_heuristics.append(result)
    
    def _evaluate_double_extension(self) -> None:
        """Evaluate double extension detection."""
        heuristic_key = "double_extension"
        
        ext_data = self.part1.get("extension_analysis", {}).get("output_value", {})
        
        if not ext_data:
            return
        
        double_ext = ext_data.get("double_extension_detected", False)
        
        triggered = double_ext
        evidence_refs = ["extension_analysis"] if triggered else []
        trigger_details = {
            "extension_chain": ext_data.get("extension_chain", []),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No double extension detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_unicode_deception(self) -> None:
        """Evaluate Unicode deception characters."""
        heuristic_key = "unicode_deception"
        
        ext_data = self.part1.get("extension_analysis", {}).get("output_value", {})
        
        if not ext_data:
            return
        
        unicode_deception = ext_data.get("unicode_deception", [])
        homoglyphs = ext_data.get("homoglyphs_detected", [])
        
        triggered = len(unicode_deception) > 0 or len(homoglyphs) > 0
        evidence_refs = ["extension_analysis"] if triggered else []
        trigger_details = {
            "unicode_deception": unicode_deception,
            "homoglyphs": homoglyphs,
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No Unicode deception characters detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_polyglot_file(self) -> None:
        """Evaluate polyglot file detection."""
        heuristic_key = "polyglot_file"
        
        magic_data = self.part1.get("magic_detection", {}).get("output_value", {})
        
        if not magic_data:
            return
        
        polyglot_indicators = magic_data.get("polyglot_indicators", [])
        signatures = magic_data.get("signatures_found", [])
        
        # Check for multiple signature types
        unique_types = set(s.get("signature_type") for s in signatures)
        
        triggered = len(polyglot_indicators) > 0 or len(unique_types) > 1
        evidence_refs = ["magic_detection"] if triggered else []
        trigger_details = {
            "polyglot_indicators": polyglot_indicators,
            "signature_types": list(unique_types),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No polyglot indicators detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_trailing_data(self) -> None:
        """Evaluate trailing data after EOF."""
        heuristic_key = "trailing_data"
        
        # Check PART 2 trailing data finding
        trailing_data = self._get_evidence_value("trailing_data")
        
        # Also check PART 1 advanced checks
        advanced = self.part1.get("advanced_checks", {}).get("output_value", {})
        issues = advanced.get("issues_found", [])
        trailing_issues = [i for i in issues if i.get("check") == "trailing_data"]
        
        triggered = (trailing_data is not None) or len(trailing_issues) > 0
        evidence_refs = []
        trigger_details = {}
        
        if trailing_data:
            evidence_refs.append("trailing_data")
            trigger_details["trailing_size"] = trailing_data.get("trailing_size", 0)
        
        if trailing_issues:
            evidence_refs.append("advanced_checks")
            for issue in trailing_issues:
                trigger_details["trailing_bytes"] = issue.get("trailing_bytes", 0)
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No trailing data detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_zip_bomb_indicator(self) -> None:
        """Evaluate zip bomb indicators."""
        heuristic_key = "zip_bomb_indicator"
        
        zip_data = self._get_evidence_value("zip_container_analysis")
        
        if not zip_data or not isinstance(zip_data, dict):
            return
        
        zip_bomb_indicators = zip_data.get("zip_bomb_indicators", [])
        overall_ratio = zip_data.get("overall_compression_ratio", 0)
        
        triggered = len(zip_bomb_indicators) > 0 or overall_ratio > 50
        evidence_refs = ["zip_container_analysis"] if triggered else []
        trigger_details = {
            "zip_bomb_indicators": zip_bomb_indicators,
            "overall_ratio": overall_ratio,
            "max_ratio": max([z.get("ratio", 0) for z in zip_bomb_indicators], default=0),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No zip bomb indicators detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_encrypted_archive_entries(self) -> None:
        """Evaluate encrypted archive entries."""
        heuristic_key = "encrypted_archive_entries"
        
        zip_data = self._get_evidence_value("zip_container_analysis")
        archive_data = self._get_evidence_value("archive_analysis")
        
        encrypted_entries = []
        
        if zip_data and isinstance(zip_data, dict):
            encrypted_entries.extend(zip_data.get("encrypted_entries", []))
        
        if archive_data and isinstance(archive_data, dict):
            encrypted_entries.extend(archive_data.get("encrypted_entries", []))
        
        triggered = len(encrypted_entries) > 0
        evidence_refs = []
        if triggered:
            if zip_data:
                evidence_refs.append("zip_container_analysis")
            if archive_data:
                evidence_refs.append("archive_analysis")
        
        trigger_details = {
            "encrypted_entries": encrypted_entries[:10],
            "count": len(encrypted_entries),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No encrypted entries detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_suspicious_strings(self) -> None:
        """Evaluate suspicious command strings."""
        heuristic_key = "suspicious_strings"
        
        strings_data = self._get_evidence_value("printable_strings")
        
        if not strings_data or not isinstance(strings_data, dict):
            return
        
        suspicious_commands = strings_data.get("suspicious_commands", [])
        
        triggered = len(suspicious_commands) > 0
        evidence_refs = ["printable_strings"] if triggered else []
        trigger_details = {
            "suspicious_commands": suspicious_commands[:10],
            "count": len(suspicious_commands),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No suspicious command strings detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_embedded_urls(self) -> None:
        """Evaluate embedded URLs."""
        heuristic_key = "embedded_urls"
        
        strings_data = self._get_evidence_value("printable_strings")
        
        if not strings_data or not isinstance(strings_data, dict):
            return
        
        urls = strings_data.get("urls", [])
        
        triggered = len(urls) > 0
        evidence_refs = ["printable_strings"] if triggered else []
        trigger_details = {
            "urls": [u.get("value", u) if isinstance(u, dict) else u for u in urls[:10]],
            "count": len(urls),
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No embedded URLs detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_pe_packing_indicators(self) -> None:
        """Evaluate PE packing indicators."""
        heuristic_key = "pe_packing_indicators"
        
        if self.semantic_file_type != 'EXECUTABLE_PE':
            return
        
        pe_data = self._get_evidence_value("pe_analysis")
        
        if not pe_data or not isinstance(pe_data, dict):
            return
        
        packing_indicators = pe_data.get("packing_indicators", [])
        
        triggered = len(packing_indicators) > 0
        evidence_refs = ["pe_analysis"] if triggered else []
        trigger_details = {
            "packing_indicators": packing_indicators[:10],
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No PE packing indicators detected"
            self.failed_heuristics.append(result)
    
    def _evaluate_ole_hidden_streams(self) -> None:
        """Evaluate OLE hidden streams."""
        heuristic_key = "ole_hidden_streams"
        
        ole_data = self._get_evidence_value("ole_container_analysis")
        
        if not ole_data or not isinstance(ole_data, dict):
            return
        
        hidden_streams = ole_data.get("hidden_streams", [])
        
        triggered = len(hidden_streams) > 0
        evidence_refs = ["ole_container_analysis"] if triggered else []
        trigger_details = {
            "hidden_streams": hidden_streams[:10],
        }
        
        result = self._create_heuristic_result(
            heuristic_key, triggered, evidence_refs, trigger_details
        )
        
        if triggered:
            self.triggered_heuristics.append(result)
        else:
            result["failure_reason"] = "No hidden OLE streams detected"
            self.failed_heuristics.append(result)


def evaluate_heuristics(
    part1_results: Dict[str, Any],
    part2_results: Dict[str, Any],
    semantic_file_type: str
) -> Dict[str, Any]:
    """
    Convenience function to evaluate all heuristics.
    
    Args:
        part1_results: Results from PART 1 analysis.
        part2_results: Results from PART 2 analysis.
        semantic_file_type: Semantic file type from PART 1.
    
    Returns:
        Dict containing triggered and failed heuristics.
    """
    engine = HeuristicEngine(part1_results, part2_results, semantic_file_type)
    return engine.evaluate()
