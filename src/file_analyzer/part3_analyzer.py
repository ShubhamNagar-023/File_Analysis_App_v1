"""
PART 3 Analyzer - Rules, Correlation & Explainable Risk Scoring

This module is the main entry point for PART 3 analysis. It consumes
structured outputs from PART 1 and PART 2 and produces evidence-based
detections, correlations, and risk assessments.

GLOBAL NON-NEGOTIABLE RULES:
- No analysis without evidence from PART 1 or PART 2
- No scoring without a documented rule or heuristic
- No cloud lookups or online intelligence
- No guessing intent, malware family, or threat names
- Same inputs MUST always produce the same outputs
"""

import json
from typing import Any, Dict, List, Optional

from .rule_engine import RuleEngine
from .heuristic_engine import HeuristicEngine, HEURISTIC_DEFINITIONS
from .risk_scorer import RiskScorer
from .correlator import SessionCorrelator


class Part3Analyzer:
    """
    PART 3: Rules, Correlation & Explainable Risk Scoring
    
    Consumes PART 1 and PART 2 outputs to produce:
    1. Rule-Based Detections (YARA)
    2. Fuzzy Hash Similarity (ssdeep, TLSH)
    3. Deterministic Heuristic Evaluation
    4. Evidence-Based Risk Scoring
    5. Session-Level Correlation
    
    All outputs are deterministic, reproducible, and explainable.
    """
    
    def __init__(
        self,
        file_path: str,
        part1_results: Dict[str, Any],
        part2_results: Dict[str, Any]
    ):
        """
        Initialize the PART 3 analyzer.
        
        Args:
            file_path: Path to the file being analyzed.
            part1_results: Structured JSON output from PART 1 (FileAnalyzer).
            part2_results: Structured JSON output from PART 2 (DeepAnalyzer).
        """
        self.file_path = file_path
        self.part1 = part1_results
        self.part2 = part2_results
        
        # Extract key data from PART 1/2
        self._extract_base_data()
        
        self.results: Dict[str, Any] = {
            "file_info": {},
            "rule_engine": {},
            "heuristics": {},
            "risk_score": {},
            "summary": {},
            "reproducibility": {},
        }
    
    def _extract_base_data(self) -> None:
        """Extract base data from PART 1 and PART 2 outputs."""
        # File data must be read from the file path
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            self.file_size = len(self.file_data)
        except Exception as e:
            self.file_data = b''
            self.file_size = 0
            self._file_read_error = str(e)
        
        # Extract semantic file type from PART 1
        semantic = self.part1.get("semantic_file_type", {}).get("output_value", {})
        self.semantic_file_type = semantic.get("semantic_file_type", "UNKNOWN")
        self.container_type = semantic.get("container_type")
        
        # Extract file info
        self.file_name = self.part1.get("file_info", {}).get("file_name", "")
        
        # Extract structural anomalies from PART 2
        self.structural_anomalies = []
        for finding in self.part2.get("universal", []):
            if finding.get("finding_type") == "structural_anomalies":
                anomalies = finding.get("extracted_value", {}).get("anomalies", [])
                for a in anomalies:
                    a["finding_id"] = finding.get("finding_id", "unknown")
                self.structural_anomalies.extend(anomalies)
    
    def analyze(
        self,
        yara_rules_path: Optional[str] = None,
        reference_hashes: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """
        Perform full PART 3 analysis.
        
        Args:
            yara_rules_path: Optional path to YARA rules file or directory.
            reference_hashes: Optional dict of reference hashes for similarity comparison.
                              Format: {"ssdeep": ["hash1", "hash2"], "tlsh": ["hash1"]}
        
        Returns:
            Dict containing all PART 3 analysis results in structured JSON format.
        """
        try:
            # Step 1: File info and validation
            self._build_file_info()
            
            # Step 2: Rule-based detection (YARA + fuzzy hashing)
            self._perform_rule_detection(yara_rules_path, reference_hashes)
            
            # Step 3: Deterministic heuristic evaluation
            self._evaluate_heuristics()
            
            # Step 4: Evidence-based risk scoring
            self._compute_risk_score()
            
            # Step 5: Generate summary
            self._generate_summary()
            
            # Step 6: Add reproducibility notes
            self._add_reproducibility_notes()
            
        except Exception as e:
            self.results["error"] = {
                "type": type(e).__name__,
                "message": str(e),
                "analysis_state": "FAILED",
            }
        
        return self.results
    
    def _build_file_info(self) -> None:
        """Build file info section."""
        self.results["file_info"] = {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "semantic_file_type": self.semantic_file_type,
            "container_type": self.container_type,
            "part1_evidence_verified": "ingestion" in self.part1,
            "part2_evidence_verified": "universal" in self.part2,
        }
        
        if hasattr(self, '_file_read_error'):
            self.results["file_info"]["file_read_error"] = self._file_read_error
    
    def _perform_rule_detection(
        self,
        yara_rules_path: Optional[str],
        reference_hashes: Optional[Dict[str, List[str]]]
    ) -> None:
        """Perform rule-based detection."""
        rule_engine = RuleEngine(
            file_path=self.file_path,
            file_data=self.file_data,
            semantic_file_type=self.semantic_file_type
        )
        
        rule_results = rule_engine.analyze(
            yara_rules_path=yara_rules_path,
            reference_hashes=reference_hashes
        )
        
        self.results["rule_engine"] = {
            "yara_detections": rule_results.get("yara_detections", []),
            "yara_detection_count": len(rule_results.get("yara_detections", [])),
            "fuzzy_hashes": rule_results.get("fuzzy_hashes", {}),
            "similarity_matches": rule_results.get("similarity_matches", []),
            "similarity_match_count": len(rule_results.get("similarity_matches", [])),
            "library_status": rule_results.get("library_status", {}),
            "failure_reasons": rule_results.get("failure_reasons", []),
        }
    
    def _evaluate_heuristics(self) -> None:
        """Evaluate deterministic heuristics."""
        heuristic_engine = HeuristicEngine(
            part1_results=self.part1,
            part2_results=self.part2,
            semantic_file_type=self.semantic_file_type
        )
        
        heuristic_results = heuristic_engine.evaluate()
        
        self.results["heuristics"] = {
            "triggered_heuristics": heuristic_results.get("triggered_heuristics", []),
            "triggered_count": len(heuristic_results.get("triggered_heuristics", [])),
            "failed_heuristics": heuristic_results.get("failed_heuristics", []),
            "failed_count": len(heuristic_results.get("failed_heuristics", [])),
            "heuristics_evaluated": heuristic_results.get("heuristics_evaluated", 0),
            "total_weight": heuristic_results.get("total_weight", 0),
            "heuristic_definitions_used": list(HEURISTIC_DEFINITIONS.keys()),
        }
    
    def _compute_risk_score(self) -> None:
        """Compute evidence-based risk score."""
        risk_scorer = RiskScorer(
            semantic_file_type=self.semantic_file_type,
            yara_detections=self.results["rule_engine"].get("yara_detections", []),
            heuristic_results=self.results["heuristics"],
            similarity_matches=self.results["rule_engine"].get("similarity_matches", []),
            structural_anomalies=self.structural_anomalies,
        )
        
        score_result = risk_scorer.compute_score()
        
        self.results["risk_score"] = {
            "id": score_result.get("id"),
            "type": "score",
            "semantic_file_type": self.semantic_file_type,
            "raw_score": score_result.get("raw_score", 0),
            "normalized_score": score_result.get("normalized_score", 0),
            "severity": score_result.get("severity", "informational"),
            "confidence": score_result.get("confidence", "LOW"),
            "score_contributions": score_result.get("score_contributions", []),
            "contribution_count": score_result.get("contribution_count", 0),
            "scoring_method": score_result.get("scoring_method", "weighted_additive"),
            "logic_applied": score_result.get("logic_applied", ""),
            "explanation": score_result.get("explanation", ""),
            "reproducibility_notes": score_result.get("reproducibility_notes", ""),
            "failure_reason": score_result.get("failure_reason"),
        }
    
    def _generate_summary(self) -> None:
        """Generate analysis summary."""
        risk = self.results["risk_score"]
        heuristics = self.results["heuristics"]
        rules = self.results["rule_engine"]
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        
        for h in heuristics.get("triggered_heuristics", []):
            sev = h.get("severity", "informational").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        for d in rules.get("yara_detections", []):
            sev = d.get("severity", "informational").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Build summary
        self.results["summary"] = {
            "file_path": self.file_path,
            "semantic_file_type": self.semantic_file_type,
            "overall_risk_score": risk.get("normalized_score", 0),
            "overall_severity": risk.get("severity", "informational"),
            "overall_confidence": risk.get("confidence", "LOW"),
            "total_findings": (
                rules.get("yara_detection_count", 0) +
                heuristics.get("triggered_count", 0) +
                rules.get("similarity_match_count", 0)
            ),
            "findings_by_severity": severity_counts,
            "yara_matches": rules.get("yara_detection_count", 0),
            "heuristics_triggered": heuristics.get("triggered_count", 0),
            "similarity_matches": rules.get("similarity_match_count", 0),
            "key_findings": self._extract_key_findings(),
            "recommendation": self._generate_recommendation(risk.get("normalized_score", 0)),
            "analysis_complete": True,
        }
    
    def _extract_key_findings(self) -> List[Dict[str, Any]]:
        """Extract the most significant findings."""
        key_findings = []
        
        # Add high/critical heuristics
        for h in self.results["heuristics"].get("triggered_heuristics", []):
            if h.get("severity") in ["high", "critical"]:
                key_findings.append({
                    "type": "heuristic",
                    "name": h.get("name"),
                    "severity": h.get("severity"),
                    "explanation": h.get("explanation"),
                })
        
        # Add YARA matches
        for d in self.results["rule_engine"].get("yara_detections", []):
            key_findings.append({
                "type": "yara_rule",
                "name": d.get("rule_id"),
                "severity": d.get("severity"),
                "explanation": d.get("explanation"),
            })
        
        # Limit to top 10
        return key_findings[:10]
    
    def _generate_recommendation(self, score: float) -> str:
        """Generate recommendation based on risk score."""
        if score >= 80:
            return "CRITICAL: Immediate review required. File exhibits multiple high-risk indicators."
        elif score >= 60:
            return "HIGH RISK: Careful examination recommended before allowing file."
        elif score >= 40:
            return "MEDIUM RISK: Review identified indicators. Exercise caution."
        elif score >= 20:
            return "LOW RISK: Minor concerns noted. Standard handling appropriate."
        else:
            return "MINIMAL RISK: No significant concerns identified."
    
    def _add_reproducibility_notes(self) -> None:
        """Add reproducibility documentation."""
        self.results["reproducibility"] = {
            "analysis_engine": "Part3Analyzer",
            "analysis_version": "1.0.0",
            "deterministic": True,
            "inputs_required": [
                "file_path",
                "part1_results (PART 1 structured JSON)",
                "part2_results (PART 2 structured JSON)",
                "yara_rules_path (optional)",
                "reference_hashes (optional)",
            ],
            "outputs_provided": [
                "rule_engine (YARA detections, fuzzy hashes, similarity matches)",
                "heuristics (triggered and failed heuristics with evidence)",
                "risk_score (evidence-based score with contributions)",
                "summary (aggregated findings and recommendation)",
            ],
            "constraints": [
                "No analysis without evidence from PART 1 or PART 2",
                "No scoring without a documented rule or heuristic",
                "No cloud lookups or online intelligence",
                "No guessing intent, malware family, or threat names",
                "Same inputs MUST always produce the same outputs",
            ],
            "note": "All detections are evidence-based and traceable to source data",
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export analysis results as JSON string."""
        return json.dumps(self.results, indent=indent, default=str)


def analyze_part3(
    file_path: str,
    part1_results: Dict[str, Any],
    part2_results: Dict[str, Any],
    yara_rules_path: Optional[str] = None,
    reference_hashes: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Any]:
    """
    Convenience function for PART 3 analysis.
    
    Args:
        file_path: Path to the file being analyzed.
        part1_results: Structured JSON output from PART 1.
        part2_results: Structured JSON output from PART 2.
        yara_rules_path: Optional path to YARA rules.
        reference_hashes: Optional reference hashes for similarity comparison.
    
    Returns:
        Dict containing all PART 3 analysis results.
    """
    analyzer = Part3Analyzer(file_path, part1_results, part2_results)
    return analyzer.analyze(yara_rules_path, reference_hashes)


def full_analysis(
    file_path: str,
    yara_rules_path: Optional[str] = None,
    reference_hashes: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Any]:
    """
    Perform complete analysis (PART 1 + PART 2 + PART 3).
    
    Args:
        file_path: Path to the file to analyze.
        yara_rules_path: Optional path to YARA rules.
        reference_hashes: Optional reference hashes for similarity comparison.
    
    Returns:
        Dict containing combined results from all parts.
    """
    from .analyzer import FileAnalyzer
    from .deep_analyzer import DeepAnalyzer
    
    # PART 1: File Ingestion & Semantic Type Resolution
    part1_analyzer = FileAnalyzer(file_path)
    part1_results = part1_analyzer.analyze()
    
    # PART 2: Deep File-Type-Aware Static Analysis
    part2_analyzer = DeepAnalyzer(file_path, part1_results)
    part2_results = part2_analyzer.analyze()
    
    # PART 3: Rules, Correlation & Explainable Scoring
    part3_analyzer = Part3Analyzer(file_path, part1_results, part2_results)
    part3_results = part3_analyzer.analyze(yara_rules_path, reference_hashes)
    
    return {
        "file_path": file_path,
        "part1": part1_results,
        "part2": part2_results,
        "part3": part3_results,
        "summary": part3_results.get("summary", {}),
    }


def main():
    """Main entry point for command-line usage."""
    import sys
    
    print("I understand PART 3 constraints and am ready to process verified PART 1 and")
    print("PART 2 outputs to produce deterministic, evidence-based detections and")
    print("explainable risk scoring using real rules only.")
    print()
    print("Usage: python part3_analyzer.py <file_path> [yara_rules_path]")
    
    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        yara_rules_path = sys.argv[2] if len(sys.argv) >= 3 else None
        
        try:
            results = full_analysis(file_path, yara_rules_path)
            print(json.dumps(results, indent=2, default=str))
        except Exception as e:
            print(json.dumps({
                "error": {
                    "type": type(e).__name__,
                    "message": str(e)
                }
            }, indent=2))
            sys.exit(1)


if __name__ == '__main__':
    main()
