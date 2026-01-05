"""
Risk Scorer - PART 3: Evidence-Based Risk Scoring

This module implements deterministic, evidence-based risk scoring
using weighted additive logic. All scores are traceable to specific
rule matches, heuristic triggers, and structural anomalies.

Scoring is transparent, reproducible, and never uses black-box methods.
"""

import math
from typing import Any, Dict, List, Optional, Tuple


# Severity level thresholds and weights
SEVERITY_LEVELS = {
    "critical": {"min_score": 80, "weight_multiplier": 2.0, "label": "Critical"},
    "high": {"min_score": 60, "weight_multiplier": 1.5, "label": "High"},
    "medium": {"min_score": 40, "weight_multiplier": 1.2, "label": "Medium"},
    "low": {"min_score": 20, "weight_multiplier": 1.0, "label": "Low"},
    "informational": {"min_score": 0, "weight_multiplier": 0.5, "label": "Informational"},
}


# Score contribution weights for different detection types
DETECTION_TYPE_WEIGHTS = {
    "rule": 1.0,       # YARA rules
    "heuristic": 1.0,  # Heuristic triggers
    "correlation": 0.5,  # Similarity matches
    "structural_anomaly": 0.8,  # Structural anomalies from PART 2
}


# Normalization parameters for the logistic function
# NORMALIZATION_STEEPNESS controls how quickly scores transition from low to high
# Lower values = gentler curve, higher values = sharper transition
NORMALIZATION_STEEPNESS = 0.05

# NORMALIZATION_MIDPOINT is the raw score at which the normalized score is 50
# This is the "inflection point" of the scoring curve
NORMALIZATION_MIDPOINT = 50


def generate_score_id(counter: int) -> str:
    """Generate a unique score ID."""
    return f"S{counter:04d}_risk_score"


class RiskScorer:
    """
    Evidence-based risk scoring engine for PART 3.
    
    Computes risk scores using weighted additive logic where each
    score contribution is traceable to specific evidence from
    rule matches, heuristic triggers, and structural anomalies.
    """
    
    def __init__(
        self,
        semantic_file_type: str,
        yara_detections: Optional[List[Dict]] = None,
        heuristic_results: Optional[Dict] = None,
        similarity_matches: Optional[List[Dict]] = None,
        structural_anomalies: Optional[List[Dict]] = None,
    ):
        """
        Initialize the risk scorer.
        
        Args:
            semantic_file_type: Semantic file type from PART 1.
            yara_detections: List of YARA rule detections.
            heuristic_results: Dict containing triggered/failed heuristics.
            similarity_matches: List of fuzzy hash similarity matches.
            structural_anomalies: List of structural anomalies from PART 2.
        """
        self.semantic_file_type = semantic_file_type
        self.yara_detections = yara_detections or []
        self.heuristic_results = heuristic_results or {}
        self.similarity_matches = similarity_matches or []
        self.structural_anomalies = structural_anomalies or []
        
        self.score_counter = 0
        self.score_contributions: List[Dict[str, Any]] = []
    
    def _next_score_id(self) -> str:
        """Generate next score ID."""
        self.score_counter += 1
        return generate_score_id(self.score_counter)
    
    def _severity_to_weight(self, severity: str) -> float:
        """Convert severity level to weight multiplier."""
        severity_lower = severity.lower()
        if severity_lower in SEVERITY_LEVELS:
            return SEVERITY_LEVELS[severity_lower]["weight_multiplier"]
        return 1.0
    
    def _score_to_severity(self, score: float) -> str:
        """Convert numeric score to severity level."""
        for level, config in sorted(
            SEVERITY_LEVELS.items(),
            key=lambda x: x[1]["min_score"],
            reverse=True
        ):
            if score >= config["min_score"]:
                return level
        return "informational"
    
    def _calculate_confidence(self, contributions: List[Dict]) -> str:
        """
        Calculate overall confidence based on score contributions.
        
        Args:
            contributions: List of score contribution dicts.
        
        Returns:
            Confidence level string (HIGH, MEDIUM, LOW).
        """
        if not contributions:
            return "LOW"
        
        # Count confidence levels
        high_count = sum(1 for c in contributions if c.get("confidence") == "HIGH")
        medium_count = sum(1 for c in contributions if c.get("confidence") == "MEDIUM")
        low_count = sum(1 for c in contributions if c.get("confidence") == "LOW")
        
        total = len(contributions)
        
        # Determine overall confidence
        if high_count / total >= 0.7:
            return "HIGH"
        elif (high_count + medium_count) / total >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def compute_score(self) -> Dict[str, Any]:
        """
        Compute the overall risk score.
        
        Returns:
            Dict containing score details, contributions, and explanation.
        """
        self.score_contributions = []
        
        # Process YARA detections
        for detection in self.yara_detections:
            self._add_yara_contribution(detection)
        
        # Process heuristic triggers
        triggered = self.heuristic_results.get("triggered_heuristics", [])
        for heuristic in triggered:
            self._add_heuristic_contribution(heuristic)
        
        # Process similarity matches
        for match in self.similarity_matches:
            self._add_similarity_contribution(match)
        
        # Process structural anomalies
        for anomaly in self.structural_anomalies:
            self._add_structural_contribution(anomaly)
        
        # Calculate raw score (sum of weighted contributions)
        raw_score = sum(c["weighted_score"] for c in self.score_contributions)
        
        # Normalize to 0-100 scale using sigmoid-like function
        # This prevents runaway scores while maintaining sensitivity
        normalized_score = self._normalize_score(raw_score)
        
        # Determine severity level
        severity = self._score_to_severity(normalized_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(self.score_contributions)
        
        # Build result
        result = {
            "id": self._next_score_id(),
            "type": "score",
            "semantic_file_type": self.semantic_file_type,
            "raw_score": round(raw_score, 2),
            "normalized_score": round(normalized_score, 2),
            "severity": severity,
            "confidence": confidence,
            "score_contributions": self.score_contributions,
            "contribution_count": len(self.score_contributions),
            "scoring_method": "weighted_additive",
            "logic_applied": self._build_scoring_explanation(),
            "explanation": self._build_human_explanation(normalized_score, severity),
            "reproducibility_notes": "Deterministic scoring based on evidence from rules and heuristics",
            "failure_reason": None if self.score_contributions else "No evidence to score",
        }
        
        return result
    
    def _add_yara_contribution(self, detection: Dict) -> None:
        """Add score contribution from YARA detection."""
        base_weight = DETECTION_TYPE_WEIGHTS["rule"]
        severity = detection.get("severity", "informational")
        severity_multiplier = self._severity_to_weight(severity)
        
        # YARA rules contribute base score of 20, modified by severity
        base_score = 20
        weighted_score = base_score * base_weight * severity_multiplier
        
        self.score_contributions.append({
            "source_id": detection.get("id", "unknown"),
            "source_type": "rule",
            "source_name": detection.get("rule_id", "unknown"),
            "base_score": base_score,
            "weight": base_weight,
            "severity_multiplier": severity_multiplier,
            "weighted_score": weighted_score,
            "confidence": detection.get("confidence", "MEDIUM"),
            "evidence_reference": f"YARA rule: {detection.get('rule_id', 'unknown')}",
            "explanation": f"YARA rule match contributes {weighted_score:.1f} points",
        })
    
    def _add_heuristic_contribution(self, heuristic: Dict) -> None:
        """Add score contribution from heuristic trigger."""
        base_weight = DETECTION_TYPE_WEIGHTS["heuristic"]
        severity = heuristic.get("severity", "informational")
        severity_multiplier = self._severity_to_weight(severity)
        
        # Use the heuristic's defined weight as base score
        base_score = heuristic.get("weight", 10)
        weighted_score = base_score * base_weight * severity_multiplier
        
        self.score_contributions.append({
            "source_id": heuristic.get("id", "unknown"),
            "source_type": "heuristic",
            "source_name": heuristic.get("name", "unknown"),
            "base_score": base_score,
            "weight": base_weight,
            "severity_multiplier": severity_multiplier,
            "weighted_score": weighted_score,
            "confidence": heuristic.get("confidence", "MEDIUM"),
            "evidence_reference": f"Heuristic: {heuristic.get('name', 'unknown')}",
            "explanation": f"Heuristic trigger contributes {weighted_score:.1f} points",
        })
    
    def _add_similarity_contribution(self, match: Dict) -> None:
        """Add score contribution from similarity match."""
        base_weight = DETECTION_TYPE_WEIGHTS["correlation"]
        
        # Similarity contributes based on similarity percentage
        similarity = match.get("similarity_percentage", 0)
        base_score = similarity / 2  # Max 50 points for 100% similarity
        weighted_score = base_score * base_weight
        
        self.score_contributions.append({
            "source_id": match.get("id", "unknown"),
            "source_type": "correlation",
            "source_name": f"{match.get('algorithm', 'unknown')}_similarity",
            "base_score": base_score,
            "weight": base_weight,
            "severity_multiplier": 1.0,
            "weighted_score": weighted_score,
            "confidence": match.get("confidence", "MEDIUM"),
            "evidence_reference": f"Similarity: {match.get('algorithm', 'unknown')} ({similarity:.1f}%)",
            "explanation": f"Similarity match ({similarity:.1f}%) contributes {weighted_score:.1f} points",
        })
    
    def _add_structural_contribution(self, anomaly: Dict) -> None:
        """Add score contribution from structural anomaly."""
        base_weight = DETECTION_TYPE_WEIGHTS["structural_anomaly"]
        
        # Structural anomalies contribute based on type
        anomaly_type = anomaly.get("type", "unknown")
        
        # Assign base scores based on anomaly type
        type_scores = {
            "null_padding": 5,
            "trailing_data": 15,
            "entropy_anomaly": 10,
            "high_entropy": 15,
            "low_entropy": 10,
        }
        
        base_score = type_scores.get(anomaly_type, 10)
        weighted_score = base_score * base_weight
        
        self.score_contributions.append({
            "source_id": anomaly.get("finding_id", "unknown"),
            "source_type": "structural_anomaly",
            "source_name": anomaly_type,
            "base_score": base_score,
            "weight": base_weight,
            "severity_multiplier": 1.0,
            "weighted_score": weighted_score,
            "confidence": "MEDIUM",
            "evidence_reference": f"Structural anomaly: {anomaly_type}",
            "explanation": f"Structural anomaly ({anomaly_type}) contributes {weighted_score:.1f} points",
        })
    
    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalize raw score to 0-100 scale.
        
        Uses a modified sigmoid function to prevent runaway scores
        while maintaining sensitivity to differences.
        
        Args:
            raw_score: Raw additive score.
        
        Returns:
            Normalized score (0-100).
        """
        if raw_score <= 0:
            return 0.0
        
        # Use logistic function: 100 / (1 + e^(-k*(x-x0)))
        # Parameters are defined as module-level constants for maintainability
        normalized = 100 / (1 + math.exp(
            -NORMALIZATION_STEEPNESS * (raw_score - NORMALIZATION_MIDPOINT)
        ))
        
        # Clamp to 0-100
        return max(0, min(100, normalized))
    
    def _build_scoring_explanation(self) -> str:
        """Build detailed scoring logic explanation."""
        if not self.score_contributions:
            return "No evidence available for scoring"
        
        parts = ["Score computed using weighted additive logic:"]
        
        for contrib in self.score_contributions[:5]:  # Limit to top 5
            parts.append(
                f"- {contrib['source_type']}: {contrib['source_name']} "
                f"({contrib['weighted_score']:.1f} points)"
            )
        
        if len(self.score_contributions) > 5:
            parts.append(f"- ... and {len(self.score_contributions) - 5} more contributions")
        
        return "; ".join(parts)
    
    def _build_human_explanation(self, score: float, severity: str) -> str:
        """Build human-readable score explanation."""
        if score == 0:
            return "No risk indicators detected. File appears benign based on available evidence."
        
        severity_text = SEVERITY_LEVELS.get(severity, {}).get("label", severity.title())
        
        # Count contribution types
        type_counts = {}
        for contrib in self.score_contributions:
            t = contrib["source_type"]
            type_counts[t] = type_counts.get(t, 0) + 1
        
        contribution_summary = ", ".join(
            f"{count} {t}" for t, count in type_counts.items()
        )
        
        if score >= 80:
            risk_text = "Critical risk level"
            action_text = "Immediate review recommended"
        elif score >= 60:
            risk_text = "High risk level"
            action_text = "Careful examination recommended"
        elif score >= 40:
            risk_text = "Medium risk level"
            action_text = "Review suspicious indicators"
        elif score >= 20:
            risk_text = "Low risk level"
            action_text = "Minor concerns noted"
        else:
            risk_text = "Minimal risk"
            action_text = "No immediate concerns"
        
        return (
            f"{risk_text}: Score {score:.1f}/100 ({severity_text}). "
            f"Based on {contribution_summary}. {action_text}."
        )


def compute_risk_score(
    semantic_file_type: str,
    yara_detections: Optional[List[Dict]] = None,
    heuristic_results: Optional[Dict] = None,
    similarity_matches: Optional[List[Dict]] = None,
    structural_anomalies: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Convenience function to compute risk score.
    
    Args:
        semantic_file_type: Semantic file type from PART 1.
        yara_detections: List of YARA rule detections.
        heuristic_results: Dict containing triggered/failed heuristics.
        similarity_matches: List of fuzzy hash similarity matches.
        structural_anomalies: List of structural anomalies from PART 2.
    
    Returns:
        Dict containing score details and contributions.
    """
    scorer = RiskScorer(
        semantic_file_type=semantic_file_type,
        yara_detections=yara_detections,
        heuristic_results=heuristic_results,
        similarity_matches=similarity_matches,
        structural_anomalies=structural_anomalies,
    )
    return scorer.compute_score()


def explain_score(score_result: Dict[str, Any]) -> str:
    """
    Generate detailed explanation of a score result.
    
    Args:
        score_result: Score result from compute_risk_score.
    
    Returns:
        Human-readable explanation string.
    """
    lines = [
        f"Risk Assessment: {score_result.get('severity', 'unknown').upper()}",
        f"Score: {score_result.get('normalized_score', 0):.1f}/100",
        f"Confidence: {score_result.get('confidence', 'unknown')}",
        "",
        "Score Breakdown:",
    ]
    
    contributions = score_result.get("score_contributions", [])
    for contrib in contributions:
        lines.append(
            f"  [{contrib.get('source_type', '?')}] {contrib.get('source_name', '?')}: "
            f"+{contrib.get('weighted_score', 0):.1f} pts"
        )
    
    lines.extend([
        "",
        f"Summary: {score_result.get('explanation', 'No explanation available')}",
    ])
    
    return "\n".join(lines)
