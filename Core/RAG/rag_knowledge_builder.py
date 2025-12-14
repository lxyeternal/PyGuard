"""
RAG Knowledge Base Builder for Malware Detection.
Builds comprehensive knowledge base from pattern data JSON files.
"""

import os
import sys
import json
import pickle
import logging
import time
import argparse
import multiprocessing
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

import numpy as np

try:
    import faiss
except ImportError:
    faiss = None

try:
    import tqdm
except ImportError:
    tqdm = None

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)


class Config:
    """Configuration for RAG Knowledge Builder."""
    INPUT_JSON_PATH = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "analysis_results",
                                    "optimized_patterns", "patterns_with_cases_id.json")
    OUTPUT_KB_DIR = os.path.join(PYGUARD_ROOT, "Core", "RAG", "rag_knowledge_base")
    PROMPTS_DIR = os.path.join(PYGUARD_ROOT, "Resources", "Prompts", "rag_prompts")
    PARALLEL_PROCESSES = 24
    PARALLEL_ENABLED = True


@dataclass
class PatternKnowledge:
    """Pattern subsequence knowledge extracted by LLM."""
    pattern_id: int
    pattern: List[str]
    pattern_type: str
    support: int
    coverage: Dict
    pattern_embedding: np.ndarray
    semantic_summary: str
    security_assessment: str
    typical_scenarios: List[str]
    benign_characteristics: List[str]
    malware_characteristics: List[str]
    distinction_rules: List[str]
    context_indicators: Dict


@dataclass
class CaseKnowledge:
    """Case-level knowledge with detailed context."""
    sequence_id: int
    filename: str
    label: str
    pattern_id: int
    case_action_sequence: List[Dict]
    code_context: str
    extracted_features: Dict
    similarity_embedding: np.ndarray
    action_sequence_embedding: np.ndarray
    case_summary: str
    key_behaviors: List[str]
    risk_indicators: List[str]


class PromptManager:
    """Manages prompt templates from external files."""

    def __init__(self, prompts_dir: str):
        self.prompts_dir = prompts_dir
        self.templates = {}
        self._load_templates()


    def _load_templates(self):
        """Load all prompt templates from files."""
        template_files = {
            'pattern_analysis': 'pattern_analysis_prompt.txt',
            'case_analysis': 'case_analysis_prompt.txt',
            'malware_detection': 'malware_detection_prompt.txt',
            'pure_pattern_instructions': 'pure_pattern_instructions.txt',
            'distinction_pattern_instructions': 'distinction_pattern_instructions.txt',
            'basic_detection': 'basic_detection_prompt.txt'
        }
        for template_name, filename in template_files.items():
            file_path = os.path.join(self.prompts_dir, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.templates[template_name] = f.read()
            except FileNotFoundError:
                self.templates[template_name] = ""


    def get_template(self, template_name: str) -> str:
        """Get a prompt template by name."""
        return self.templates.get(template_name, "")


    def format_template(self, template_name: str, **kwargs) -> str:
        """Format a template with provided values."""
        template = self.get_template(template_name)
        for key, value in kwargs.items():
            placeholder = "{" + key + "}"
            template = template.replace(placeholder, str(value))
        return template


class RAGKnowledgeBuilder:
    """Enhanced RAG Knowledge Builder for comprehensive pattern analysis."""

    def __init__(self, llm_agent=None, config=None):
        self.config = config or Config()
        from Utils.llmquery import LLMAgent
        self.llm_agent = llm_agent or LLMAgent()
        self.embedding_model = self.llm_agent.embedding_model
        self.prompt_manager = PromptManager(self.config.PROMPTS_DIR)
        self.pattern_knowledge: Dict[int, PatternKnowledge] = {}
        self.case_knowledge: Dict[int, CaseKnowledge] = {}
        self.pattern_to_cases: Dict[int, Dict[str, List[int]]] = {}
        self.pattern_to_pattern_ids: Dict[Tuple[str, ...], List[int]] = {}
        self.pattern_index = None
        self.case_index = None
        self.pattern_embeddings = {}
        self.case_embeddings = {}
        self.lock = None
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)


    def _get_embedding(self, text: str) -> np.ndarray:
        """Get embedding using LLMAgent's unified interface."""
        return self.llm_agent.generate_embedding(text)


    def load_pattern_data(self, json_file_path: str) -> Dict:
        """Load pattern data from JSON file."""
        if not os.path.exists(json_file_path):
            raise FileNotFoundError(f"Pattern data file not found: {json_file_path}")
        with open(json_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)


    def extract_pattern_knowledge(self, pattern_data: Dict) -> PatternKnowledge:
        """Extract comprehensive knowledge about pattern subsequences using LLM."""
        pattern_id = pattern_data['pattern_id']
        pattern = pattern_data['pattern']
        pattern_type = pattern_data['type']
        self.logger.info(f"Extracting knowledge for pattern {pattern_id} (type: {pattern_type})")
        prompt = self._build_pattern_analysis_prompt(pattern_data)
        try:
            response = self.llm_agent.perform_query(
                messages=[
                    {"role": "system", "content": "You are a malware detection expert. Always respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            analysis = json.loads(response)
            pattern_text = ' '.join(pattern)
            pattern_embedding = self._get_embedding(pattern_text)
            return PatternKnowledge(
                pattern_id=pattern_id,
                pattern=pattern,
                pattern_type=pattern_type,
                support=pattern_data['support'],
                coverage=pattern_data['coverage'],
                pattern_embedding=pattern_embedding,
                semantic_summary=analysis.get('semantic_summary', f"Pattern: {' -> '.join(pattern)}"),
                security_assessment=analysis.get('security_assessment', 'Requires analysis'),
                typical_scenarios=analysis.get('typical_scenarios', []),
                benign_characteristics=analysis.get('benign_characteristics', []),
                malware_characteristics=analysis.get('malware_characteristics', []),
                distinction_rules=analysis.get('distinction_rules', []),
                context_indicators=analysis.get('context_indicators', {})
            )
        except Exception as e:
            self.logger.error(f"Failed to extract knowledge for pattern {pattern_id}: {e}")
            pattern_text = ' '.join(pattern)
            pattern_embedding = self._get_embedding(pattern_text)
            return PatternKnowledge(
                pattern_id=pattern_id,
                pattern=pattern,
                pattern_type=pattern_type,
                support=pattern_data['support'],
                coverage=pattern_data['coverage'],
                pattern_embedding=pattern_embedding,
                semantic_summary=f"Pattern: {' -> '.join(pattern)}",
                security_assessment="Requires analysis",
                typical_scenarios=[],
                benign_characteristics=[],
                malware_characteristics=[],
                distinction_rules=[],
                context_indicators={}
            )


    def _build_pattern_analysis_prompt(self, pattern_data: Dict) -> str:
        """Build comprehensive pattern analysis prompt."""
        pattern = pattern_data['pattern']
        pattern_type = pattern_data['type']
        support = pattern_data['support']
        coverage = pattern_data['coverage']
        benign_cases = pattern_data.get('benign_cases', [])
        malware_cases = pattern_data.get('malware_cases', [])
        max_samples = 10
        max_code_length = 200
        benign_examples = ""
        for i, case in enumerate(benign_cases[:max_samples]):
            code_snippet = case.get('code_context', '')[:max_code_length]
            benign_examples += f"\nBenign Example {i+1}:\nFile: {case.get('filename', 'unknown')}\nCode: {code_snippet}...\n"
        malware_examples = ""
        for i, case in enumerate(malware_cases[:max_samples]):
            code_snippet = case.get('code_context', '')[:max_code_length]
            malware_examples += f"\nMalware Example {i+1}:\nFile: {case.get('filename', 'unknown')}\nCode: {code_snippet}...\n"
        template = self.prompt_manager.get_template('pattern_analysis')
        if template:
            return self.prompt_manager.format_template(
                'pattern_analysis',
                PATTERN_SUBSEQUENCE=' -> '.join(pattern),
                PATTERN_TYPE=pattern_type,
                SUPPORT=support,
                COVERAGE=json.dumps(coverage),
                BENIGN_EXAMPLES=benign_examples,
                MALWARE_EXAMPLES=malware_examples
            )
        return f"""Analyze this API pattern for malware detection:
            Pattern: {' -> '.join(pattern)}
            Type: {pattern_type}
            Support: {support}

            Benign examples: {benign_examples}
            Malware examples: {malware_examples}

            Respond in JSON with: semantic_summary, security_assessment, typical_scenarios, benign_characteristics, malware_characteristics, distinction_rules, context_indicators"""


    def extract_case_knowledge(self, case_data: Dict, label: str, pattern_id: int) -> CaseKnowledge:
        """Extract detailed case knowledge."""
        sequence_id = case_data['sequence_id']
        filename = case_data['filename']
        case_action_sequence = case_data['api_sequence']
        code_context = case_data['code_context']
        features = self._extract_case_features(case_data)
        context_embedding = self._get_embedding(code_context)
        action_sequence_list = [api.get('id', '') for api in case_action_sequence if api.get('id')]
        action_sequence_text = ' '.join(action_sequence_list)
        action_sequence_embedding = self._get_embedding(action_sequence_text) if action_sequence_text else np.zeros(self.llm_agent.dimension, dtype=np.float32)
        case_insights = self._extract_case_insights(case_data, label)
        return CaseKnowledge(
            sequence_id=sequence_id,
            filename=filename,
            label=label,
            pattern_id=pattern_id,
            case_action_sequence=case_action_sequence,
            code_context=code_context,
            extracted_features=features,
            similarity_embedding=context_embedding,
            action_sequence_embedding=action_sequence_embedding,
            case_summary=case_insights.get('case_summary', f"Code analysis for {filename}"),
            key_behaviors=case_insights.get('key_behaviors', []),
            risk_indicators=case_insights.get('risk_indicators', [])
        )


    def _extract_case_features(self, case_data: Dict) -> Dict:
        """Extract structured features from case data."""
        code_context = case_data.get('code_context', '')
        api_sequence = case_data.get('api_sequence', [])
        return {
            'action_count': len(api_sequence),
            'unique_actions': len(set(api.get('id', '') for api in api_sequence)),
            'code_length': len(code_context),
            'has_network_urls': any(term in code_context.lower() for term in ['http://', 'https://']),
            'has_file_manipulation': any(term in code_context.lower() for term in ['remove', 'delete', 'unlink']),
            'has_encryption': any(term in code_context.lower() for term in ['encrypt', 'decrypt', 'cipher'])
        }


    def _extract_case_insights(self, case_data: Dict, label: str) -> Dict:
        """Use LLM to extract insights from individual cases."""
        code_context = case_data.get('code_context', '')
        filename = case_data.get('filename', '')
        truncated_code = code_context[:10000]
        template = self.prompt_manager.get_template('case_analysis')
        if template:
            prompt = self.prompt_manager.format_template(
                'case_analysis',
                FILENAME=filename,
                LABEL=label,
                CODE_CONTEXT=truncated_code
            )
        else:
            prompt = f"Analyze this {label} code from {filename}:\n{truncated_code}\n\nProvide JSON: case_summary, key_behaviors, risk_indicators"
        try:
            response = self.llm_agent.perform_query(
                messages=[
                    {"role": "system", "content": "You are a code analysis expert. Respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return json.loads(response)
        except Exception as e:
            self.logger.warning(f"Failed to extract case insights for {filename}: {e}")
            return {}


    def build_knowledge_base(self, json_file_path: str, resume: bool = True):
        """Build comprehensive RAG knowledge base from pattern data."""
        self.logger.info("Starting to build RAG knowledge base...")
        checkpoint_dir = os.path.join(self.config.OUTPUT_KB_DIR, "checkpoints")
        os.makedirs(checkpoint_dir, exist_ok=True)
        checkpoint_file = os.path.join(checkpoint_dir, "build_progress.pkl")
        processed_patterns = set()
        if resume and os.path.exists(checkpoint_file):
            try:
                self.logger.info("Resuming from checkpoint...")
                with open(checkpoint_file, 'rb') as f:
                    checkpoint_data = pickle.load(f)
                    self.pattern_knowledge = checkpoint_data.get('pattern_knowledge', {})
                    self.case_knowledge = checkpoint_data.get('case_knowledge', {})
                    self.pattern_to_cases = checkpoint_data.get('pattern_to_cases', {})
                    self.pattern_to_pattern_ids = checkpoint_data.get('pattern_to_pattern_ids', {})
                    processed_patterns = checkpoint_data.get('processed_patterns', set())
                self.logger.info(f"Loaded checkpoint. Already processed {len(processed_patterns)} patterns.")
            except Exception as e:
                self.logger.warning(f"Failed to load checkpoint: {e}. Starting fresh.")
        data = self.load_pattern_data(json_file_path)
        patterns = data['patterns']
        self.logger.info(f"Loaded {len(patterns)} patterns")
        patterns_to_process = [p for p in patterns if p['pattern_id'] not in processed_patterns]
        self.logger.info(f"Found {len(patterns_to_process)} patterns to process")
        if self.config.PARALLEL_ENABLED and patterns_to_process:
            self._build_knowledge_base_parallel(patterns_to_process, checkpoint_file, processed_patterns)
        else:
            self._build_knowledge_base_sequential(patterns_to_process, checkpoint_file, processed_patterns)
        self._build_vector_indices()
        if os.path.exists(checkpoint_file):
            os.remove(checkpoint_file)
        self.logger.info("RAG knowledge base construction completed!")


    def _build_knowledge_base_sequential(self, patterns_to_process, checkpoint_file, processed_patterns):
        """Sequential processing of patterns."""
        self.logger.info("Using sequential processing mode")
        for i, pattern_data in enumerate(patterns_to_process):
            pattern_id = pattern_data['pattern_id']
            pattern_type = pattern_data['type']
            pattern_subsequence = pattern_data['pattern']
            self.logger.info(f"Processing pattern {pattern_id} ({i+1}/{len(patterns_to_process)})")
            try:
                self.pattern_to_cases[pattern_id] = {"benign": [], "malware": []}
                pattern_key = tuple(pattern_subsequence)
                if pattern_key not in self.pattern_to_pattern_ids:
                    self.pattern_to_pattern_ids[pattern_key] = []
                self.pattern_to_pattern_ids[pattern_key].append(pattern_id)
                pattern_knowledge = self.extract_pattern_knowledge(pattern_data)
                self.pattern_knowledge[pattern_id] = pattern_knowledge
                for label in ['benign', 'malware']:
                    cases = pattern_data.get(f'{label}_cases', [])
                    self.logger.info(f"  Processing {len(cases)} {label} cases")
                    for case_data in cases:
                        case_knowledge = self.extract_case_knowledge(case_data, label, pattern_id)
                        self.case_knowledge[case_knowledge.sequence_id] = case_knowledge
                        self.pattern_to_cases[pattern_id][label].append(case_knowledge.sequence_id)
                processed_patterns.add(pattern_id)
                self._save_checkpoint(checkpoint_file, processed_patterns)
            except Exception as e:
                self.logger.error(f"Error processing pattern {pattern_id}: {e}")
                self._save_checkpoint(checkpoint_file, processed_patterns)
                raise


    def _build_knowledge_base_parallel(self, patterns_to_process, checkpoint_file, processed_patterns):
        """Parallel processing of patterns."""
        self.logger.info(f"Using parallel processing with {self.config.PARALLEL_PROCESSES} processes")
        manager = multiprocessing.Manager()
        self.lock = manager.Lock()
        with ProcessPoolExecutor(max_workers=self.config.PARALLEL_PROCESSES) as executor:
            future_to_pattern = {
                executor.submit(process_pattern_standalone, pattern_data, self.config.PROMPTS_DIR): pattern_data['pattern_id']
                for pattern_data in patterns_to_process
            }
            iterator = as_completed(future_to_pattern)
            if tqdm:
                iterator = tqdm.tqdm(iterator, total=len(future_to_pattern), desc="Processing patterns")
            for future in iterator:
                pattern_id = future_to_pattern[future]
                try:
                    result = future.result()
                    if result:
                        pattern_knowledge, case_knowledge_list, pattern_cases = result
                        with self.lock:
                            self.pattern_knowledge[pattern_id] = pattern_knowledge
                            for case_knowledge in case_knowledge_list:
                                self.case_knowledge[case_knowledge.sequence_id] = case_knowledge
                            self.pattern_to_cases[pattern_id] = pattern_cases
                            pattern_key = tuple(pattern_knowledge.pattern)
                            if pattern_key not in self.pattern_to_pattern_ids:
                                self.pattern_to_pattern_ids[pattern_key] = []
                            self.pattern_to_pattern_ids[pattern_key].append(pattern_id)
                            processed_patterns.add(pattern_id)
                            self._save_checkpoint(checkpoint_file, processed_patterns)
                except Exception as e:
                    self.logger.error(f"Error processing pattern {pattern_id}: {e}")
        manager.shutdown()


    def _build_vector_indices(self):
        """Build FAISS vector indices for similarity search."""
        if faiss is None:
            self.logger.warning("FAISS not installed, skipping index building")
            return
        self.logger.info("Building vector indices...")
        if self.pattern_knowledge:
            pattern_embeddings_list = []
            pattern_ids = []
            for pid, knowledge in self.pattern_knowledge.items():
                pattern_embeddings_list.append(knowledge.pattern_embedding)
                pattern_ids.append(pid)
            if pattern_embeddings_list:
                pattern_embeddings = np.vstack(pattern_embeddings_list)
                self.pattern_index = faiss.IndexFlatIP(pattern_embeddings.shape[1])
                faiss.normalize_L2(pattern_embeddings)
                self.pattern_index.add(pattern_embeddings.astype('float32'))
                self.pattern_embeddings = {pid: emb for pid, emb in zip(pattern_ids, pattern_embeddings)}
        if self.case_knowledge:
            case_embeddings_list = []
            case_ids = []
            for cid, knowledge in self.case_knowledge.items():
                case_embeddings_list.append(knowledge.similarity_embedding)
                case_ids.append(cid)
            case_embeddings = np.vstack(case_embeddings_list)
            self.case_index = faiss.IndexFlatIP(case_embeddings.shape[1])
            faiss.normalize_L2(case_embeddings)
            self.case_index.add(case_embeddings.astype('float32'))
            self.case_embeddings = {cid: emb for cid, emb in zip(case_ids, case_embeddings_list)}


    def save_knowledge_base(self, save_dir: str = None):
        """Save complete knowledge base to directory."""
        save_dir = save_dir or self.config.OUTPUT_KB_DIR
        os.makedirs(save_dir, exist_ok=True)
        self.logger.info(f"Saving knowledge base to {save_dir}")
        with open(os.path.join(save_dir, 'pattern_knowledge.pkl'), 'wb') as f:
            pickle.dump(self.pattern_knowledge, f)
        with open(os.path.join(save_dir, 'case_knowledge.pkl'), 'wb') as f:
            pickle.dump(self.case_knowledge, f)
        with open(os.path.join(save_dir, 'embeddings_and_mappings.pkl'), 'wb') as f:
            pickle.dump({
                'pattern_embeddings': self.pattern_embeddings,
                'case_embeddings': self.case_embeddings,
                'pattern_to_cases': self.pattern_to_cases,
                'pattern_to_pattern_ids': self.pattern_to_pattern_ids
            }, f)
        if self.pattern_index is not None:
            faiss.write_index(self.pattern_index, os.path.join(save_dir, 'pattern_index.faiss'))
        if self.case_index is not None:
            faiss.write_index(self.case_index, os.path.join(save_dir, 'case_index.faiss'))
        metadata = {
            'total_patterns': len(self.pattern_knowledge),
            'total_cases': len(self.case_knowledge),
            'embedding_model': self.embedding_model
        }
        with open(os.path.join(save_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        self.logger.info(f"Knowledge base saved to {save_dir}")


    def _save_checkpoint(self, checkpoint_file: str, processed_patterns: set):
        """Save current progress to checkpoint file."""
        checkpoint_data = {
            'pattern_knowledge': self.pattern_knowledge,
            'case_knowledge': self.case_knowledge,
            'pattern_to_cases': self.pattern_to_cases,
            'pattern_to_pattern_ids': self.pattern_to_pattern_ids,
            'processed_patterns': processed_patterns
        }
        with open(checkpoint_file, 'wb') as f:
            pickle.dump(checkpoint_data, f)


    def get_statistics(self) -> Dict:
        """Get knowledge base statistics."""
        pattern_types = defaultdict(int)
        for knowledge in self.pattern_knowledge.values():
            pattern_types[knowledge.pattern_type] += 1
        case_labels = defaultdict(int)
        for knowledge in self.case_knowledge.values():
            case_labels[knowledge.label] += 1
        return {
            "total_patterns": len(self.pattern_knowledge),
            "pattern_types": dict(pattern_types),
            "total_cases": len(self.case_knowledge),
            "case_labels": dict(case_labels)
        }


def process_pattern_standalone(pattern_data, prompts_dir):
    """Standalone pattern processing function for parallel execution."""
    from Utils.llmquery import LLMAgent
    pattern_id = pattern_data['pattern_id']
    try:
        llm_agent = LLMAgent()
        prompt_manager = PromptManager(prompts_dir)
        pattern = pattern_data['pattern']
        pattern_text = ' '.join(pattern)
        pattern_embedding = llm_agent.generate_embedding(pattern_text)
        pattern_knowledge = PatternKnowledge(
            pattern_id=pattern_id,
            pattern=pattern,
            pattern_type=pattern_data['type'],
            support=pattern_data['support'],
            coverage=pattern_data['coverage'],
            pattern_embedding=pattern_embedding,
            semantic_summary=f"Pattern: {' -> '.join(pattern)}",
            security_assessment="Requires analysis",
            typical_scenarios=[],
            benign_characteristics=[],
            malware_characteristics=[],
            distinction_rules=[],
            context_indicators={}
        )
        case_knowledge_list = []
        pattern_cases = {"benign": [], "malware": []}
        for label in ['benign', 'malware']:
            for case_data in pattern_data.get(f'{label}_cases', []):
                sequence_id = case_data['sequence_id']
                code_context = case_data['code_context']
                api_sequence = case_data['api_sequence']
                context_embedding = llm_agent.generate_embedding(code_context)
                action_ids = [api.get('id', '') for api in api_sequence if api.get('id')]
                action_embedding = llm_agent.generate_embedding(' '.join(action_ids)) if action_ids else np.zeros(llm_agent.dimension)
                case_knowledge = CaseKnowledge(
                    sequence_id=sequence_id,
                    filename=case_data['filename'],
                    label=label,
                    pattern_id=pattern_id,
                    case_action_sequence=api_sequence,
                    code_context=code_context,
                    extracted_features={},
                    similarity_embedding=context_embedding,
                    action_sequence_embedding=action_embedding,
                    case_summary=f"Code from {case_data['filename']}",
                    key_behaviors=[],
                    risk_indicators=[]
                )
                case_knowledge_list.append(case_knowledge)
                pattern_cases[label].append(sequence_id)
        return pattern_knowledge, case_knowledge_list, pattern_cases
    except Exception as e:
        print(f"Error processing pattern {pattern_id}: {e}")
        return None


def main():
    """Main function for building RAG knowledge base."""
    parser = argparse.ArgumentParser(description='Build RAG knowledge base')
    parser.add_argument('--processes', type=int, default=Config.PARALLEL_PROCESSES,
                        help=f'Number of parallel processes (default: {Config.PARALLEL_PROCESSES})')
    parser.add_argument('--no-parallel', action='store_true',
                        help='Disable parallel processing')
    parser.add_argument('--input', type=str, default=Config.INPUT_JSON_PATH,
                        help='Input JSON file path')
    parser.add_argument('--output', type=str, default=Config.OUTPUT_KB_DIR,
                        help='Output knowledge base directory')
    args = parser.parse_args()
    Config.PARALLEL_PROCESSES = args.processes
    Config.PARALLEL_ENABLED = not args.no_parallel
    Config.INPUT_JSON_PATH = args.input
    Config.OUTPUT_KB_DIR = args.output
    print("=== Building RAG Knowledge Base ===")
    print(f"Input: {Config.INPUT_JSON_PATH}")
    print(f"Output: {Config.OUTPUT_KB_DIR}")
    print(f"Prompts: {Config.PROMPTS_DIR}")
    print(f"Parallel: {Config.PARALLEL_ENABLED} ({Config.PARALLEL_PROCESSES} processes)")
    if not os.path.exists(Config.INPUT_JSON_PATH):
        print(f"Error: Input file not found: {Config.INPUT_JSON_PATH}")
        return
    os.makedirs(Config.PROMPTS_DIR, exist_ok=True)
    try:
        start_time = time.time()
        builder = RAGKnowledgeBuilder()
        builder.build_knowledge_base(Config.INPUT_JSON_PATH, resume=True)
        builder.save_knowledge_base(Config.OUTPUT_KB_DIR)
        stats = builder.get_statistics()
        print("\n=== Statistics ===")
        for key, value in stats.items():
            print(f"{key}: {value}")
        print(f"\nCompleted in {time.time() - start_time:.2f} seconds")
        print(f"Saved to: {Config.OUTPUT_KB_DIR}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
