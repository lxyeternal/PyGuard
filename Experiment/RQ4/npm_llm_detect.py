"""
Run LLM-based malware detection on NPM packages.
Supports direct GPT-4.1 detection and RAG-enhanced detection.

Detection Methods:
    - gpt-4.1: Direct LLM analysis without additional knowledge
    - pyguard: RAG-enhanced LLM analysis with pattern knowledge
"""
import os
import sys
import json
import glob
import pickle
import logging
import multiprocessing
from pathlib import Path
from typing import Dict, Any, Optional

sys.path.append(str(Path(__file__).parent.parent))
from utils.llmquery import LLMAgent


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("NPMLLMDetect")

PYGUARD_ROOT = Path(__file__).parent.parent

NUM_PROCESSES = 5

RAG_KB_DIR = PYGUARD_ROOT / "Core" / "RAG" / "database" / "rag_knowledge_base"


class PatternKnowledge:
    """Pattern-level knowledge extracted by LLM."""
    def __init__(self, pattern_id, pattern, pattern_type, support, coverage,
                 semantic_summary, security_assessment, typical_scenarios,
                 benign_characteristics, malware_characteristics,
                 distinction_rules, context_indicators):
        self.pattern_id = pattern_id
        self.pattern = pattern
        self.pattern_type = pattern_type
        self.support = support
        self.coverage = coverage
        self.semantic_summary = semantic_summary
        self.security_assessment = security_assessment
        self.typical_scenarios = typical_scenarios
        self.benign_characteristics = benign_characteristics
        self.malware_characteristics = malware_characteristics
        self.distinction_rules = distinction_rules
        self.context_indicators = context_indicators


class CaseKnowledge:
    """Case-level knowledge with detailed context."""
    def __init__(self, sequence_id, filename, label, pattern_id, api_sequence, code_context,
                 extracted_features, similarity_embedding, case_summary, key_behaviors, risk_indicators):
        self.sequence_id = sequence_id
        self.filename = filename
        self.label = label
        self.pattern_id = pattern_id
        self.api_sequence = api_sequence
        self.code_context = code_context
        self.extracted_features = extracted_features
        self.similarity_embedding = similarity_embedding
        self.case_summary = case_summary
        self.key_behaviors = key_behaviors
        self.risk_indicators = risk_indicators


def load_rag_knowledge() -> Optional[Dict]:
    """Load RAG knowledge base."""
    logger.info(f"Loading RAG knowledge base: {RAG_KB_DIR}")

    knowledge = {}

    try:
        with open(RAG_KB_DIR / 'pattern_knowledge.pkl', 'rb') as f:
            knowledge['pattern_knowledge'] = pickle.load(f)

        with open(RAG_KB_DIR / 'case_knowledge.pkl', 'rb') as f:
            knowledge['case_knowledge'] = pickle.load(f)

        with open(RAG_KB_DIR / 'embeddings_and_mappings.pkl', 'rb') as f:
            embeddings_and_mappings = pickle.load(f)
            knowledge['pattern_embeddings'] = embeddings_and_mappings.get('pattern_embeddings', {})
            knowledge['case_embeddings'] = embeddings_and_mappings.get('case_embeddings', {})
            knowledge['pattern_to_cases'] = embeddings_and_mappings.get('pattern_to_cases', {})
            knowledge['api_sequence_to_patterns'] = embeddings_and_mappings.get('api_sequence_to_patterns', {})

        with open(RAG_KB_DIR / 'metadata.json', 'r') as f:
            knowledge['metadata'] = json.load(f)

        logger.info(f"Loaded RAG knowledge: {len(knowledge['pattern_knowledge'])} patterns, "
                    f"{len(knowledge['case_knowledge'])} cases")
        return knowledge

    except Exception as e:
        logger.error(f"Failed to load RAG knowledge base: {e}")
        return None


def extract_rag_knowledge_summary() -> str:
    """Extract summary knowledge from RAG knowledge base."""
    rag_knowledge = load_rag_knowledge()

    if not rag_knowledge:
        logger.error("Cannot load RAG knowledge base")
        return ""

    malicious_characteristics = []
    benign_characteristics = []
    distinction_rules = []
    risk_indicators = []
    malicious_behaviors = []

    for pattern in rag_knowledge['pattern_knowledge'].values():
        if pattern.pattern_type in ['pure_malware_only', 'distinction_malware_biased']:
            malicious_characteristics.extend(pattern.malware_characteristics)
            if pattern.security_assessment:
                malicious_behaviors.append(pattern.security_assessment)
        elif pattern.pattern_type in ['pure_benign_only', 'distinction_benign_biased']:
            benign_characteristics.extend(pattern.benign_characteristics)

        distinction_rules.extend(pattern.distinction_rules)

    malware_cases = [c for c in rag_knowledge['case_knowledge'].values() if c.label == 'malware']
    for case in malware_cases:
        risk_indicators.extend(case.risk_indicators)

    malicious_characteristics = list(set(malicious_characteristics))[:100]
    malicious_behaviors = list(set(malicious_behaviors))[:100]
    risk_indicators = list(set(risk_indicators))[:100]

    knowledge_summary = """
Based on extensive analysis of code patterns in packages, the following knowledge points can help identify malicious JavaScript/NPM code:

## Typical characteristics of malicious code:
{malicious_features}

## Typical malicious behaviors:
{malicious_behaviors}

## Key risk indicators:
{risk_indicators}

When analyzing the code above, please refer to these knowledge points to determine if the code contains malicious behavior.
""".format(
        malicious_features="\n".join(f"- {feature}" for feature in malicious_characteristics),
        malicious_behaviors="\n".join(f"- {behavior}" for behavior in malicious_behaviors),
        risk_indicators="\n".join(f"- {indicator}" for indicator in risk_indicators)
    )

    logger.info("RAG knowledge summary prepared")
    return knowledge_summary


def build_direct_prompt(code_content: str, file_type: str) -> str:
    """Build prompt for direct detection without RAG knowledge."""
    return f"""
Please analyze the following {file_type} code and determine if it contains malicious behavior:

```javascript
{code_content}
```

Please respond in JSON format with the following fields:
{{
  "is_malicious": true/false,
  "malicious_behavior": "If the code contains malicious behavior, please explain in detail; otherwise leave empty"
}}
"""


def build_enhanced_prompt(code_content: str, rag_knowledge_summary: str, file_type: str) -> str:
    """Build prompt with RAG knowledge enhancement."""
    return f"""
Please analyze the following {file_type} code and determine if it contains malicious behavior:

```javascript
{code_content}
```

{rag_knowledge_summary}

Please respond in JSON format with the following fields:
{{
  "is_malicious": true/false,
  "malicious_behavior": "If the code contains malicious behavior, please explain in detail; otherwise leave empty"
}}
"""


def analyze_package_files(package_path: str, rag_knowledge_summary: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Analyze all JS files in a package."""
    js_files = glob.glob(f"{package_path}/**/*.js", recursive=True)
    package_json_files = glob.glob(f"{package_path}/**/package.json", recursive=True)

    if not js_files and not package_json_files:
        logger.warning(f"No JS files or package.json found in {package_path}")
        return {
            "package_name": os.path.basename(package_path),
            "is_malicious": False,
            "files_analyzed": 0,
            "malicious_files": 0,
            "file_results": []
        }

    llm_agent = LLMAgent()
    file_results = []

    all_files = [(f, "js") for f in js_files] + [(f, "package.json") for f in package_json_files]

    for file_path, file_type in all_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            if not code_content.strip():
                file_results.append({
                    "file_path": file_path,
                    "relative_path": os.path.relpath(file_path, package_path),
                    "file_type": file_type,
                    "is_malicious": False,
                    "malicious_behavior": ""
                })
                continue

            if rag_knowledge_summary:
                prompt = build_enhanced_prompt(code_content, rag_knowledge_summary, file_type)
            else:
                prompt = build_direct_prompt(code_content, file_type)

            system_content = ("You are a professional JavaScript/NPM malicious code analysis expert. "
                              "Analyze the following code and determine if it contains malicious behavior.")

            messages = [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ]

            response = llm_agent.perform_query(
                messages=messages,
                response_format={"type": "json_object"}
            )

            result = json.loads(response)

            file_results.append({
                "file_path": file_path,
                "relative_path": os.path.relpath(file_path, package_path),
                "file_type": file_type,
                "is_malicious": result.get("is_malicious", False),
                "malicious_behavior": result.get("malicious_behavior", "")
            })

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return None

    malicious_files = sum(1 for fr in file_results if fr["is_malicious"])

    return {
        "package_name": os.path.basename(package_path),
        "is_malicious": malicious_files > 0,
        "files_analyzed": len(file_results),
        "malicious_files": malicious_files,
        "file_results": file_results
    }


def process_package_worker(args) -> Dict[str, Any]:
    """Worker function for processing a single package."""
    package_path, direct_output_file, rag_output_file, true_label, rag_knowledge_summary = args

    try:
        results = {}

        # Direct detection (without RAG)
        if not os.path.exists(direct_output_file) or os.path.getsize(direct_output_file) == 0:
            logger.info(f"Direct detection: {os.path.basename(package_path)}")
            direct_result = analyze_package_files(package_path, rag_knowledge_summary=None)

            if direct_result is not None:
                direct_result["true_label"] = true_label
                with open(direct_output_file, 'w', encoding='utf-8') as f:
                    json.dump(direct_result, f, ensure_ascii=False, indent=2)
                results["direct"] = "processed"
            else:
                results["direct"] = "error"
        else:
            results["direct"] = "skipped"

        # RAG-enhanced detection
        if not os.path.exists(rag_output_file) or os.path.getsize(rag_output_file) == 0:
            logger.info(f"RAG-enhanced detection: {os.path.basename(package_path)}")
            rag_result = analyze_package_files(package_path, rag_knowledge_summary=rag_knowledge_summary)

            if rag_result is not None:
                rag_result["true_label"] = true_label
                with open(rag_output_file, 'w', encoding='utf-8') as f:
                    json.dump(rag_result, f, ensure_ascii=False, indent=2)
                results["rag"] = "processed"
            else:
                results["rag"] = "error"
        else:
            results["rag"] = "skipped"

        return {
            "status": "completed",
            "package": os.path.basename(package_path),
            "results": results
        }

    except Exception as e:
        logger.error(f"Error processing package {package_path}: {e}")
        return {
            "status": "error",
            "package": os.path.basename(package_path),
            "error": str(e)
        }


def main():
    """Main function."""
    # Paths
    dataset_dir = PYGUARD_ROOT.parent / "Dataset" / "npm_data"
    output_dir = PYGUARD_ROOT / "Experiment" / "Results" / "NPM"

    benign_path = dataset_dir / "unzip_benign"
    malware_path = dataset_dir / "unzip_malware"

    # Output directories
    direct_output_base = output_dir / "gpt-4.1"
    rag_output_base = output_dir / "pyguard"

    os.makedirs(direct_output_base / "benign", exist_ok=True)
    os.makedirs(direct_output_base / "malware", exist_ok=True)
    os.makedirs(rag_output_base / "benign", exist_ok=True)
    os.makedirs(rag_output_base / "malware", exist_ok=True)

    logger.info(f"Dataset: {dataset_dir}")
    logger.info(f"Output: {output_dir}")
    logger.info(f"Workers: {NUM_PROCESSES}")

    # Load RAG knowledge
    logger.info("Extracting RAG knowledge summary...")
    rag_knowledge_summary = extract_rag_knowledge_summary()

    # Collect tasks
    tasks = []

    if benign_path.exists():
        benign_folders = [f for f in os.listdir(benign_path) if os.path.isdir(benign_path / f)]
        for folder in benign_folders:
            package_path = str(benign_path / folder)
            direct_output = str(direct_output_base / "benign" / f"{folder}.json")
            rag_output = str(rag_output_base / "benign" / f"{folder}.json")
            tasks.append((package_path, direct_output, rag_output, "benign", rag_knowledge_summary))

    if malware_path.exists():
        malware_folders = [f for f in os.listdir(malware_path) if os.path.isdir(malware_path / f)]
        for folder in malware_folders:
            package_path = str(malware_path / folder)
            direct_output = str(direct_output_base / "malware" / f"{folder}.json")
            rag_output = str(rag_output_base / "malware" / f"{folder}.json")
            tasks.append((package_path, direct_output, rag_output, "malware", rag_knowledge_summary))

    total_tasks = len(tasks)
    logger.info(f"Found {total_tasks} packages to process")

    # Process packages
    stats = {
        "direct": {"processed": 0, "skipped": 0, "errors": 0},
        "rag": {"processed": 0, "skipped": 0, "errors": 0}
    }

    with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
        for i, result in enumerate(pool.imap_unordered(process_package_worker, tasks)):
            if result["status"] == "completed":
                for method in ["direct", "rag"]:
                    status = result["results"].get(method, "error")
                    if status == "processed":
                        stats[method]["processed"] += 1
                    elif status == "skipped":
                        stats[method]["skipped"] += 1
                    else:
                        stats[method]["errors"] += 1
                logger.info(f"Processed {result['package']} [{i+1}/{total_tasks}]")
            else:
                stats["direct"]["errors"] += 1
                stats["rag"]["errors"] += 1
                logger.error(f"Error: {result['package']} - {result.get('error', 'Unknown')} [{i+1}/{total_tasks}]")

    logger.info("All packages processed!")
    logger.info(f"Direct (gpt-4.1): processed={stats['direct']['processed']}, "
                f"skipped={stats['direct']['skipped']}, errors={stats['direct']['errors']}")
    logger.info(f"RAG (pyguard): processed={stats['rag']['processed']}, "
                f"skipped={stats['rag']['skipped']}, errors={stats['rag']['errors']}")


if __name__ == "__main__":
    main()
