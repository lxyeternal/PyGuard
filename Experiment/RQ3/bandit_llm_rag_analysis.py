import os
import sys
import json
import glob
import re
import logging
import multiprocessing
from pathlib import Path
from functools import partial
import datetime
import time

PYGUARD_ROOT = Path(__file__).parent.parent.parent

sys.path.append(str(PYGUARD_ROOT))
from Core.utils.llmquery import LLMAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("Bandit4MalLLMRAGAnalysis")

DATASETS = [
    {
        "name": "Evaluation",
        "bandit4mal_path": PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / "Evaluation" / "bandit4mal",
        "dataset_path": PYGUARD_ROOT / "Dataset" / "PyPI" / "Experiment" / "Evaluation"
    },
    {
        "name": "Latest",
        "bandit4mal_path": PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / "Latest" / "bandit4mal",
        "dataset_path": PYGUARD_ROOT / "Dataset" / "PyPI" / "Experiment" / "Latest"
    },
    {
        "name": "Obfuscation",
        "bandit4mal_path": PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / "Obfuscation" / "bandit4mal",
        "dataset_path": PYGUARD_ROOT / "Dataset" / "PyPI" / "Experiment" / "Obfuscation"
    }
]

OUTPUT_BASE = PYGUARD_ROOT / "Experiment" / "Results" / "PyPI"

RAG_KB_DIR = PYGUARD_ROOT / "Core" / "RAG" / "database" / "rag_knowledge_base"

class PatternKnowledge:
    """Pattern-level knowledge extracted by LLM"""
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
    """Case-level knowledge with detailed context"""
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

NUM_PROCESSES = 5

for dataset in DATASETS:
    os.makedirs(OUTPUT_BASE / dataset["name"] / "bandit4mal_llm" / "benign", exist_ok=True)
    os.makedirs(OUTPUT_BASE / dataset["name"] / "bandit4mal_rag" / "benign", exist_ok=True)
    os.makedirs(OUTPUT_BASE / dataset["name"] / "bandit4mal_llm" / "malware", exist_ok=True)
    os.makedirs(OUTPUT_BASE / dataset["name"] / "bandit4mal_rag" / "malware", exist_ok=True)

def setup_logger(dataset_name):
    """Set up a separate log file for each dataset"""
    log_dir = OUTPUT_BASE / "logs"
    os.makedirs(log_dir, exist_ok=True)

    log_file = log_dir / f"bandit4mal_analysis_{dataset_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return log_file

def extract_detection_locations(txt_content, category):
    """
    Extract all detection location information from bandit4mal detection results
    Returns: {file_path: [location1_info, location2_info, ...]}

    Parameters:
    - txt_content: bandit4mal detection result text
    - category: 'benign' or 'malware'
    """
    try:
        lines = txt_content.split('\n')

        detection_locations = {}
        match_count = 0

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            issue_match = re.match(r'>> Issue: \[([^\]]+)\] (.+)', line)
            if issue_match:
                issue_id = issue_match.group(1)
                issue_description = issue_match.group(2)

                severity_line = ""
                confidence_line = ""
                location_line = ""
                more_info_line = ""

                j = i + 1
                while j < len(lines) and j < i + 10:
                    next_line = lines[j].strip()

                    if next_line.startswith("Severity:"):
                        severity_match = re.search(r'Severity:\s+(\w+)\s+Confidence:\s+(\w+)', next_line)
                        if severity_match:
                            severity = severity_match.group(1)
                            confidence = severity_match.group(2)

                    elif next_line.startswith("Location:"):
                        location_match = re.search(r'Location:\s+(.+):(\d+)', next_line)
                        if location_match:
                            file_path = location_match.group(1)
                            line_number = location_match.group(2)

                    elif next_line.startswith("More Info:"):
                        more_info_line = next_line
                        break

                    j += 1

                if 'file_path' in locals() and 'line_number' in locals():
                    code_lines = []
                    k = j + 1
                    while k < len(lines) and k < j + 10:
                        code_line = lines[k].strip()
                        if code_line and not code_line.startswith('--') and not code_line.startswith('>>'):
                            code_line_clean = re.sub(r'^\d+\s+', '', code_line)
                            if code_line_clean:
                                code_lines.append(code_line_clean)
                        elif code_line.startswith('--') or code_line.startswith('>>'):
                            break
                        k += 1

                    code_snippet = '\n'.join(code_lines)

                    location_info = {
                        'issue_id': issue_id,
                        'issue_description': issue_description,
                        'severity': severity if 'severity' in locals() else 'Unknown',
                        'confidence': confidence if 'confidence' in locals() else 'Unknown',
                        'line_number': line_number,
                        'code_snippet': code_snippet,
                        'full_path': file_path,
                        'more_info': more_info_line
                    }

                    if file_path not in detection_locations:
                        detection_locations[file_path] = []

                    detection_locations[file_path].append(location_info)
                    match_count += 1

                for var in ['file_path', 'line_number', 'severity', 'confidence']:
                    if var in locals():
                        del locals()[var]

                i = j
                continue

            i += 1

        package_name = None
        if detection_locations:
            first_path = next(iter(detection_locations.keys()))
            path_parts = first_path.split('/')
            for i, part in enumerate(path_parts):
                if part.startswith('unzip_'):
                    if i + 1 < len(path_parts):
                        package_name = path_parts[i + 1]
                        break

        return detection_locations, match_count, package_name

    except Exception as e:
        logger.error(f"Error extracting detection locations: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None, 0, None

def read_file_content(file_path):
    """Read file content"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return None

def extract_rag_knowledge_summary():
    """Extract summarized knowledge from RAG knowledge base"""
    try:
        import pickle

        knowledge = {}

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

        malicious_characteristics = []
        benign_characteristics = []
        distinction_rules = []
        risk_indicators = []
        malicious_behaviors = []

        for pattern in knowledge['pattern_knowledge'].values():
            if hasattr(pattern, 'pattern_type') and pattern.pattern_type in ['pure_malware_only', 'distinction_malware_biased']:
                if hasattr(pattern, 'malware_characteristics'):
                    malicious_characteristics.extend(pattern.malware_characteristics)
                if hasattr(pattern, 'security_assessment') and pattern.security_assessment:
                    malicious_behaviors.append(pattern.security_assessment)
            elif hasattr(pattern, 'pattern_type') and pattern.pattern_type in ['pure_benign_only', 'distinction_benign_biased']:
                if hasattr(pattern, 'benign_characteristics'):
                    benign_characteristics.extend(pattern.benign_characteristics)

            if hasattr(pattern, 'distinction_rules'):
                distinction_rules.extend(pattern.distinction_rules)

        malware_cases = [c for c in knowledge['case_knowledge'].values() if hasattr(c, 'label') and c.label == 'malware']
        for case in malware_cases:
            if hasattr(case, 'risk_indicators'):
                risk_indicators.extend(case.risk_indicators)

        malicious_characteristics = list(set(malicious_characteristics))
        benign_characteristics = list(set(benign_characteristics))
        distinction_rules = list(set(distinction_rules))
        risk_indicators = list(set(risk_indicators))
        malicious_behaviors = list(set(malicious_behaviors))

        knowledge_summary = """
            Based on extensive analysis of Python malicious and benign code, the following knowledge points can help identify malicious code:

            ## Typical characteristics of malicious code:
            {malicious_features}

            ## Typical malicious behaviors:
            {malicious_behaviors}

            ## Key risk indicators:
            {risk_indicators}

            ## Typical characteristics of benign code:
            {benign_features}

            ## Rules for distinguishing malicious from benign code:
            {distinction_rules}

            When analyzing the code above, please refer to these knowledge points to determine if the code contains malicious behavior.
            """.format(
            malicious_features="\n".join(f"- {feature}" for feature in malicious_characteristics[:50]),
            malicious_behaviors="\n".join(f"- {behavior}" for behavior in malicious_behaviors[:50]),
            risk_indicators="\n".join(f"- {indicator}" for indicator in risk_indicators[:50]),
            benign_features="\n".join(f"- {feature}" for feature in benign_characteristics[:50]),
            distinction_rules="\n".join(f"- {rule}" for rule in distinction_rules[:50])
        )

        return knowledge_summary

    except Exception as e:
        logger.error(f"Error extracting RAG knowledge summary: {e}")
        return ""

def build_simple_prompt(code_content, detection_infos):
    """Build simple prompt"""
    detection_context = "Bandit4Mal Detection Results:\n"
    for i, info in enumerate(detection_infos, 1):
        detection_context += f"- Detection {i} (Line {info['line_number']}): [{info['issue_id']}] {info['issue_description']}\n"
        detection_context += f"  Severity: {info['severity']}, Confidence: {info['confidence']}\n"
        detection_context += f"  Detected code: {info['code_snippet']}\n"

    prompt = f"""
        Please analyze the following Python code and the detection results from Bandit4Mal security tool.
        The tool has flagged this code as potentially malicious. Please review the code and determine if it is actually malicious.

        {detection_context}

        Complete Python file:
        ```python
        {code_content}
        ```

        Please respond in JSON format with the following fields:
        {{
        "is_malicious": true/false,
        "confidence": "high/medium/low",
        "malicious_behavior": "If the code contains malicious behavior, please explain in detail; otherwise leave empty",
        "false_positive_reason": "If you believe this is a false positive, explain why; otherwise leave empty"
        }}
        """
    return prompt

def build_rag_enhanced_prompt(code_content, detection_infos, rag_knowledge_summary):
    """Build RAG-enhanced prompt"""
    detection_context = "Bandit4Mal Detection Results:\n"
    for i, info in enumerate(detection_infos, 1):
        detection_context += f"- Detection {i} (Line {info['line_number']}): [{info['issue_id']}] {info['issue_description']}\n"
        detection_context += f"  Severity: {info['severity']}, Confidence: {info['confidence']}\n"
        detection_context += f"  Detected code: {info['code_snippet']}\n"

    prompt = f"""
        Please analyze the following Python code and the detection results from Bandit4Mal security tool.
        The tool has flagged this code as potentially malicious. Please review the code and determine if it is actually malicious.

        {detection_context}

        Complete Python file:
        ```python
        {code_content}
        ```

        {rag_knowledge_summary}

        Please respond in JSON format with the following fields:
        {{
        "is_malicious": true/false,
        "confidence": "high/medium/low",
        "malicious_behavior": "If the code contains malicious behavior, please explain in detail; otherwise leave empty",
        "false_positive_reason": "If you believe this is a false positive, explain why; otherwise leave empty"
        }}
        """
    return prompt

def analyze_with_llm(code_content, detection_infos, use_rag=False, rag_knowledge_summary=None):
    """Analyze code with LLM"""
    try:
        llm_agent = LLMAgent()

        if use_rag and rag_knowledge_summary:
            prompt = build_rag_enhanced_prompt(code_content, detection_infos, rag_knowledge_summary)
        else:
            prompt = build_simple_prompt(code_content, detection_infos)

        messages = [
            {"role": "system", "content": "You are a professional Python malicious code analysis expert. Analyze the following code and determine if it contains malicious behavior."},
            {"role": "user", "content": prompt}
        ]

        response = llm_agent.perform_query(
            messages=messages,
            response_format={"type": "json_object"}
        )

        result = json.loads(response)
        return result

    except Exception as e:
        logger.error(f"Error during LLM analysis: {e}")
        return {
            "is_malicious": False,
            "confidence": "low",
            "malicious_behavior": "",
            "false_positive_reason": f"Error during analysis: {str(e)}"
        }

def process_txt_file(args):
    """Worker function to process a single txt file"""
    txt_file, dataset, rag_knowledge_summary, category, dataset_path = args
    dataset_name = dataset["name"]
    bandit4mal_path = dataset["bandit4mal_path"]

    try:
        txt_path = bandit4mal_path / category / txt_file
        package_name = os.path.splitext(txt_file)[0]

        llm_output_path = OUTPUT_BASE / dataset_name / "bandit4mal_llm" / category / f"{package_name}.json"
        rag_output_path = OUTPUT_BASE / dataset_name / "bandit4mal_rag" / category / f"{package_name}.json"

        if os.path.exists(llm_output_path) and os.path.exists(rag_output_path):
            logger.info(f"Skipping already processed file: {txt_file}")
            return {"status": "skipped", "file": txt_file}

        txt_content = read_file_content(txt_path)
        if not txt_content:
            return {"status": "error", "file": txt_file, "error": "Cannot read txt file"}

        if "No issues identified." in txt_content:
            logger.info(f"File {txt_file} has no detection results, skipping")
            empty_result = {
                "package_name": package_name,
                "total_matches": 0,
                "is_malicious": False,
                "file_results": []
            }
            with open(llm_output_path, 'w', encoding='utf-8') as f:
                json.dump(empty_result, f, ensure_ascii=False, indent=2)
            with open(rag_output_path, 'w', encoding='utf-8') as f:
                json.dump(empty_result, f, ensure_ascii=False, indent=2)
            return {"status": "no_detection", "file": txt_file}

        if "Total issues (by severity):" in txt_content:
            severity_match = re.search(r'Total issues \(by severity\):\s*.*?High:\s*([\d.]+)', txt_content, re.DOTALL)
            if severity_match:
                total_high = float(severity_match.group(1))
                if total_high == 0:
                    logger.info(f"File {txt_file} has no high severity detection results, skipping")
                    empty_result = {
                        "package_name": package_name,
                        "total_matches": 0,
                        "is_malicious": False,
                        "file_results": []
                    }
                    with open(llm_output_path, 'w', encoding='utf-8') as f:
                        json.dump(empty_result, f, ensure_ascii=False, indent=2)
                    with open(rag_output_path, 'w', encoding='utf-8') as f:
                        json.dump(empty_result, f, ensure_ascii=False, indent=2)
                    return {"status": "no_detection", "file": txt_file}

        detection_locations, match_count, package_name_no_ext = extract_detection_locations(txt_content, category)
        if not detection_locations or match_count == 0:
            logger.info(f"File {txt_file} has no detection locations, skipping")
            empty_result = {
                "package_name": package_name,
                "total_matches": 0,
                "is_malicious": False,
                "file_results": []
            }
            with open(llm_output_path, 'w', encoding='utf-8') as f:
                json.dump(empty_result, f, ensure_ascii=False, indent=2)
            with open(rag_output_path, 'w', encoding='utf-8') as f:
                json.dump(empty_result, f, ensure_ascii=False, indent=2)
            return {"status": "no_detection", "file": txt_file}

        llm_result = {
            "package_name": package_name,
            "total_matches": match_count,
            "is_malicious": False,
            "file_results": []
        }

        rag_result = {
            "package_name": package_name,
            "total_matches": match_count,
            "is_malicious": False,
            "file_results": []
        }

        for file_path, detection_infos in detection_locations.items():
            code_content = read_file_content(file_path)
            if not code_content:
                logger.warning(f"Cannot read Python file: {file_path}")
                continue

            llm_analysis = analyze_with_llm(code_content, detection_infos, use_rag=False)

            rag_analysis = analyze_with_llm(code_content, detection_infos, use_rag=True, rag_knowledge_summary=rag_knowledge_summary)

            file_name = os.path.basename(file_path)

            llm_file_result = {
                "file_path": file_path,
                "file_name": file_name,
                "detection_count": len(detection_infos),
                "is_malicious": llm_analysis.get("is_malicious", False),
                "confidence": llm_analysis.get("confidence", "low"),
                "malicious_behavior": llm_analysis.get("malicious_behavior", ""),
                "false_positive_reason": llm_analysis.get("false_positive_reason", ""),
                "detection_points": detection_infos
            }
            llm_result["file_results"].append(llm_file_result)

            rag_file_result = {
                "file_path": file_path,
                "file_name": file_name,
                "detection_count": len(detection_infos),
                "is_malicious": rag_analysis.get("is_malicious", False),
                "confidence": rag_analysis.get("confidence", "low"),
                "malicious_behavior": rag_analysis.get("malicious_behavior", ""),
                "false_positive_reason": rag_analysis.get("false_positive_reason", ""),
                "detection_points": detection_infos
            }
            rag_result["file_results"].append(rag_file_result)

            if llm_analysis.get("is_malicious", False):
                llm_result["is_malicious"] = True

            if rag_analysis.get("is_malicious", False):
                rag_result["is_malicious"] = True

        with open(llm_output_path, 'w', encoding='utf-8') as f:
            json.dump(llm_result, f, ensure_ascii=False, indent=2)

        with open(rag_output_path, 'w', encoding='utf-8') as f:
            json.dump(rag_result, f, ensure_ascii=False, indent=2)

        if llm_result["is_malicious"] or rag_result["is_malicious"]:
            malicious_type = []
            if llm_result["is_malicious"]:
                malicious_type.append("LLM")
            if rag_result["is_malicious"]:
                malicious_type.append("RAG")

            logger.info(f"Found malicious file [{'/'.join(malicious_type)}]: {txt_file}")
            logger.info(f"  Original txt path: {txt_path}")
            logger.info(f"  LLM analysis result: {llm_output_path}")
            logger.info(f"  RAG analysis result: {rag_output_path}")

            malicious_files = []
            for file_result in llm_result["file_results"]:
                if file_result["is_malicious"]:
                    malicious_files.append(f"{file_result['file_name']} (LLM)")

            for file_result in rag_result["file_results"]:
                if file_result["is_malicious"] and f"{file_result['file_name']} (RAG)" not in malicious_files:
                    malicious_files.append(f"{file_result['file_name']} (RAG)")

            if malicious_files:
                logger.info(f"  Malicious files: {', '.join(malicious_files)}")

        logger.info(f"Successfully processed file: {txt_file}")
        return {"status": "success", "file": txt_file}

    except Exception as e:
        logger.error(f"Error processing file {txt_file}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {"status": "error", "file": txt_file, "error": str(e)}

def process_dataset(dataset):
    """Process a single dataset"""
    dataset_name = dataset["name"]
    bandit4mal_path = dataset["bandit4mal_path"]
    dataset_path = dataset["dataset_path"]

    log_file = setup_logger(dataset_name)
    logger.info(f"Starting to process dataset: {dataset_name}")
    logger.info(f"Log file: {log_file}")

    logger.info("Extracting RAG knowledge summary...")
    rag_knowledge_summary = extract_rag_knowledge_summary()

    for category in ["benign", "malware"]:
        category_path = bandit4mal_path / category

        if not os.path.exists(category_path):
            logger.warning(f"Directory does not exist: {category_path}")
            continue

        txt_files = [f for f in os.listdir(category_path) if f.endswith('.txt')]
        logger.info(f"Found {len(txt_files)} {category} txt files")

        tasks = [(txt_file, dataset, rag_knowledge_summary, category, dataset_path) for txt_file in txt_files]

        logger.info(f"Using {NUM_PROCESSES} processes to process {category} files in parallel...")

        results = {
            "success": 0,
            "skipped": 0,
            "no_detection": 0,
            "error": 0
        }

        with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
            for i, result in enumerate(pool.imap_unordered(process_txt_file, tasks)):
                status = result["status"]
                results[status] = results.get(status, 0) + 1

                if (i + 1) % 10 == 0 or (i + 1) == len(txt_files):
                    logger.info(f"{category} progress: {i+1}/{len(txt_files)}, success: {results['success']}, "
                               f"skipped: {results['skipped']}, no_detection: {results.get('no_detection', 0)}, "
                               f"error: {results['error']}")

        logger.info(f"{category} processing complete: success: {results['success']}, skipped: {results['skipped']}, "
                   f"no_detection: {results.get('no_detection', 0)}, error: {results['error']}")

    logger.info(f"Dataset {dataset_name} processing complete")

    return True

def main():
    """Main function"""
    logger.info("Starting bandit4mal detection results LLM and RAG analysis")

    for dataset in DATASETS:
        process_dataset(dataset)

    logger.info("All datasets processed")

if __name__ == "__main__":
    main()
