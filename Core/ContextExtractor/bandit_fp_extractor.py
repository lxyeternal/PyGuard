"""
Extract context from bandit4mal false positives (benign code flagged by bandit) using LLM.
"""
import os
import json
import re
import sys
import hashlib
from collections import defaultdict
import multiprocessing
from functools import partial
import time
import logging
import datetime
import random
import traceback
from pathlib import Path

PYGUARD_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PYGUARD_ROOT))
from Utils.llmquery import LLMAgent

SOURCE_JSON = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "detailed_reports.json")
TARGET_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "llm_extracted_context" / "benign_bandit4mal")
PROMPT_PATH = str(PYGUARD_ROOT / "Resources" / "Prompts" / "codeslice" / "single_snippets_prompt.txt")
ISSUES_TO_SELECT = 8000

EXCLUDED_TYPES = [
    "B824:url_found", "B823:ip_found",
]

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(CURRENT_DIR, f"bandit_analysis_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

def setup_logger():
    """Set up logger to output to console and file"""
    logger = logging.getLogger('bandit_analysis')
    logger.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger()

os.makedirs(TARGET_DIR, exist_ok=True)

def normalize_code(code_snippet):
    """Normalize code snippet by removing possible variations (e.g., variable names, spaces, etc.)"""
    normalized = re.sub(r'\s+', '', code_snippet)
    normalized = normalized.lower()
    return normalized

def hash_code(code_snippet):
    """Generate hash value for code snippet for similarity comparison"""
    normalized = normalize_code(code_snippet)
    return hashlib.md5(normalized.encode()).hexdigest()

def read_source_code(file_path):
    """Read source code file content"""      
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")     
        return None

def process_with_llm(code_content, detection_info, prompt_template):
    """
    Use LLM to process code content, need to extract separate context for each detection point
    
    Parameters:
        code_content: source code content
        detection_info: detection information list
        prompt_template: prompt template path
    
    Returns:
        List of multiple context fragments, each element corresponds to a detection point
    """
    try:
        with open(prompt_template, 'r', encoding='utf-8') as f:
            prompt_template_content = f.read()
        
        detection_context = "Detection information:\n"
        for i, info in enumerate(detection_info, 1):
            detection_context += f"- Match (Line {info['line_number']}): {info['type_description']}\n"
            detection_context += f"  {info['code_snippet']}\n"
        
        code_with_context = f"{detection_context}\nSource code:\n{code_content}"
        current_prompt = prompt_template_content.replace("{CODE}", code_with_context)
        
        llm_agent = LLMAgent()
        
        messages = [
            {"role": "system", "content": "You are an code analysis expert."},
            {"role": "user", "content": current_prompt}
        ]
        
        response = llm_agent.perform_query(messages)

        print(response)
        
        try:
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if json_match:
                json_content = json_match.group(1)
                context_data = json.loads(json_content)
            else:
                context_data = json.loads(response)
            
            context_results = []
            
            if "extracted_context" in context_data:
                for i, info in enumerate(detection_info):
                    result_item = {
                        "extracted_context": context_data["extracted_context"],
                        "line_number": info["line_number"],
                        "type_description": info["type_description"],
                        "original_snippet": info["code_snippet"]
                    }
                    context_results.append(result_item)
                    logger.info(f"Successfully processed context, line number: {info['line_number']}")
                
                return context_results
            else:
                logger.error("LLM response is missing the extracted_context field")
                return None
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
            logger.debug(f"Original LLM response: {response[:200]}...")
            
            code_blocks = re.findall(r'```python(.*?)```', response, re.DOTALL)
            if code_blocks:
                logger.info(f"Extracted {len(code_blocks)} code blocks from response")
                context_results = []
                
                for i, code_block in enumerate(code_blocks):
                    detection_idx = min(i, len(detection_info) - 1) if detection_info else 0
                    detection = detection_info[detection_idx] if detection_info else {"line_number": "unknown", "type_description": "unknown", "code_snippet": ""}
                    
                    result_item = {
                        "extracted_context": code_block.strip(),
                        "line_number": detection["line_number"],
                        "type_description": detection["type_description"],
                        "original_snippet": detection["code_snippet"]
                    }
                    context_results.append(result_item)
                
                return context_results
            
            return None
            
    except Exception as e:
        logger.error(f"LLM processing failed: {e}")
        logger.error(traceback.format_exc())
        return None

def load_issues_from_json(json_file):
    """Load issue list from JSON file"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            logger.error(f"JSON file format error: expected a list, but got {type(data)}")
            return []
        
        all_issues = []
        for package_data in data:
            if 'detailed_issues' in package_data and isinstance(package_data['detailed_issues'], list):
                all_issues.extend(package_data['detailed_issues'])
        
        logger.info(f"Successfully loaded JSON file, containing {len(all_issues)} issues")
        
        if all_issues:
            sample = all_issues[0]
            required_fields = ['type', 'location', 'line', 'code']
            missing = [field for field in required_fields if field not in sample]
            if missing:
                logger.warning(f"JSON entries are missing some expected fields: {missing}")
            
            type_samples = [issue.get('type', 'unknown') for issue in all_issues[:3]]
            logger.info(f"First three issue type samples: {type_samples}")
        
        return all_issues

    except Exception as e:
        logger.error(f"Error loading issues from JSON file: {e}")
        logger.error(traceback.format_exc())
        return []

def identify_blacklist_types(issues):
    """Identify and return all types with blacklist suffix"""
    blacklist_types = set()
    for issue in issues:
        issue_type = issue.get('type', '')
        if 'blacklist' in issue_type.lower():
            blacklist_types.add(issue_type)
    return blacklist_types

def filter_and_select_issues(issues, excluded_types, total_count):
    """Filter and randomly select issues"""
    blacklist_types = identify_blacklist_types(issues)
    if blacklist_types:
        logger.info(f"Identified {len(blacklist_types)} types with blacklist:")
        for btype in sorted(blacklist_types):
            logger.info(f"  - {btype}")
    
    all_excluded = set(excluded_types).union(blacklist_types)
    logger.info(f"Total excluded {len(all_excluded)} types")
    
    issue_by_type = defaultdict(list)
    
    filtered_issues = []
    for issue in issues:
        issue_type = issue.get('type', '')
        if issue_type not in all_excluded:
            issue_by_type[issue_type].append(issue)
            filtered_issues.append(issue)
    
    logger.info(f"After filtering, {len(filtered_issues)} issues remain, {len(issue_by_type)} types")
    logger.info("Issue type statistics:")
    for issue_type, type_issues in sorted(issue_by_type.items(), key=lambda x: len(x[1]), reverse=True):
        logger.info(f"  {issue_type}: {len(type_issues)} issues")
    
    if len(filtered_issues) <= total_count:
        logger.info(f"The total number of filtered issues ({len(filtered_issues)}) is less than the number to be selected ({total_count}), return all filtered issues")
        return filtered_issues
    
    total_filtered = len(filtered_issues)
    selected_issues = []
    
    min_per_type = min(5, total_count // len(issue_by_type))
    remaining = total_count - min_per_type * len(issue_by_type)
    
    if remaining < 0:
        logger.info(f"There are too many types ({len(issue_by_type)}), perform global random selection")
        return random.sample(filtered_issues, total_count)
    
    logger.info(f"Select at least {min_per_type} issues for each type, remaining {remaining} issues are allocated proportionally")
    for issue_type, type_issues in issue_by_type.items():
        count_to_select = min_per_type
        
        if remaining > 0:
            proportion = len(type_issues) / total_filtered
            additional = int(remaining * proportion)
            count_to_select += additional
        
        count_to_select = min(count_to_select, len(type_issues))
        
        selected = random.sample(type_issues, count_to_select)
        selected_issues.extend(selected)
        logger.debug(f"Type {issue_type}: selected {count_to_select} issues")
    
    if len(selected_issues) < total_count:
        remaining_issues = [i for i in filtered_issues if i not in selected_issues]
        additional_needed = total_count - len(selected_issues)
        if remaining_issues and additional_needed > 0:
            additional = random.sample(remaining_issues, min(additional_needed, len(remaining_issues)))
            selected_issues.extend(additional)
            logger.info(f"Insufficient selection, additional {len(additional)} issues")
    
    if len(selected_issues) > total_count:
        selected_issues = random.sample(selected_issues, total_count)
        logger.info(f"Selection exceeds the required number, randomly reduce to {total_count} issues")
    
    final_type_counts = defaultdict(int)
    for issue in selected_issues:
        final_type_counts[issue.get('type', 'unknown')] += 1
    
    logger.info(f"Finally selected {len(selected_issues)} issues, type distribution:")
    for issue_type, count in sorted(final_type_counts.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  {issue_type}: {count} issues")
    
    return selected_issues

def process_issue_worker(issue, prompt_path, processed_code_hashes=None):
    """Process a single issue worker function"""
    try:
        issue_type = issue.get('type', 'unknown')
        severity = issue.get('severity', 'unknown')
        confidence = issue.get('confidence', 'unknown')
        location = issue.get('location', '')
        line_number = issue.get('line', 'unknown')
        code_snippet = issue.get('code', '')
        
        logger.info(f"Processing issue: {issue_type} at {location}:{line_number}")
        
        if not location or not os.path.exists(location):
            logger.warning(f"File does not exist: {location}")
            return None
        
        code_content = read_source_code(location)
        if not code_content:
            logger.error(f"Cannot read source code: {location}")
            return None
        
        detection_info = [{
            'line_number': line_number,
            'type_description': issue_type,
            'code_snippet': code_snippet
        }]
        
        logger.info(f"Using LLM to analyze code: {location}")
        llm_results = process_with_llm(code_content, detection_info, prompt_path)
        if not llm_results:
            logger.error(f"LLM processing failed: {location}")
            return None
        
        file_name = os.path.basename(location)
        result_items = []
        
        for context_result in llm_results:
            context_code = context_result.get("extracted_context", "")
            
            if context_code.strip() == "":
                logger.info(f"LLM determined that this issue does not contain suspicious code, skip: {location}")
                continue
            
            context_hash = hash_code(context_code)
            
            if processed_code_hashes and context_hash in processed_code_hashes:
                logger.info(f"Duplicate code found: {location} - {issue_type}")
                continue
            
            if processed_code_hashes is not None:
                processed_code_hashes[context_hash] = True
            
            result_item = {
                "pyfile": file_name,
                "full_path": location,
                "line_number": context_result.get('line_number', line_number),
                "type_description": context_result.get('type_description', issue_type),
                "severity": severity,
                "confidence": confidence,
                "original_snippet": code_snippet,
                "context_snippet": context_code,
                "hash_value": context_hash
            }
            
            result_items.append(result_item)
            logger.info(f"Successfully processed issue: {location} - {issue_type}")
        
        return result_items
        
    except Exception as e:
        logger.error(f"Error processing issue: {e}")
        logger.error(traceback.format_exc())
        return None

def process_package(package_name, pkg_issues, prompt_path, processed_code_hashes):
    """Process all issues in a single package"""
    logger.info(f"Starting to process package: {package_name}, containing {len(pkg_issues)} issues")
    package_results = []
    processed_count = 0
    success_count = 0
    
    for issue in pkg_issues:
        processed_count += 1
        if processed_count % 5 == 0 or processed_count == len(pkg_issues):
            logger.info(f"Package {package_name} progress: {processed_count}/{len(pkg_issues)} issues")
            
        result = process_issue_worker(issue, prompt_path, processed_code_hashes)
        if result:
            package_results.extend(result)
            success_count += 1
    
    logger.info(f"Package {package_name} processing completed, processed {processed_count} issues, successfully extracted context for {success_count} issues, generated {len(package_results)} results")
    return package_name, package_results

def main():
    """Main function, process all issues"""
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    logger.info(f"Loading issues from {SOURCE_JSON}")
    issues = load_issues_from_json(SOURCE_JSON)
    logger.info(f"Loaded {len(issues)} issues")
    
    if not issues:
        logger.error("No issues loaded, program exiting")
        return
    
    selected_issues = filter_and_select_issues(issues, EXCLUDED_TYPES, ISSUES_TO_SELECT)
    logger.info(f"After filtering and selection, {len(selected_issues)} issues remain")
    
    if not selected_issues:
        logger.error("No issues remain after filtering, program exiting")
        return
    
    existing_packages = []
    total_skipped_issues = 0
    packages_to_process = []
    total_issues_to_process = 0
    
    temp_issues_by_package = defaultdict(list)
    for issue in selected_issues:
        location = issue.get('location', '')
        if not location or not os.path.exists(location):
            continue
            
        package_name = "unknown_package"
        match = re.search(r'/unzip_benign/([^/]+)/', location)
        if match:
            package_name = match.group(1)
        
        temp_issues_by_package[package_name].append(issue)
    
    for package_name, pkg_issues in temp_issues_by_package.items():
        filename = f"{package_name}.json"
        file_path = os.path.join(TARGET_DIR, filename)
        if os.path.exists(file_path):
            existing_packages.append(package_name)
            total_skipped_issues += len(pkg_issues)
        else:
            packages_to_process.append(package_name)
            total_issues_to_process += len(pkg_issues)
    
    logger.info(f"=== Processing statistics ===")
    logger.info(f"Total packages: {len(temp_issues_by_package)}")
    logger.info(f"Processed (skipped): {len(existing_packages)} packages, containing {total_skipped_issues} issues")
    logger.info(f"Pending: {len(packages_to_process)} packages, containing {total_issues_to_process} issues")
    
    if existing_packages:
        logger.info(f"Skipped package list (first 10):")
        for pkg in sorted(existing_packages)[:10]:
            pkg_issues_count = len(temp_issues_by_package[pkg])
            logger.info(f"  - {pkg} ({pkg_issues_count} issues)")
        if len(existing_packages) > 10:
            logger.info(f"  ... there are {len(existing_packages) - 10} packages")
    
    if packages_to_process:
        logger.info(f"Pending package issue distribution:")
        for package_name, pkg_issues in sorted(temp_issues_by_package.items(), key=lambda x: len(x[1]), reverse=True):
            if package_name in packages_to_process:
                logger.info(f"  {package_name}: {len(pkg_issues)} issues")
    
    issues_by_package = temp_issues_by_package
    
    logger.info(f"Issues grouped by package, total {len(issues_by_package)} packages")
    for package_name, pkg_issues in sorted(issues_by_package.items(), key=lambda x: len(x[1]), reverse=True):
        logger.info(f"  {package_name}: {len(pkg_issues)} issues")
    
    manager = multiprocessing.Manager()
    processed_code_hashes = manager.dict()
    
    total_packages = 0
    total_items = 0
    total_issues_processed = 0
    total_issues_to_process = sum(len(issues) for issues in issues_by_package.values())
    
    logger.info(f"Total {len(issues_by_package)} packages, {total_issues_to_process} issues")    
    
    num_processes = 15
    logger.info(f"Using {num_processes} processes for parallel processing")
    
    package_args = []
    
    for package_name in packages_to_process:
        pkg_issues = issues_by_package[package_name]
        package_args.append((package_name, pkg_issues, PROMPT_PATH, processed_code_hashes))
    
    total_issues_processed += total_skipped_issues
    
    logger.info(f"Starting to process {len(package_args)} packages")    
    
    if len(package_args) == 0:
        logger.info("All packages have been processed, no need to reprocess")
        total_all_issues = total_skipped_issues + total_issues_to_process
        logger.info(f"Total {total_issues_processed}/{total_all_issues} issues")
        logger.info(f"Results saved in directory: {TARGET_DIR}")
        return
    
    with multiprocessing.Pool(processes=num_processes) as pool:
        for i, (package_name, results) in enumerate(pool.starmap(process_package, package_args)):
            issues_in_package = len(issues_by_package[package_name])
            total_issues_processed += issues_in_package
            
            if results:
                metadata = {
                    "metadata": {
                        "package_name": package_name,
                        "total_matches": len(results),
                        "processing_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                }
                
                package_results = [metadata] + results
                
                filename = f"{package_name}.json"
                file_path = os.path.join(TARGET_DIR, filename)
                
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(package_results, f, ensure_ascii=False, indent=2)
                    
                    total_items += len(results)
                    total_packages += 1
                    logger.info(f"Results for package {package_name} saved, containing {len(results)} issues, file path: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to save results for package {package_name}: {e}")
            
            packages_done = i + 1
            packages_total = len(issues_by_package)
            percent_done = (packages_done / packages_total) * 100
            logger.info(f"Total progress: {packages_done}/{packages_total} packages ({percent_done:.1f}%), "
                        f"Processed {total_issues_processed}/{total_issues_to_process} issues, "
                        f"Generated {total_items} results")
    
    logger.info(f"Analysis completed, processed {total_issues_processed}/{total_issues_to_process} issues, "
                f"generated {total_packages} package result files, skipped {skipped_packages} existing packages, total {total_items} result items")
    logger.info(f"Results saved in directory: {TARGET_DIR}")
    
    if total_items < total_issues_processed * 0.5:
        logger.warning(f"Warning: the number of results ({total_items}) is significantly less than the number of processed issues ({total_issues_processed}), please check the processing process")

if __name__ == "__main__":
    logger.info("Starting to execute bandit_code_snippets.py")
    logger.info(f"Log file path: {LOG_FILE}")
    
    main()