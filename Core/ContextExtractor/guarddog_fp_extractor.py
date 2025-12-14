"""
Extract context from guarddog false positives (truly benign code) using LLM.
"""
import os
import json
import re
from pathlib import Path
import sys
import hashlib
from collections import defaultdict
import multiprocessing
from functools import partial
import time
import logging
import datetime

PYGUARD_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PYGUARD_ROOT))
from Utils.llmquery import LLMAgent

SOURCE_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "tool_scan_output" / "guarddog" / "benign")
TARGET_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "llm_extracted_context" / "benign_guarddog")
PROMPT_PATH = str(PYGUARD_ROOT / "Resources" / "Prompts" / "codeslice" / "code_snippets_prompt.txt")

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(CURRENT_DIR, f"benign_analysis_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

def setup_logger():
    """Set up logger to output to both console and file"""
    logger = logging.getLogger('benign_analysis')
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
    """Normalize code snippet, remove possible variations (like variable names, spaces, etc.)"""
    normalized = re.sub(r'\s+', '', code_snippet)
    normalized = normalized.lower()
    return normalized

def hash_code(code_snippet):
    """Generate hash value for code snippet, used for comparing similarity"""
    normalized = normalize_code(code_snippet)
    return hashlib.md5(normalized.encode()).hexdigest()

def extract_malicious_locations(txt_content):
    """
    Extract all malicious code location information from the report
    Return format: {file_path: [location1_info, location2_info, ...]}
    Also returns the number of matches
    """
    logger.info("First 100 characters of the file content:")
    logger.info(txt_content[:100])
    
    if "Found" in txt_content:
        logger.info("File contains 'Found' string")
        found_lines = [line for line in txt_content.split('\n') if "Found" in line]
        logger.info("Lines containing 'Found':")
        for line in found_lines:
            logger.info(f"  - {line}")
    else:
        logger.info("File does not contain 'Found' string")
    
    archive_pattern = r'Found \d+ potentially malicious indicators in (.*?)(\.tar\.gz|\.zip|\.whl)'
    archive_match = re.search(archive_pattern, txt_content)
    
    logger.info(f"Regex match result: {archive_match}")
    
    if not archive_match:
        logger.warning("Warning: Cannot extract archive path")
        return None, 0
    
    zip_path = archive_match.group(1) + archive_match.group(2)
    logger.info(f"Extracted archive path: {zip_path}")
    
    lines = txt_content.split('\n')
    
    malicious_locations = {}
    current_type = ""
    match_count = 0
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        type_match = re.match(r'^([\w\-]+): found (\d+) .* matches', line)
        if type_match:
            current_type = line
            match_count_str = type_match.group(2)
            try:
                match_count += int(match_count_str)
            except ValueError:
                pass
            logger.info(f"Found type description: {current_type}")
            i += 1
            continue
        
        location_match = re.search(r'\*.*?\s+at\s+([\w\-\.\/]+\.py):(\d+)', line)
        if location_match and current_type:
            relative_path = location_match.group(1)
            line_number = location_match.group(2)
            
            logger.info(f"Found file location: {relative_path}:{line_number}")
            
            full_path = zip_path.replace('zip_malware', 'unzip_malware').replace('zip_benign', 'unzip_benign').replace('.tar.gz', '').replace('.zip', '').replace('.whl', '') + '/' + relative_path
            
            code_lines = []
            j = i + 1
            while j < len(lines):
                next_line = lines[j].strip()
                if not next_line or next_line.startswith('*') or re.match(r'^[\w\-]+: found \d+ .* matches', next_line):
                    break
                code_line = re.sub(r'^\s+', '', next_line)
                code_lines.append(code_line)
                j += 1
            
            code_snippet = '\n'.join(code_lines)
            
            logger.info(f"Found code snippet: \n{code_snippet}")
            
            location_info = {
                'line_number': line_number,
                'type_description': current_type,
                'code_snippet': code_snippet,
                'full_match': line,
                'full_path': full_path
            }
            
            if full_path not in malicious_locations:
                malicious_locations[full_path] = []
                logger.info(f"Adding new file path: {full_path}")
            
            malicious_locations[full_path].append(location_info)
            
            i = j
            continue
        
        i += 1
    
    if not malicious_locations:
        logger.warning("Warning: No malicious code locations found")
    else:
        logger.info(f"Found malicious code locations in {len(malicious_locations)} files")
    
    return malicious_locations, match_count

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
    Process code content with LLM, requiring separate context extraction for each detection point
    
    Args:
        code_content: Source code content
        detection_info: Detection information list
        prompt_template: Prompt template path
    
    Returns:
        List containing multiple context snippets, each element corresponding to a detection point
    """
    try:
        with open(prompt_template, 'r', encoding='utf-8') as f:
            prompt_template_content = f.read()
        
        detection_context = "Detection information:\n"
        for i, info in enumerate(detection_info, 1):
            detection_context += f"- Match {i} (Line {info['line_number']}): {info['type_description']}\n"
            detection_context += f"  {info['code_snippet']}\n"
        
        code_with_context = f"{detection_context}\nSource code:\n{code_content}"
        current_prompt = prompt_template_content.replace("{CODE}", code_with_context)
        
        llm_agent = LLMAgent()
        
        messages = [
            {"role": "system", "content": "You are an code analysis expert."},
            {"role": "user", "content": current_prompt}
        ]
        
        response = llm_agent.perform_query(messages)
        
        try:
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if json_match:
                contexts_data = json.loads(json_match.group(1))
            else:
                contexts_data = json.loads(response)
            
            if not isinstance(contexts_data, list):
                if "extracted_context" in contexts_data:
                    contexts_data = [contexts_data]
                else:
                    logger.error("LLM response is not in expected list format")
                    return None
            
            context_results = []
            
            if len(contexts_data) != len(detection_info):
                logger.warning(f"Number of contexts returned by LLM ({len(contexts_data)}) doesn't match the number of detection points ({len(detection_info)})")
            
            for i, context_data in enumerate(contexts_data):
                detection_idx = min(i, len(detection_info) - 1) if detection_info else 0
                detection = detection_info[detection_idx] if detection_info else {"line_number": "unknown", "type_description": "unknown", "code_snippet": ""}
                
                result_item = {}
                
                if "extracted_context" in context_data:
                    result_item["extracted_context"] = context_data["extracted_context"]
                elif "context" in context_data:
                    result_item["extracted_context"] = context_data["context"]
                else:
                    for key in context_data:
                        if isinstance(context_data[key], str) and len(context_data[key]) > 10:
                            result_item["extracted_context"] = context_data[key]
                            break
                
                if "extracted_context" not in result_item:
                    logger.warning(f"Cannot extract context content from LLM response: {context_data}")
                    result_item["extracted_context"] = ""
                
                result_item["line_number"] = context_data.get("detection_line", detection["line_number"])
                result_item["type_description"] = context_data.get("detection_type", detection["type_description"])
                result_item["original_snippet"] = detection["code_snippet"]
                
                context_results.append(result_item)
                logger.info(f"Successfully processed context #{i+1}, line number: {result_item['line_number']}")
            
            return context_results
            
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
        import traceback
        logger.error(traceback.format_exc())
        return None

def should_process_file(txt_content):
    """Determine whether to process this file (only process files with Found n, n>0)"""
    match = re.search(r'Found (\d+) potentially malicious indicators', txt_content)
    if match and int(match.group(1)) > 0:
        return True
    return False

def process_file_worker(
    txt_file: str,
    source_dir: str,
    target_dir: str,
    prompt_path: str,
    processed_code_hashes: dict, 
    analyzed_code_hashes: dict,
    code_hash_map: dict
) -> tuple:
    """Worker function for multiprocessing individual files"""
    logger.info(f"\nPreprocessing file: {txt_file}")
    txt_path = os.path.join(source_dir, txt_file)
    
    processed = 0
    skipped_exists = 0
    skipped_duplicate = 0
    failed = 0
    
    try:
        json_file = os.path.join(target_dir, os.path.splitext(txt_file)[0] + '.json')
        if os.path.exists(json_file):
            return 0, 1, 0, 0
        
        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt_content = f.read()
        
        if not should_process_file(txt_content):
            logger.info(f"{txt_file} does not meet processing criteria, skipping")
            return 0, 0, 0, 0
        
        malicious_locations, match_count = extract_malicious_locations(txt_content)
        
        if malicious_locations and match_count > 0:
            logger.info(f"{txt_file} has {match_count} matches, processing by Python file...")
            
            final_result = []
            
            metadata_entry = {
                "metadata": {
                    "package_name": os.path.splitext(txt_file)[0],
                    "report_path": txt_path,
                    "total_matches": match_count
                }
            }
            final_result.append(metadata_entry)
            
            for full_path, location_infos in malicious_locations.items():
                logger.info(f"Processing Python file: {full_path}, contains {len(location_infos)} matches")
                
                code_content = read_source_code(full_path)
                if not code_content:
                    logger.error(f"Cannot read source code: {full_path}")
                    continue
                
                logger.info(f"Using LLM to analyze code snippets, {len(location_infos)} detection points")
                llm_results = process_with_llm(code_content, location_infos, prompt_path)
                if not llm_results:
                    logger.error(f"LLM processing failed: {full_path}")
                    continue
                
                file_name = os.path.basename(full_path)
                
                for i, context_result in enumerate(llm_results):
                    try:
                        if "extracted_context" in context_result:
                            context_code = context_result["extracted_context"]
                        elif "malicious_code" in context_result:
                            context_code = context_result["malicious_code"]
                        else:
                            logger.warning(f"Warning: LLM response JSON contains neither 'malicious_code' nor 'extracted_context' field: {full_path} detection point {i+1}")
                            continue
                        
                        if context_code.strip() == "":
                            logger.info(f"LLM determined file {full_path} detection point {i+1} does not contain malicious code, skipping")
                            continue
                        
                        context_hash = hash_code(context_code)
                        
                        malicious_entry = {
                            "pyfile": file_name,
                            "full_path": full_path,
                            "line_number": context_result.get('line_number', 'unknown'),
                            "type_description": context_result.get('type_description', 'unknown'),
                            "original_snippet": context_result.get('original_snippet', ''),
                            "context_snippet": context_code,
                            "hash_value": context_hash,
                            "detection_index": i+1
                        }
                        
                        final_result.append(malicious_entry)
                        processed += 1
                    
                    except Exception as e:
                        logger.error(f"Error processing detection point {i+1} result: {e}")
                
            if len(final_result) > 1:
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(final_result, f, ensure_ascii=False, indent=2)
                
                logger.info(f"Generated JSON file: {json_file}")
                return processed, 0, 0, failed
            else:
                logger.info(f"{txt_file} No valid malicious code found")
                return 0, 0, 0, 0
        else:
            logger.info(f"{txt_file} No malicious code locations found")
            return 0, 0, 0, 0
            
    except Exception as e:
        logger.error(f"Error processing file {txt_file}: {e}")
        return 0, 0, 0, 1

def main():
    """Main function, process all report files"""
    txt_files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    logger.info(f"Found {len(txt_files)} txt files")
    
    processed = 0
    skipped_exists = 0
    skipped_duplicate = 0
    failed = 0
    
    processed_code_hashes = {}
    code_hash_map = {}
    analyzed_code_hashes = {}
    
    num_processes = 24
    logger.info(f"Using {num_processes} processes for parallel processing")
    
    with multiprocessing.Pool(processes=num_processes) as pool:
        process_func = partial(
            process_file_worker,
            source_dir=SOURCE_DIR,
            target_dir=TARGET_DIR,
            prompt_path=PROMPT_PATH,
            processed_code_hashes=processed_code_hashes,
            analyzed_code_hashes=analyzed_code_hashes,
            code_hash_map=code_hash_map
        )
        
        results = []
        for i, result in enumerate(pool.imap_unordered(process_func, txt_files)):
            p, s_e, s_d, f = result
            processed += p
            skipped_exists += s_e
            skipped_duplicate += s_d
            failed += f
            
            if (i + 1) % 10 == 0 or (i + 1) == len(txt_files):
                logger.info(f"Progress: {i+1}/{len(txt_files)} files, Success: {processed}, Skipped(Exists): {skipped_exists}, Skipped(Duplicate): {skipped_duplicate}, Failed: {failed}")
    
    logger.info("\nGenerating malicious code duplication report...")
    
    code_hash_map = collect_code_hash_info(TARGET_DIR)
    
    duplicate_report = []
    for code_hash, info in code_hash_map.items():
        if len(info['packages']) > 1:
            duplicate_report.append({
                "hash": code_hash,
                "count": len(info['packages']),
                "packages": info['packages'],
                "code": info['code'],
                "type": info['type'],
                "first_analysis": info['first_analysis_package'],
                "first_path": info['first_analysis_path']
            })
    
    duplicate_report.sort(key=lambda x: x['count'], reverse=True)
    
    dup_report_path = os.path.join(TARGET_DIR, "duplicate_code_report.json")
    with open(dup_report_path, 'w', encoding='utf-8') as f:
        json.dump(duplicate_report, f, ensure_ascii=False, indent=2)
    
    duplicate_index = {}
    for dup_pattern in duplicate_report:
        for pkg in dup_pattern['packages'][1:]:
            duplicate_index[pkg] = {
                "hash": dup_pattern['hash'],
                "duplicate_of": dup_pattern['first_analysis'],
                "total_duplicates": dup_pattern['count']
            }
    
    dup_index_path = os.path.join(TARGET_DIR, "duplicate_package_index.json")
    with open(dup_index_path, 'w', encoding='utf-8') as f:
        json.dump(duplicate_index, f, ensure_ascii=False, indent=2)
    
    summary_path = os.path.join(TARGET_DIR, "processing_summary.txt")
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(f"Malicious Code Processing Summary\n")
        f.write(f"==============\n\n")
        f.write(f"Total txt files: {len(txt_files)}\n")
        f.write(f"Successfully processed: {processed}\n")
        f.write(f"Skipped (Already exists): {skipped_exists}\n")
        f.write(f"Skipped (Duplicate code): {skipped_duplicate}\n")
        f.write(f"Processing failed: {failed}\n\n")
        
        f.write(f"Duplicate malicious code patterns: {len(duplicate_report)}\n\n")
        
        if duplicate_report:
            f.write(f"Top 10 duplicate malicious code patterns:\n")
            f.write(f"-------------------\n\n")
            for i, pattern in enumerate(duplicate_report[:10], 1):
                f.write(f"{i}. Occurrence count: {pattern['count']} packages\n")
                f.write(f"   Type: {pattern['type']}\n")
                f.write(f"   Hash value: {pattern['hash']}\n")
                f.write(f"   First analysis package: {pattern['first_analysis']}\n")
                f.write(f"   Code:\n")
                for line in pattern['code'].split('\n'):
                    f.write(f"     {line}\n")
                f.write(f"   Package list: {', '.join(pattern['packages'][:5])}{'...' if len(pattern['packages']) > 5 else ''}\n\n")
    
    logger.info(f"\nProcessing complete: Success {processed}, Skipped(Exists) {skipped_exists}, Skipped(Duplicate) {skipped_duplicate}, Failed {failed}")
    logger.info(f"Duplicate malicious code patterns: {len(duplicate_report)}")
    logger.info(f"Duplicate code report saved to: {dup_report_path}")
    logger.info(f"Duplicate package index saved to: {dup_index_path}")
    logger.info(f"Processing summary saved to: {summary_path}")

def collect_code_hash_info(target_dir):
    """Collect code hash information from generated JSON files"""
    code_hash_map = {}
    json_files = [f for f in os.listdir(target_dir) if f.endswith('.json') and f not in ["duplicate_code_report.json", "duplicate_package_index.json"]]
    
    for json_file in json_files:
        try:
            with open(os.path.join(target_dir, json_file), 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                package_name = os.path.splitext(json_file)[0]
                source_path = None
                
                for item in data:
                    if "metadata" in item:
                        source_path = item.get("metadata", {}).get("report_path", "")
                        break
                
                for item in data:
                    if "context_snippet" in item:
                        code_snippet = item.get("context_snippet", "")
                        code_hash = item.get("hash_value", "")
                        detection_type = item.get("type_description", "")
                        
                        if code_hash and code_snippet:
                            if code_hash not in code_hash_map:
                                code_hash_map[code_hash] = {
                                    'code': code_snippet,
                                    'type': detection_type,
                                    'packages': [package_name],
                                    'first_analysis_package': package_name,
                                    'first_analysis_path': source_path or ""
                                }
                            else:
                                code_hash_map[code_hash]['packages'].append(package_name)
                        
        except Exception as e:
            logger.error(f"Error collecting hash information for file {json_file}: {e}")
    
    return code_hash_map

def test_single_file(file_path):
    """Test processing a single file, including LLM processing and result saving"""
    logger.info(f"Testing file: {file_path}")
    
    try:
        txt_file = os.path.basename(file_path)
        
        json_file = os.path.join(TARGET_DIR, os.path.splitext(txt_file)[0] + '.json')
        if os.path.exists(json_file):
            logger.info(f"JSON file already exists: {json_file}, skipping")
            return
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt_content = f.read()
        
        logger.info(f"File size: {len(txt_content)} characters")
        logger.info(f"First 200 characters of file {file_path}:")
        logger.info(txt_content[:200])
        
        should_process = should_process_file(txt_content)
        logger.info(f"Should process: {should_process}")
        
        if not should_process:
            logger.info(f"File {txt_file} does not need processing")
            return
        
        malicious_locations, match_count = extract_malicious_locations(txt_content)
        logger.info(f"Match count: {match_count}")
        
        if not malicious_locations or match_count == 0:
            logger.info(f"File {txt_file} No malicious code locations found")
            return
        
        final_result = []
        
        metadata_entry = {
            "metadata": {
                "package_name": os.path.splitext(txt_file)[0],
                "report_path": file_path,
                "total_matches": match_count
            }
        }
        final_result.append(metadata_entry)
        
        for full_path, location_infos in malicious_locations.items():
            logger.info(f"Processing Python file: {full_path}, contains {len(location_infos)} matches")
            
            code_content = read_source_code(full_path)
            if not code_content:
                logger.error(f"Cannot read source code: {full_path}")
                continue
            
            logger.info(f"Using LLM to analyze code snippets, {len(location_infos)} detection points")
            llm_results = process_with_llm(code_content, location_infos, PROMPT_PATH)
            if not llm_results:
                logger.error(f"LLM processing failed: {full_path}")
                continue
            
            file_name = os.path.basename(full_path)
            
            for i, context_result in enumerate(llm_results):
                try:
                    if "extracted_context" in context_result:
                        context_code = context_result["extracted_context"]
                    elif "malicious_code" in context_result:
                        context_code = context_result["malicious_code"]
                    else:
                        logger.warning(f"Warning: LLM response JSON contains neither 'malicious_code' nor 'extracted_context' field: {full_path} detection point {i+1}")
                        continue
                    
                    if context_code.strip() == "":
                        logger.info(f"LLM determined file {full_path} detection point {i+1} does not contain malicious code, skipping")
                        continue
                    
                    context_hash = hash_code(context_code)
                    
                    malicious_entry = {
                        "pyfile": file_name,
                        "full_path": full_path,
                        "line_number": context_result.get('line_number', 'unknown'),
                        "type_description": context_result.get('type_description', 'unknown'),
                        "original_snippet": context_result.get('original_snippet', ''),
                        "context_snippet": context_code,
                        "hash_value": context_hash,
                        "detection_index": i+1
                    }
                    
                    final_result.append(malicious_entry)
                    logger.info(f"Successfully extracted context: file {file_name}, detection point {i+1}")
                
                except Exception as e:
                    logger.error(f"Error processing detection point {i+1} result: {e}")
            
        if len(final_result) > 1:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(final_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Generated JSON file: {json_file}")
        else:
            logger.info(f"{txt_file} No valid malicious code found")
            
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    logger.info("Starting execution of benign_code_snippets.py")
    logger.info(f"Log file path: {LOG_FILE}")
    
    test_file = "/home2/blue/Documents/PyPIAgent/Codes/tool_detect/detect_output/study/guarddog/benign/aeidon-1.15.txt"
    
    main()