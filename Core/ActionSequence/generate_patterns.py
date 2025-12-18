import json
import os
import sys
from typing import Dict, List, Any, Tuple
import time
import re
import multiprocessing
from functools import partial

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(PYGUARD_ROOT)
from Utils.llmquery import LLMAgent

def init_worker():
    global llm_agent
    llm_agent = LLMAgent()

def process_json_file_worker(
    task: str,
    api_classification_path: str,
    api_categories_path: str,
    prompt_template_path: str,
    input_base_path: str,
    output_base_path: str,
    code_field: str = "context_snippet"
) -> bool:
    """Function to process single JSON file, used for multiprocessing"""
    json_file = task
    input_file_path = os.path.join(input_base_path, json_file)
    output_file_path = os.path.join(output_base_path, json_file)
    
    print(f"Processing file: {json_file}")
    
    try:
        if os.path.exists(output_file_path) and os.path.getsize(output_file_path) > 0:
            print(f"Skipping already processed file: {json_file}")
            return True
        
        api_classification = _load_api_classification(api_classification_path)
        api_categories = _load_api_categories(api_categories_path)
        prompt_template = _load_prompt_template(prompt_template_path)
        
        with open(input_file_path, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        
        output_data = []
        
        metadata = None
        for item in input_data:
            if "metadata" in item:
                metadata = item["metadata"].copy()
                # Remove absolute paths from metadata
                if "report_path" in metadata:
                    del metadata["report_path"]
                if "original_json_path" in metadata:
                    del metadata["original_json_path"]
                output_data.append({"metadata": metadata})
                break
        
        global llm_agent
        
        for code_item in input_data:
            if code_field not in code_item:
                continue

            code = code_item.get(code_field, "")
            if not code:
                continue
            
            print(f"   Analyzing code snippet...")
            
            pattern_result = extract_code_pattern(code, api_classification, api_categories, prompt_template, llm_agent)
            
            if "mapped_sequence" in pattern_result:
                for api_item in pattern_result["mapped_sequence"]:
                    if "id" in api_item and not all(key in api_item for key in ["first_id", "second_id", "third_id"]):
                        api_id = api_item["id"]
                        first_id, second_id, third_id = find_category_hierarchy(api_id, api_categories)
                        api_item["first_id"] = first_id
                        api_item["second_id"] = second_id
                        api_item["third_id"] = third_id
            
            result_item = {
                "pyfile": code_item.get("pyfile", ""),
                "full_path": code_item.get("full_path", ""),
                "line_number": code_item.get("line_number", ""),
                "type_description": code_item.get("type_description", ""),
                "severity": code_item.get("severity", ""),
                "confidence": code_item.get("confidence", ""),
                "original_snippet": code_item.get("original_snippet", ""),
                "code_snippet": code,
                "pattern_analysis": pattern_result
            }
            
            output_data.append(result_item)
        
        _ensure_directory_exists(os.path.dirname(output_file_path))
        with open(output_file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
            
        print(f"Processing completed, results saved to: {output_file_path}")
        return True
        
    except Exception as e:
        print(f"Error processing file {json_file}: {e}")
        return False
    
    time.sleep(2)

def _load_prompt_template(prompt_template_path: str) -> str:
    """Load prompt template"""
    try:
        with open(prompt_template_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Failed to load prompt template file: {e}")
        return ""

def _load_api_categories(api_categories_path: str) -> Dict:
    """Load API category mapping"""
    try:
        with open(api_categories_path, 'r', encoding='utf-8') as f:
            api_categories = json.load(f)
            return api_categories
    except Exception as e:
        print(f"Failed to load API category mapping file: {e}")
        return {}

def _load_api_classification(api_classification_path: str) -> Dict:
    """Load API classification used for LLM prompt (used for generating prompt)"""
    try:
        with open(api_classification_path, 'r', encoding='utf-8') as f:
            api_classification = json.load(f)
            return api_classification
    except Exception as e:
        print(f"Failed to load LLM prompt API classification file: {e}")
        return {}

def _ensure_directory_exists(directory: str):
    """Ensure directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_pattern_extract_prompt(code: str, api_categories: Dict, prompt_template: str) -> str:
    """Generate prompt for extracting code patterns"""
    categories_str = json.dumps(api_categories, indent=2, ensure_ascii=False)
    
    prompt = prompt_template.replace("{CATEGORIES}", categories_str).replace("{CODE}", code)
    
    return prompt

def get_pattern_extract_prompt(code: str, api_classification: Dict, prompt_template: str) -> str:
    """Generate prompt for extracting code patterns, using api_classification"""
    categories_str = json.dumps(api_classification, indent=2, ensure_ascii=False)
    
    prompt = prompt_template.replace("{CATEGORIES}", categories_str).replace("{CODE}", code)
    
    return prompt

def find_category_hierarchy(api_id: str, api_categories: Dict) -> Tuple[str, str, str]:
    """
    Find the third-level category ID corresponding to the given api_id in api_categories
    
    Args:
        api_id: API behavior ID
        api_categories: (API categories data)
        
    Returns:
        Tuple containing first_id, second_id, and third_id, or empty strings if not found
    """
    if isinstance(api_categories, dict):
        categories = api_categories.get("categories", [])
    else:
        categories = api_categories if isinstance(api_categories, list) else []
    
    for first_category in categories:
        if not isinstance(first_category, dict):
            continue
            
        first_id = first_category.get("id", "")
        subcategories = first_category.get("subcategories", [])
        
        for second_category in subcategories:
            if not isinstance(second_category, dict):
                continue
                
            second_id = second_category.get("id", "")
            subsubcategories = second_category.get("subsubcategories", [])
            
            for third_category in subsubcategories:
                if not isinstance(third_category, dict):
                    continue
                    
                third_id = third_category.get("id", "")
                behaviors = third_category.get("behaviors", [])
                
                for behavior in behaviors:
                    if not isinstance(behavior, dict):
                        continue
                        
                    if behavior.get("id", "") == api_id:
                        return first_id, second_id, third_id
    
    return "", "", ""

def extract_code_pattern(
    code: str, 
    api_classification: Dict,
    api_categories: Dict,
    prompt_template: str, 
    llm_agent: LLMAgent
) -> Dict:
    """Extract code pattern"""
    prompt = get_pattern_extract_prompt(code, api_classification, prompt_template)
    
    messages = [
        {"role": "system", "content": "You are a professional code analysis expert, specializing in identifying patterns and API calls in code."},
        {"role": "user", "content": prompt}
    ]
    
    try:
        response = llm_agent.perform_query(
            messages=messages,
            response_format={"type": "json_object"}
        )
        
        try:
            result = json.loads(response)
            
            if "mapped_sequence" in result:
                for api_item in result["mapped_sequence"]:
                    if "id" in api_item and not all(key in api_item for key in ["first_id", "second_id", "third_id"]):
                        api_id = api_item["id"]
                        first_id, second_id, third_id = find_category_hierarchy(api_id, api_categories)
                        api_item["first_id"] = first_id
                        api_item["second_id"] = second_id
                        api_item["third_id"] = third_id
            
            return result
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            print(f"Original response: {response}")
            return {
                "error": "JSON parse error",
                "raw_response": response,
                "api_sequence": [],
                "api_sequence_with_args": [],
                "mapped_sequence": [],
                "contextual_code": ""
            }
            
    except Exception as e:
        print(f"Error extracting code pattern: {e}")
        return {
            "error": str(e),
            "api_sequence": [],
            "api_sequence_with_args": [],
            "mapped_sequence": [],
            "contextual_code": ""
        }

DATASET_CONFIGS = {
    "malware": {
        "input_dir": "malware",
        "output_dir": "malware",
        "code_field": "malicious_code_snippets"
    },
    "benign_guarddog": {
        "input_dir": "benign_guarddog",
        "output_dir": "benign_guarddog",
        "code_field": "context_snippet"
    },
    "malware_fn": {
        "input_dir": "malware_fn",
        "output_dir": "malware_fn",
        "code_field": "malicious_code"
    },
    "benign_bandit4mal": {
        "input_dir": "benign_bandit4mal",
        "output_dir": "benign_bandit4mal",
        "code_field": "context_snippet"
    }
}

class PatternGenerator:
    def __init__(self, dataset_type="benign_bandit4mal"):
        """Initialize pattern generator"""
        self.dataset_type = dataset_type
        self.config = DATASET_CONFIGS.get(dataset_type)
        if not self.config:
            raise ValueError(f"Unknown dataset type: {dataset_type}")
        self.llm_agent = LLMAgent()

        self.api_classification_path = os.path.join(
            PYGUARD_ROOT,
            "Core",
            "TaxonomyGenerator",
            "api_categories",
            "api_classification.json"
        )

        self.api_categories_path = os.path.join(
            PYGUARD_ROOT,
            "Core",
            "TaxonomyGenerator",
            "api_categories",
            "api_final_categories.json"
        )

        self.prompt_template_path = os.path.join(
            PYGUARD_ROOT,
            "Resources",
            "Prompts",
            "action_sequence",
            "pattern_extract.txt"
        )

        self.input_base_path = os.path.join(
            PYGUARD_ROOT,
            "Core",
            "ContextExtractor",
            "llm_extracted_context",
            self.config["input_dir"]
        )
        self.output_base_path = os.path.join(
            PYGUARD_ROOT,
            "Core",
            "ActionSequence",
            self.config["output_dir"]
        )
        
        self.api_categories = self._load_api_categories()
        self.api_classification = self._load_api_classification()
        self.prompt_template = self._load_prompt_template()
        
        self._ensure_directory_exists(self.output_base_path)
        
    def _load_prompt_template(self) -> str:
        """Load prompt template"""
        try:
            with open(self.prompt_template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Failed to load prompt template file: {e}")
            return ""

    def _load_api_categories(self) -> Dict:
        """Load full API category mapping (used for finding upper-level category ID)"""
        try:
            with open(self.api_categories_path, 'r', encoding='utf-8') as f:
                api_categories = json.load(f)
                return api_categories
        except Exception as e:
            print(f"Failed to load full API category mapping file: {e}")
            return {}

    def _load_api_classification(self) -> Dict:
        """Load API classification used for LLM prompt (used for generating prompt)"""
        try:
            with open(self.api_classification_path, 'r', encoding='utf-8') as f:
                api_classification = json.load(f)
                return api_classification
        except Exception as e:
            print(f"Failed to load LLM prompt API classification file: {e}")
            return {}
    
    def _ensure_directory_exists(self, directory: str):
        """Ensure directory exists"""
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    def get_pattern_extract_prompt(self, code: str) -> str:
        """
        Generate prompt for extracting code patterns
        
        Args:
            code: Code string to analyze
            
        Returns:
            Prompt string
        """
        categories_str = json.dumps(self.api_classification, indent=2, ensure_ascii=False)
        
        prompt = self.prompt_template.replace("{CATEGORIES}", categories_str).replace("{CODE}", code)
        
        return prompt
    
    def extract_code_pattern(self, code: str) -> Dict:
        """
        Extract code pattern
        
        Args:
            code: Code string to analyze
            
        Returns:
            Dictionary containing extracted pattern
        """
        prompt = self.get_pattern_extract_prompt(code)
        
        messages = [
            {"role": "system", "content": "You are a professional code analysis expert, specializing in identifying patterns and API calls in code."},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.llm_agent.perform_query(
                messages=messages,
                response_format={"type": "json_object"}
            )
            
            try:
                result = json.loads(response)
                
                if "mapped_sequence" in result:
                    for api_item in result["mapped_sequence"]:
                        if "id" in api_item and not all(key in api_item for key in ["first_id", "second_id", "third_id"]):
                            api_id = api_item["id"]
                            first_id, second_id, third_id = find_category_hierarchy(api_id, self.api_categories)
                            api_item["first_id"] = first_id
                            api_item["second_id"] = second_id
                            api_item["third_id"] = third_id
                
                return result
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON response: {e}")
                print(f"Original response: {response}")
                return {
                    "error": "JSON parse error",
                    "raw_response": response,
                    "api_sequence": [],
                    "api_sequence_with_args": [],
                    "mapped_sequence": [],
                    "contextual_code": ""
                }
                
        except Exception as e:
            print(f"Error extracting code pattern: {e}")
            return {
                "error": str(e),
                "api_sequence": [],
                "api_sequence_with_args": [],
                "mapped_sequence": [],
                "contextual_code": ""
            }
    
    def process_json_file(self, input_file_path: str, output_file_path: str):
        """Process single JSON file"""
        print(f"Processing file: {input_file_path}")
        try:
            with open(input_file_path, 'r', encoding='utf-8') as f:
                input_data = json.load(f)
            
            output_data = []
            
            metadata = None
            for item in input_data:
                if "metadata" in item:
                    metadata = item["metadata"]
                    output_data.append({"metadata": metadata})
                    break
            
            code_field = self.config["code_field"]
            for code_item in input_data:
                if code_field not in code_item:
                    continue

                code = code_item.get(code_field, "")
                if not code:
                    continue

                print(f"   Analyzing code snippet...")
                pattern_result = self.extract_code_pattern(code)
                
                if "mapped_sequence" in pattern_result:
                    for api_item in pattern_result["mapped_sequence"]:
                        if "id" in api_item and not all(key in api_item for key in ["first_id", "second_id", "third_id"]):
                            api_id = api_item["id"]
                            first_id, second_id, third_id = find_category_hierarchy(api_id, self.api_categories)
                            api_item["first_id"] = first_id
                            api_item["second_id"] = second_id
                            api_item["third_id"] = third_id
                
                result_item = {
                    "pyfile": code_item.get("pyfile", ""),
                    "full_path": code_item.get("full_path", ""),
                    "line_number": code_item.get("line_number", ""),
                    "type_description": code_item.get("type_description", ""),
                    "severity": code_item.get("severity", ""),
                    "confidence": code_item.get("confidence", ""),
                    "code_snippet": code,
                    "pattern_analysis": pattern_result
                }
                
                output_data.append(result_item)
            
            self._ensure_directory_exists(os.path.dirname(output_file_path))
            with open(output_file_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
                
            print(f"Processing completed, results saved to: {output_file_path}")
            return True
        
        except Exception as e:
            print(f"Error processing file {input_file_path}: {e}")
            return False
    
    def process_directory(self, num_processes=8):
        """Process all JSON files in malware directory, support multiprocessing"""
        input_dir = self.input_base_path
        output_dir = self.output_base_path
        
        if not os.path.exists(input_dir):
            print(f"Input directory does not exist: {input_dir}")
            return
        
        self._ensure_directory_exists(output_dir)
        
        json_files = [f for f in os.listdir(input_dir) if f.endswith('.json')]
        total_files = len(json_files)
        
        print(f"Start processing {total_files} files, from {input_dir} to {output_dir}")
        
        if num_processes <= 1:
            print(f"Using single process mode to process files")
            processed_count = 0
            
            for i, json_file in enumerate(json_files):
                input_file_path = os.path.join(input_dir, json_file)
                output_file_path = os.path.join(output_dir, json_file)
                
                print(f"[{i+1}/{total_files}] Processing: {json_file}")
                success = self.process_json_file(input_file_path, output_file_path)
                
                if success:
                    processed_count += 1
                else:
                    print(f"Failed to process file {json_file}, skipping")
                
                time.sleep(2)
                
            print(f"All files processed. Success: {processed_count}/{total_files}")
        else:
            print(f"Using {num_processes} processes to process files")
            
            process_func = partial(
                process_json_file_worker,
                api_classification_path=self.api_classification_path,
                api_categories_path=self.api_categories_path,
                prompt_template_path=self.prompt_template_path,
                input_base_path=self.input_base_path,
                output_base_path=self.output_base_path,
                code_field=self.config["code_field"]
            )
            
            with multiprocessing.Pool(
                processes=num_processes,
                initializer=init_worker
            ) as pool:
                processed_count = 0
                skipped_count = 0
                
                for i, success in enumerate(pool.imap_unordered(process_func, json_files)):
                    if success:
                        processed_count += 1
                    else:
                        skipped_count += 1
                        
                    if (i + 1) % 5 == 0 or (i + 1) == total_files:
                        print(f"Progress: {i+1}/{total_files} files processed, success: {processed_count}, failed: {skipped_count}")
            
            print(f"All files processed. Success: {processed_count}/{total_files}, Failed: {skipped_count}/{total_files}")

def main():
    """Main function"""
    import argparse
    parser = argparse.ArgumentParser(description="Generate API patterns from code snippets")
    parser.add_argument("--dataset", type=str, default="benign_bandit4mal",
                       choices=["malware", "benign_guarddog", "malware_fn", "benign_bandit4mal", "all"],
                       help="Dataset type to process")
    parser.add_argument("--processes", type=int, default=8,
                       help="Number of processes for parallel processing")
    args = parser.parse_args()

    if args.dataset == "all":
        datasets = ["malware", "benign_guarddog", "malware_fn", "benign_bandit4mal"]
    else:
        datasets = [args.dataset]

    for dataset_type in datasets:
        print(f"\n=== Processing dataset: {dataset_type} ===")
        try:
            generator = PatternGenerator(dataset_type=dataset_type)
            generator.process_directory(num_processes=args.processes)
        except Exception as e:
            print(f"Error processing {dataset_type}: {e}")
            continue

    print("\nAll processing completed!")

if __name__ == "__main__":
    main()