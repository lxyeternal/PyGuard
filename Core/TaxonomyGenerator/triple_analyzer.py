"""
Triple Analyzer: Extract behavioral triples (Action, Object, Intention) from code snippets.
Uses predefined taxonomy categories and LLM for semantic analysis via Card Sorting method.
"""
import os
import sys
import json
import argparse
from pathlib import Path

PYGUARD_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PYGUARD_ROOT))
from Utils.llmquery import LLMAgent

TAXONOMY_DIR = Path(__file__).parent / "api_categories"
PROMPTS_DIR = PYGUARD_ROOT / "Resources" / "Prompts" / "taxonomy"
OUTPUT_DIR = Path(__file__).parent / "triple_description"
LLM_CONTEXT_DIR = PYGUARD_ROOT / "Core" / "ContextExtractor" / "llm_extracted_context"

DATASET_CONFIGS = {
    "malware": {
        "input_dir": LLM_CONTEXT_DIR / "malware",
        "output_dir": OUTPUT_DIR / "malware",
        "code_field": "malicious_code_snippets"
    },
    "benign_guarddog": {
        "input_dir": LLM_CONTEXT_DIR / "benign_guarddog",
        "output_dir": OUTPUT_DIR / "benign",
        "code_field": "context_snippet"
    },
    "malware_fn": {
        "input_dir": LLM_CONTEXT_DIR / "malware_fn",
        "output_dir": OUTPUT_DIR / "malware_fn",
        "code_field": "malicious_code"
    },
    "benign_bandit4mal": {
        "input_dir": LLM_CONTEXT_DIR / "benign_bandit4mal",
        "output_dir": OUTPUT_DIR / "benign_bandit4mal",
        "code_field": "context_snippet"
    }
}


class TripleAnalyzer:
    """Extract (Action, Object, Intention) triples from code snippets using Card Sorting."""

    def __init__(self, dataset_type="malware"):
        self.dataset_type = dataset_type
        self.config = DATASET_CONFIGS.get(dataset_type)
        if not self.config:
            raise ValueError(f"Unknown dataset type: {dataset_type}")
        self.llm_agent = LLMAgent()
        self.actions, self.objects, self.intentions = self._load_taxonomy()
        self.prompt = self._build_prompt()
        os.makedirs(self.config["output_dir"], exist_ok=True)

    def _load_taxonomy(self):
        """Load action, object, and intention categories. Create empty if not exist."""
        actions = self._load_or_create_json("action_classification.json")
        objects = self._load_or_create_json("object_classification.json")
        intentions = self._load_or_create_json("intension_classification.json")
        return actions, objects, intentions

    def _load_or_create_json(self, filename):
        """Load JSON file, create empty list if not exist."""
        path = TAXONOMY_DIR / filename
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump([], f)
        print(f"Created empty taxonomy file: {path}")
        return []

    def _update_taxonomy(self, triples):
        """Update taxonomy files with new categories from LLM analysis (Card Sorting)."""
        action_ids = {item["id"] for item in self.actions}
        object_ids = {item["id"] for item in self.objects}
        intention_ids = {item["id"] for item in self.intentions}
        new_actions, new_objects, new_intentions = [], [], []
        for triple in triples:
            action_id = triple.get("action_id", "")
            action_desc = triple.get("action_description", "")
            if action_id and action_id not in action_ids:
                new_actions.append({"id": action_id, "description": action_desc})
                action_ids.add(action_id)
            object_id = triple.get("object_id", "")
            object_desc = triple.get("object_description", "")
            if object_id and object_id not in object_ids:
                new_objects.append({"id": object_id, "description": object_desc})
                object_ids.add(object_id)
            intention_id = triple.get("intention_id", "")
            intention_desc = triple.get("intention_description", "")
            if intention_id and intention_id not in intention_ids:
                new_intentions.append({"id": intention_id, "description": intention_desc})
                intention_ids.add(intention_id)
        if new_actions:
            self.actions.extend(new_actions)
            self._save_json("action_classification.json", self.actions)
            print(f"Added {len(new_actions)} new actions to taxonomy")
        if new_objects:
            self.objects.extend(new_objects)
            self._save_json("object_classification.json", self.objects)
            print(f"Added {len(new_objects)} new objects to taxonomy")
        if new_intentions:
            self.intentions.extend(new_intentions)
            self._save_json("intension_classification.json", self.intentions)
            print(f"Added {len(new_intentions)} new intentions to taxonomy")

    def _save_json(self, filename, data):
        """Save data to JSON file."""
        path = TAXONOMY_DIR / filename
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _build_prompt(self):
        """Build analysis prompt with taxonomy categories."""
        prompt_path = PROMPTS_DIR / "triple_analysis_prompt_predefined.txt"
        if not prompt_path.exists():
            print(f"Warning: Prompt file not found: {prompt_path}")
            return ""
        with open(prompt_path, 'r', encoding='utf-8') as f:
            template = f.read()
        prompt = template.replace("{action_categories_json}", json.dumps(self.actions, ensure_ascii=False, indent=2))
        prompt = prompt.replace("{object_categories_json}", json.dumps(self.objects, ensure_ascii=False, indent=2))
        prompt = prompt.replace("{intention_categories_json}", json.dumps(self.intentions, ensure_ascii=False, indent=2))
        return prompt

    def analyze_snippet(self, code_snippet):
        """Extract triple sequences from a code snippet using Card Sorting."""
        if not code_snippet or not self.prompt:
            return []
        try:
            messages = [
                {"role": "system", "content": self.prompt},
                {"role": "user", "content": f"""
                    Please analyze the following Python code snippet and extract behavioral triple sequences:

                    ```python
                    {code_snippet}
                    ```

                    IMPORTANT: Prefer using predefined categories. If no suitable category exists, you may create a new one.
                    """}
            ]
            response = self.llm_agent.perform_query(messages)
            try:
                data = json.loads(response)
                triples = data.get("triple_sequences", [])
                if triples:
                    self._update_taxonomy(triples)
                return triples
            except json.JSONDecodeError:
                print(f"LLM returned invalid JSON")
                return []
        except Exception as e:
            print(f"Error analyzing snippet: {e}")
            return []

    def _transform_malware_fn_data(self, raw_data, json_file_path):
        """Transform LLM analysis data from false_negative/llm_analysis to standard format."""
        package_name = os.path.basename(json_file_path).rsplit('.', 1)[0]
        metadata = {
            "package_name": package_name,
            "original_json_path": str(json_file_path),
            "dataset_type": "malware_fn"
        }
        transformed_files = []
        for entry in raw_data:
            file_path = entry.get("file_path", "")
            malicious_code = entry.get("malicious_code", "")
            pyfile = os.path.basename(file_path) if file_path else "unknown.py"
            transformed_files.append({
                "pyfile": pyfile,
                "full_path": file_path,
                "malicious_code_snippets": malicious_code
            })
        return [{"metadata": metadata}] + transformed_files

    def process_file(self, input_path):
        """Process single code file and generate triple sequences."""
        package_name = os.path.basename(input_path).rsplit('.', 1)[0]
        output_path = self.config["output_dir"] / f"{package_name}.json"
        if output_path.exists():
            print(f"Skipping already analyzed: {package_name}")
            with open(output_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        print(f"Processing: {package_name}")
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            if not raw_data or raw_data == []:
                print(f"Skipping empty file: {input_path}")
                return None
            # Transform malware_fn data format
            if self.dataset_type == "malware_fn":
                code_data = self._transform_malware_fn_data(raw_data, input_path)
            else:
                code_data = raw_data
            # Extract metadata
            metadata = {"package_name": package_name, "original_json_path": str(input_path), "dataset_type": self.dataset_type}
            for item in code_data:
                if isinstance(item, dict) and "metadata" in item:
                    metadata.update(item["metadata"])
                    break
            result = {"metadata": metadata, "code_files": []}
            # Find code item and analyze
            for item in code_data:
                if isinstance(item, dict) and "metadata" not in item:
                    code_snippet = ""
                    # Try different code fields
                    for field in ["malicious_code_snippets", "context_snippet", "malicious_code", "code_snippets"]:
                        if field in item and item[field]:
                            code_snippet = item[field]
                            break
                    if not code_snippet:
                        continue
                    triples = self.analyze_snippet(code_snippet)
                    file_info = {"pyfile": item.get("pyfile", "unknown.py")}
                    for field in ["full_path", "line_number", "type_description", "severity", "confidence"]:
                        if field in item:
                            file_info[field] = item[field]
                    file_info["code_snippets"] = [{"snippet": code_snippet, "triple_sequences": triples}]
                    result["code_files"].append(file_info)
                    break  # Only process first code item
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"Saved: {output_path}")
            return result
        except Exception as e:
            print(f"Error processing {input_path}: {e}")
            return None

    def process_all(self):
        """Process all code files in input directory."""
        input_dir = self.config["input_dir"]
        if not input_dir.exists():
            print(f"Error: Input directory does not exist: {input_dir}")
            return []
        json_files = [f for f in os.listdir(input_dir) if f.endswith('.json')]
        print(f"Found {len(json_files)} JSON files in {input_dir}")
        results = []
        for i, filename in enumerate(json_files, 1):
            input_path = input_dir / filename
            result = self.process_file(input_path)
            if result:
                results.append(result)
            if i % 10 == 0:
                print(f"Progress: {i}/{len(json_files)}")
        # Save summary
        summary_path = self.config["output_dir"] / f"all_{self.dataset_type}_analysis.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump({f"{self.dataset_type}_reports": results, "total_files": len(results)}, f, ensure_ascii=False, indent=2)
        print(f"Summary saved: {summary_path}")
        return results


def extract_triples_from_result(result):
    """Extract all triples from an analysis result."""
    triples = []
    for code_file in result.get("code_files", []):
        for snippet in code_file.get("code_snippets", []):
            triples.extend(snippet.get("triple_sequences", []))
    return triples


def aggregate_triples(results):
    """Aggregate triples from multiple results."""
    all_triples = []
    for result in results:
        all_triples.extend(extract_triples_from_result(result))
    return all_triples


def main():
    parser = argparse.ArgumentParser(description="Analyze code snippets to extract behavioral triples")
    parser.add_argument("--dataset", type=str, default="malware",
                       choices=["malware", "benign_guarddog", "malware_fn", "benign_bandit4mal", "all"],
                       help="Dataset type to analyze")
    args = parser.parse_args()

    if args.dataset == "all":
        datasets = ["malware", "benign_guarddog", "malware_fn", "benign_bandit4mal"]
    else:
        datasets = [args.dataset]

    print(f"Starting Triple Analysis (Card Sorting)")
    print(f"Taxonomy dir: {TAXONOMY_DIR}")
    print(f"Output dir: {OUTPUT_DIR}")

    for dataset_type in datasets:
        print(f"\n=== Processing dataset: {dataset_type} ===")
        try:
            analyzer = TripleAnalyzer(dataset_type=dataset_type)
            analyzer.process_all()
        except Exception as e:
            print(f"Error processing {dataset_type}: {e}")
            continue

    print("\nAll processing completed!")


if __name__ == "__main__":
    main()
