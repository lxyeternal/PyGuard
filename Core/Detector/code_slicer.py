"""Code Slicing Engine - Semantic Code Fragment Extraction Module

Core: Code File (path) -> Sliced Fragments
Design: Simple, Clean, Direct
"""

import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PYGUARD_ROOT)

from Utils.llmquery import LLMAgent
from Configs.config import PyGuardConfig


@dataclass
class SliceOutput:
    """Simple output: file slices and metadata"""
    file_path: str
    slices: List[Dict[str, Any]]
    analysis_summary: str
    original_lines: int


class CodeSlicingEngine:
    """Base class defining standard interface"""
    
    def slice(self, file_path: str) -> SliceOutput:
        """Core interface: file path -> slice output"""
        raise NotImplementedError("Subclass must implement slice()")


class LLMBasedSlicing(CodeSlicingEngine):
    """LLM-based slicing implementation"""
    
    def __init__(self):
        self.llm_agent = LLMAgent()
        self.slicing_prompt = self._load_slicing_prompt()
    
    def _load_slicing_prompt(self) -> str:
        prompt_path = PyGuardConfig.get_prompt_by_name("code_slicing")
        if not prompt_path.exists():
            raise FileNotFoundError(f"Slicing prompt not found: {prompt_path}")
        return prompt_path.read_text(encoding='utf-8')
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "slices": [{"code": response}],
                "analysis_summary": "Failed to parse LLM response"
            }
    
    def slice(self, file_path: str) -> SliceOutput:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            if not code_content.strip():
                return SliceOutput(
                    file_path=file_path,
                    slices=[],
                    analysis_summary="Empty file",
                    original_lines=0
                )
            
            prompt = self.slicing_prompt.format(code=code_content)
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages)

            print(f"LLM Response: {response}")
            
            if isinstance(response, dict) and 'response' in response:
                response = response['response']
            
            slices_data = self._parse_llm_response(str(response))
            slices = slices_data.get("slices", [])
            
            base_name = Path(file_path).stem
            for i, slice_item in enumerate(slices):
                slice_item["slice_id"] = f"{base_name}_slice_{i+1}"
                slice_item["file_path"] = file_path
            
            return SliceOutput(
                file_path=file_path,
                slices=slices,
                analysis_summary=slices_data.get("analysis_summary", ""),
                original_lines=len(code_content.splitlines())
            )
        except Exception as e:
            print(f"Code slicing failed: {e}")
            return SliceOutput(
                file_path=file_path,
                slices=[],
                analysis_summary=f"Error: {str(e)}",
                original_lines=0
            )


class CodeSlicer:
    """Simple code slicing interface"""
    
    def __init__(self, slicing_engine: Optional[CodeSlicingEngine] = None):
        self.slicing_engine = slicing_engine or LLMBasedSlicing()
    
    def slice(self, file_path: str) -> SliceOutput:
        """Extract slices from code file"""
        return self.slicing_engine.slice(file_path)


# def main():
#     test_file = "atlasctf-21-prod-02#99.99.99.1/atlasctf_21_prod_02-99.99.99.1/atlasctf_21_prod_02-99.99.99.1/setup.py"
    
#     print("=" * 80)
#     print("Testing LLM Code Slicer")
#     print("=" * 80)
#     print(f"\n📂 Input File: {test_file}\n")
    
#     slicer = CodeSlicer()
#     output = slicer.slice(test_file)

#     print(f"Output: {output}")

# if __name__ == "__main__":
#     main()