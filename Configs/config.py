"""PyGuard Configuration Module

Centralized configuration for all PyGuard components.
"""

import os
from pathlib import Path


PYGUARD_ROOT = Path(__file__).parent.parent


class PyGuardConfig:
    """Centralized configuration for PyGuard system."""

    PYGUARD_ROOT = PYGUARD_ROOT

    RESOURCES_DIR = PYGUARD_ROOT / "Resources"
    PROMPTS_DIR = RESOURCES_DIR / "Prompts"
    TAXONOMY_DIR = RESOURCES_DIR / "Taxonomy"

    CONFIGS_DIR = PYGUARD_ROOT / "Configs"
    LLM_CONFIG_PATH = CONFIGS_DIR / "llm_config.json"

    OUTPUT_DIR = PYGUARD_ROOT / "Output"

    RAG_DATABASE_DIR = PYGUARD_ROOT / "Core" / "RAG" / "rag_knowledge_base"

    DETECT_PROMPTS_DIR = PROMPTS_DIR / "detect_prompts"
    RAG_PROMPTS_DIR = PROMPTS_DIR / "rag_prompts"
    CODESLICE_PROMPTS_DIR = PROMPTS_DIR / "codeslice"
    ACTION_SEQUENCE_PROMPTS_DIR = PROMPTS_DIR / "action_sequence"

    ACTION_CATEGORIES_PATH = TAXONOMY_DIR / "action_categories.json"

    MAX_ANALYSIS_FILES = 500
    FILE_ANALYSIS_WORKERS = 4
    PACKAGE_UNDERSTANDING_MAX_TOKENS = 200000

    @classmethod
    def get_prompt_by_name(cls, prompt_name: str) -> Path:
        """Get prompt file path by name."""
        prompt_mapping = {
            "code_slicing": cls.DETECT_PROMPTS_DIR / "code_slicing_prompt.txt",
            "package_understanding": cls.DETECT_PROMPTS_DIR / "package_understand_prompt.txt",
            "triple_analysis": cls.DETECT_PROMPTS_DIR / "triple_analysis_prompt_predefined.txt",
            "malware_detection": cls.RAG_PROMPTS_DIR / "malware_detection_prompt.txt",
            "pattern_analysis": cls.RAG_PROMPTS_DIR / "pattern_analysis_prompt.txt",
            "case_analysis": cls.RAG_PROMPTS_DIR / "case_analysis_prompt.txt",
        }
        return prompt_mapping.get(prompt_name, cls.PROMPTS_DIR / f"{prompt_name}.txt")


    @classmethod
    def get_api_category_path(cls, category_name: str) -> Path:
        """Get API category file path."""
        return cls.TAXONOMY_DIR / category_name


    @classmethod
    def get_file_analysis_workers(cls) -> int:
        """Get number of parallel workers for file analysis."""
        env_workers = os.environ.get("PYGUARD_FILE_WORKERS")
        if env_workers:
            try:
                return int(env_workers)
            except ValueError:
                pass
        return cls.FILE_ANALYSIS_WORKERS


    @classmethod
    def ensure_output_dir(cls) -> Path:
        """Ensure output directory exists and return path."""
        cls.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        return cls.OUTPUT_DIR
