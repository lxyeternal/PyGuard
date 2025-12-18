# PyGuard

A malware detection system for PyPI and NPM packages using RAG-based behavioral pattern analysis.

## Project Structure

```
PyGuard/
├── Core/                    # Core detection modules
│   ├── Detector/            # Package analysis and malware detection
│   ├── RAG/                 # RAG knowledge base and query engine
│   ├── ActionSequence/      # Action sequence extraction
│   ├── PatternGenerator/    # Malware pattern generation
│   ├── TaxonomyGenerator/   # API taxonomy generation
│   ├── CodeMarker/          # Code marking utilities
│   └── ContextExtractor/    # Context extraction
├── Dataset/                 # Package datasets
│   ├── PyPI/                # PyPI packages (malware & benign)
│   └── NPM/                 # NPM packages (malware & benign)
├── Experiment/              # Experiment scripts and results
│   └── Results/             # Detection results from various tools
├── Baselines/               # Baseline detection tools
├── Configs/                 # Configuration files
├── Resources/               # Prompts and taxonomy files
├── Scripts/                 # Data collection and utility scripts
├── Utils/                   # LLM query and utility functions
└── Output/                  # Detection output
```

## Core Modules

PyGuard's detection pipeline consists of several core modules:

### 1. Tool Detector (`Core/CodeMarker/tool_detector.py`)

Runs security tools (bandit4mal, guarddog, ossgadget, pypiwarehouse) on packages to mark detection positions.

### 2. Context Extractors (`Core/ContextExtractor/`)

Extract code context from security tool reports using LLM:
- `bandit_fp_extractor.py`: Extract context from bandit false positives (benign code)
- `guarddog_fp_extractor.py`: Extract context from guarddog false positives (benign code)
- `guarddog_malware_extractor.py`: Extract malicious code context from guarddog detections

### 3. Triple Analyzer (`Core/TaxonomyGenerator/triple_analyzer.py`)

Extract behavioral triples (Action, Object, Intention) from code snippets using Card Sorting method with LLM. Builds and updates the API taxonomy.

### 4. Action Sequence Generator (`Core/ActionSequence/generate_patterns.py`)

Map code snippets to action sequences using predefined API taxonomy. Uses LLM to extract and categorize API patterns.

### 5. Pattern Generator (`Core/PatternGenerator/prefixspan_pattern.py`)

Mine frequent sequence patterns using PrefixSpan algorithm. Distinguishes benign-only, malware-only, and biased patterns with hierarchical support levels.

### 6. RAG Knowledge Builder (`Core/RAG/rag_knowledge_builder.py`)

Build RAG knowledge base from pattern data. Creates pattern/case embeddings and FAISS indices for similarity search.

### 7. Package Analyzer (`Core/Detector/package_analyzer.py`) ⭐

**PyGuard's core detection module** - can be used directly for end-to-end malware detection.

```python
from Core.Detector.package_analyzer import PackageAnalyzer

# Initialize analyzer
# detection_mode: "rag" (pure LLM) or "pattern_rag" (pattern first, more efficient)
analyzer = PackageAnalyzer(detection_mode="pattern_rag")

# Analyze a package
result = analyzer.analyze_package(
    package_path="/path/to/package",
    package_manager="pypi",  # or "npm"
    output_path="/path/to/result.json"
)

# Print summary
analyzer.print_summary(result)
```

## Dataset

### Data Format

Each dataset directory contains a `packages.txt` file with package names and versions:
```
package_name-version.tar.gz
package_name-version.whl
```

### PyPI Dataset

| Type | Location | Source |
|------|----------|--------|
| Malware | `Dataset/PyPI/Study/Malware/` | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) |
| Benign | `Dataset/PyPI/Study/Benign/` | PyPI Top Packages |

### NPM Dataset

| Type | Location | Source |
|------|----------|--------|
| Malware | `Dataset/NPM/Malware/` | [Backstabbers-Knife-Collection](https://github.com/cybertier/Backstabbers-Knife-Collection) |
| Benign | `Dataset/NPM/Benign/` | NPM Popular Packages |

### Data Collection

Download packages using scripts in `Scripts/DataCollect/`:

```bash
# Download PyPI packages from packages.txt
python Scripts/DataCollect/download_pypi_packages.py <packages.txt> [--workers 8] [--output <dir>]

# Download NPM packages from packages.txt
python Scripts/DataCollect/download_npm_packages.py <packages.txt> [--workers 8] [--output <dir>]

# Example: Download PyPI benign packages
python Scripts/DataCollect/download_pypi_packages.py Dataset/PyPI/Study/Benign/packages.txt --workers 8

# Example: Download NPM benign packages
python Scripts/DataCollect/download_npm_packages.py Dataset/NPM/Benign/packages.txt --workers 8
```

Downloaded packages are saved in a two-level structure: `<package-version>/<package-version>.tar.gz`

## Experiment Results

Detection results from various tools are stored in `Experiment/Results/`:

### PyPI Results

```
Experiment/Results/PyPI/
├── Evaluation/          # Evaluation dataset results
├── Latest/              # Latest malware dataset results
└── Obfuscation/         # Obfuscated malware dataset results
```

### NPM Results

```
Experiment/Results/NPM/
├── cerebro/
├── gpt-4.1/
├── guarddog/
├── ossgadget/
├── pyguard/
└── sap/
```

### Evaluated Tools

| Tool | Type | Description |
|------|------|-------------|
| pyguard | LLM+RAG | Our proposed method |
| pyguard_gpt-4.1-mini | LLM+RAG | PyGuard with GPT-4.1-mini |
| gpt-4.1 | LLM | Direct GPT-4.1 detection |
| gpt-4.1-mini | LLM | Direct GPT-4.1-mini detection |
| deepseek-v3 | LLM | DeepSeek V3 detection |
| qwen2.5 / qwen3-8b | LLM | Qwen series detection |
| guarddog | Rule-based | DataDog's GuardDog tool |
| guarddog_llm | LLM | GuardDog + LLM enhancement |
| guarddog_rag | RAG | GuardDog + RAG enhancement |
| bandit4mal | Rule-based | Bandit for malware detection |
| hercule | Dynamic | Hercule static analyzer |
| ossgadget | Rule-based | Microsoft OSSGadget |
| sap | Static | SAP static analyzer |
| cerebro | ML | Cerebro ML-based detection (not open-sourced, tested by contacting the original authors) |
| socketai | LLM | Socket.dev AI detection |
| pypiwarehouse | Static | PyPI Warehouse heuristics |

## Resources

### Prompts (`Resources/Prompts/`)

| Directory | File | Purpose |
|-----------|------|---------|
| `detect_prompts/` | `code_slicing_prompt.txt` | LLM prompt for slicing code into semantic fragments |
| `detect_prompts/` | `triple_analysis_prompt_predefined.txt` | Extract (Action, Object, Intention) triples from code |
| `detect_prompts/` | `package_understand_prompt.txt` | Analyze package README for understanding |
| `rag_prompts/` | `malware_detection_prompt.txt` | RAG-based malware detection prompt |
| `rag_prompts/` | `pattern_analysis_prompt.txt` | Analyze malware patterns |
| `rag_prompts/` | `case_analysis_prompt.txt` | Analyze similar malware cases |
| `rag_prompts/` | `basic_detection_prompt.txt` | Basic detection without RAG |
| `rag_prompts/` | `distinction_pattern_instructions.txt` | Instructions for distinguishing patterns |
| `rag_prompts/` | `pure_pattern_instructions.txt` | Pure pattern matching instructions |
| `codeslice/` | `code_snippets_prompt.txt` | Extract code snippets |
| `codeslice/` | `malicious_code_extract.txt` | Extract malicious code segments |
| `codeslice/` | `single_snippets_prompt.txt` | Single snippet extraction |
| `action_sequence/` | `pattern_extract.txt` | Extract action sequence patterns |
| `taxonomy/` | `triple_analysis_prompt_predefined.txt` | Taxonomy-based triple analysis |
| `false_negative_analysis/` | `malicious_code_confirm.txt` | Confirm malicious code |
| `false_negative_analysis/` | `malicious_code_extract.txt` | Extract missed malicious code |

### Taxonomy (`Resources/Taxonomy/`)

| File | Description |
|------|-------------|
| `action_classification.json` | API action categories (e.g., file_read, network_request) |
| `object_classification.json` | Object categories (e.g., file_path, url, credential) |
| `intension_classification.json` | Intention categories (e.g., data_exfiltration, code_execution) |
| `action_categories.json` | Detailed action category definitions |

## Usage

### Quick Start: Package Analysis

```python
from Core.Detector.package_analyzer import PackageAnalyzer

# Use pattern_rag mode for efficient detection
analyzer = PackageAnalyzer(detection_mode="pattern_rag")

result = analyzer.analyze_package(
    package_path="/path/to/extracted/package",
    package_manager="pypi",  # or "npm"
    output_path="/path/to/output.json"
)

analyzer.print_summary(result)
```

### RAG Knowledge Base

```python
from Core.RAG.rag_knowledge_builder import RAGKnowledgeBuilder

# Build knowledge base
builder = RAGKnowledgeBuilder()
builder.build_knowledge_base("patterns_with_cases.json")
builder.save_knowledge_base("rag_knowledge_base/")
```

### Full Pipeline

```bash
# 1. Run security tools on packages
python Core/CodeMarker/tool_detector.py

# 2. Extract code context from tool reports
python Core/ContextExtractor/bandit_fp_extractor.py
python Core/ContextExtractor/guarddog_fp_extractor.py

# 3. Generate action taxonomy (Card Sorting)
python Core/TaxonomyGenerator/triple_analyzer.py --dataset all

# 4. Generate action sequences
python Core/ActionSequence/generate_patterns.py --dataset all

# 5. Mine patterns using PrefixSpan
python Core/PatternGenerator/prefixspan_pattern.py

# 6. Build RAG knowledge base
python Core/RAG/rag_knowledge_builder.py

# 7. Analyze packages
python Core/Detector/package_analyzer.py
```

## Configuration

LLM configuration is in `Configs/llm_config.json`. PyGuard requires both **Chat Model** and **Embedding Model** to be configured.

### Chat Model Configuration

Set `query_type` to choose the chat backend:

| `query_type` | Description | Required Fields |
|--------------|-------------|-----------------|
| `openai` | OpenAI API | `openai_api_key`, `openai_api_model` |
| `azure` | Azure OpenAI | `azure_api_key`, `azure_api_base`, `azure_api_model`, `azure_api_version` |
| `ollama` | Local Ollama | `ollama_model`, `ollama_host`, `ollama_port` |
| `custom_openai` | Custom OpenAI-compatible API | `custom_openai_api_key`, `custom_openai_api_base`, `custom_openai_api_model` |

### Embedding Model Configuration

Set `embedding_backend` to choose the embedding backend:

| `embedding_backend` | Description | Required Fields |
|---------------------|-------------|-----------------|
| `openai` | OpenAI Embedding API | `openai_api_key`, `embedding_model`, `embedding_dimension` |
| `custom` | Custom Embedding API | `embedding_custom_api_key`, `embedding_custom_api_base`, `embedding_model` |

### Example Configuration

```json
{
    "query_type": "openai",
    "openai_api_key": "sk-xxx",
    "openai_api_model": "gpt-4.1-mini",

    "embedding_backend": "openai",
    "embedding_model": "text-embedding-3-large",
    "embedding_dimension": 3072
}
```

Other optional parameters include retry settings, generation parameters (temperature, max_tokens), and token limits. See `Configs/llm_config.json` for details.

## Baselines

Included baseline detection tools:
- bandit4mal
- guarddog
- Hercule
- maloss
- OSSGadget
- MulGuard
- sap
- SecurityAI

## Contact

If you have any questions or issues, please contact: honywenair@gmail.com
