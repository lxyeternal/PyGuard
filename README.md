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

## Dataset

### Data Format

Each dataset directory contains a `packages.txt` file with package names and versions:
```
package_name-version.tar.gz
package_name-version.whl
```

### PyPI Dataset

| Type | Location | Count | Source |
|------|----------|-------|--------|
| Malware | `Dataset/PyPI/Study/Malware/` | 8,540 | [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) |
| Benign | `Dataset/PyPI/Study/Benign/` | 9,591 | PyPI Top Packages |

### NPM Dataset

| Type | Location | Count | Source |
|------|----------|-------|--------|
| Malware | `Dataset/NPM/Malware/` | 815 | [Backstabbers-Knife-Collection](https://github.com/cybertier/Backstabbers-Knife-Collection) |
| Benign | `Dataset/NPM/Benign/` | 999 | NPM Popular Packages |

### Data Collection

Benign packages are downloaded using scripts in `Scripts/DataCollect/`:

```bash
# Download benign PyPI packages
python Scripts/DataCollect/benign_data.py

# Download specific packages
python Scripts/DataCollect/pkg_download.py
```

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

### Package Analysis

```python
from Core.Detector.package_analyzer import PackageAnalyzer

analyzer = PackageAnalyzer()
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
from Core.RAG.rag_query_engine import RAGQueryEngine

# Build knowledge base
builder = RAGKnowledgeBuilder()
builder.build()

# Query for detection
engine = RAGQueryEngine()
result = engine.detect_malware(action_sequence, code_context)
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
