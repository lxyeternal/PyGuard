"""
Comprehensive false positive analyzer for all security tools.
Analyzes bandit4mal, guarddog, ossgadget, pypiwarehouse across all datasets.
"""
import os
import re
import glob
from pathlib import Path
from collections import defaultdict

PYGUARD_ROOT = Path(__file__).parent.parent.parent.parent
RESULTS_BASE = PYGUARD_ROOT / "Experiment" / "Results" / "PyPI"


def extract_bandit4mal_detection_types(file_path):
    """Extract detection types from bandit4mal detection file."""
    detection_types = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "No issues identified." in content or content.strip() == "benign":
                return set()
            issues = re.findall(r'>> Issue: \[(.*?)\]', content)
            detection_types.update(issues)
    except Exception as e:
        print(f"Error processing bandit4mal file {file_path}: {str(e)}")
    return detection_types


def extract_guarddog_detection_types(file_path):
    """Extract detection types from guarddog detection file."""
    detection_types = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "Found 0 potentially malicious indicators" in content or content.strip() == "benign":
                return set()
            matches = re.findall(r'(\w+(?:-\w+)*): found \d+ source code matches', content)
            detection_types.update(matches)
            other_matches = re.findall(r'(\w+(?:-\w+)*): found \d+ matches', content)
            detection_types.update(other_matches)
    except Exception as e:
        print(f"Error processing guarddog file {file_path}: {str(e)}")
    return detection_types


def extract_ossgadget_detection_types(file_path):
    """Extract detection types from ossgadget detection file (handles ANSI color codes)."""
    detection_types = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "0 matches found." in content or content.strip() == "benign":
                return set()
            tags = re.findall(r'Tag: \x1B\[34m(.*?)\x1B\[0m', content)
            detection_types.update(tags)
    except Exception as e:
        print(f"Error processing ossgadget file {file_path}: {str(e)}")
    return detection_types


def extract_pypiwarehouse_detection_types(file_path):
    """Extract detection types from pypiwarehouse detection file."""
    detection_types = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
            if content == "benign" or content == "":
                return set()
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if parts:
                        detection_types.add(parts[0])
    except Exception as e:
        print(f"Error processing pypiwarehouse file {file_path}: {str(e)}")
    return detection_types


def analyze_tool_simple(dataset_name, tool_name, extract_function):
    """Analyze false positives for a tool on a dataset (file-level deduplication)."""
    benign_folder = RESULTS_BASE / dataset_name / tool_name / "benign"
    if not benign_folder.exists():
        return {
            "total_files": 0, "false_positive_files": 0, "type_file_counts": {},
            "files_with_types": {}, "avg_types_per_file": 0, "max_types": 0, "min_types": 0
        }
    txt_files = glob.glob(str(benign_folder / "*.txt"))
    total_files = len(txt_files)
    file_detection_types = {}
    for file_path in txt_files:
        package_name = os.path.basename(file_path).replace(".txt", "")
        detection_types = extract_function(file_path)
        if detection_types:
            file_detection_types[package_name] = detection_types
    false_positive_files = len(file_detection_types)
    type_file_counts = defaultdict(int)
    for filename, detection_types in file_detection_types.items():
        for detection_type in detection_types:
            type_file_counts[detection_type] += 1
    if file_detection_types:
        type_counts_per_file = [len(types) for types in file_detection_types.values()]
        avg_types_per_file = sum(type_counts_per_file) / len(type_counts_per_file)
        max_types = max(type_counts_per_file)
        min_types = min(type_counts_per_file)
        files_with_max_types = [fn for fn, types in file_detection_types.items() if len(types) == max_types]
    else:
        avg_types_per_file, max_types, min_types = 0, 0, 0
        files_with_max_types = []
    return {
        "total_files": total_files, "false_positive_files": false_positive_files,
        "type_file_counts": dict(type_file_counts), "files_with_types": file_detection_types,
        "avg_types_per_file": avg_types_per_file, "max_types": max_types, "min_types": min_types,
        "files_with_max_types": files_with_max_types[:3]
    }


def save_simple_results(all_results, output_file):
    """Save analysis results - per dataset stats and combined totals."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("False Positive Analysis Report (Simplified)\n")
        f.write("=" * 80 + "\n\n")
        dataset_order = ["Evaluation", "Latest", "Obfuscation"]
        for dataset_name in dataset_order:
            if dataset_name not in all_results:
                continue
            f.write(f"【{dataset_name.upper()}】Dataset Statistics\n")
            f.write("=" * 50 + "\n\n")
            tools = all_results[dataset_name]
            dataset_tool_stats = []
            for tool_name, results in tools.items():
                fp_rate = (results["false_positive_files"] / results["total_files"] * 100) if results["total_files"] > 0 else 0
                dataset_tool_stats.append((tool_name, results, fp_rate))
            dataset_tool_stats.sort(key=lambda x: x[2])
            f.write(f"{dataset_name} Dataset Overview:\n")
            f.write("-" * 30 + "\n")
            for tool_name, results, fp_rate in dataset_tool_stats:
                f.write(f"{tool_name}: {results['false_positive_files']}/{results['total_files']} ({fp_rate:.2f}% FP rate)\n")
            f.write("\n")
            for tool_name, results, fp_rate in dataset_tool_stats:
                f.write(f"{tool_name.upper()} on {dataset_name} dataset:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Total benign samples: {results['total_files']}\n")
                f.write(f"False positive files: {results['false_positive_files']} ({fp_rate:.2f}%)\n")
                f.write(f"Detection types found: {len(results['type_file_counts'])}\n")
                if results["files_with_types"]:
                    f.write(f"Avg types per FP file: {results['avg_types_per_file']:.2f}\n")
                    f.write(f"Max types in single file: {results['max_types']}\n")
                    f.write(f"Min types in single file: {results['min_types']}\n\n")
                    f.write("Most common FP types (by file count):\n")
                    sorted_types = sorted(results["type_file_counts"].items(), key=lambda x: x[1], reverse=True)
                    for i, (detection_type, file_count) in enumerate(sorted_types[:10], 1):
                        pct = (file_count / results["false_positive_files"] * 100) if results["false_positive_files"] > 0 else 0
                        f.write(f"  {i}. {detection_type}: {file_count} files ({pct:.2f}%)\n")
                    if results["files_with_max_types"]:
                        f.write(f"\nFiles with most types ({results['max_types']} types):\n")
                        for fn in results["files_with_max_types"]:
                            f.write(f"  - {fn}\n")
                else:
                    f.write("No false positives found\n")
                f.write("\n" + "-" * 40 + "\n\n")
            f.write("=" * 50 + "\n\n")
        # Combined totals
        f.write("【OVERALL】Combined Results Across All Datasets\n")
        f.write("=" * 50 + "\n\n")
        tool_totals = defaultdict(lambda: {
            "total_files": 0, "fp_files": 0,
            "combined_type_counts": defaultdict(int), "all_files_with_types": {}
        })
        for dataset_name, tools in all_results.items():
            for tool_name, results in tools.items():
                tool_totals[tool_name]["total_files"] += results["total_files"]
                tool_totals[tool_name]["fp_files"] += results["false_positive_files"]
                for detection_type, count in results["type_file_counts"].items():
                    tool_totals[tool_name]["combined_type_counts"][detection_type] += count
                for fn, types in results["files_with_types"].items():
                    tool_totals[tool_name]["all_files_with_types"][f"{dataset_name}_{fn}"] = types
        sorted_tools = sorted(tool_totals.items(),
                            key=lambda x: (x[1]["fp_files"] / x[1]["total_files"]) if x[1]["total_files"] > 0 else 0)
        f.write("Overall Summary:\n")
        f.write("-" * 30 + "\n")
        for tool_name, totals in sorted_tools:
            fp_rate = (totals["fp_files"] / totals["total_files"] * 100) if totals["total_files"] > 0 else 0
            f.write(f"{tool_name}: {totals['fp_files']}/{totals['total_files']} ({fp_rate:.2f}% FP rate)\n")
        f.write("\n")
        for tool_name, totals in sorted_tools:
            f.write(f"{tool_name.upper()} Overall Statistics:\n")
            f.write("-" * 40 + "\n")
            fp_rate = (totals["fp_files"] / totals["total_files"] * 100) if totals["total_files"] > 0 else 0
            f.write(f"Total benign samples: {totals['total_files']}\n")
            f.write(f"False positive files: {totals['fp_files']} ({fp_rate:.2f}%)\n")
            f.write(f"Detection types found: {len(totals['combined_type_counts'])}\n")
            if totals["all_files_with_types"]:
                type_counts_per_file = [len(types) for types in totals["all_files_with_types"].values()]
                avg_types = sum(type_counts_per_file) / len(type_counts_per_file)
                max_types = max(type_counts_per_file)
                min_types = min(type_counts_per_file)
                f.write(f"Avg types per FP file: {avg_types:.2f}\n")
                f.write(f"Max types in single file: {max_types}\n")
                f.write(f"Min types in single file: {min_types}\n\n")
                f.write("Most common FP types (by file count):\n")
                sorted_types = sorted(totals["combined_type_counts"].items(), key=lambda x: x[1], reverse=True)
                for i, (detection_type, file_count) in enumerate(sorted_types[:10], 1):
                    pct = (file_count / totals["fp_files"] * 100) if totals["fp_files"] > 0 else 0
                    f.write(f"  {i}. {detection_type}: {file_count} files ({pct:.2f}%)\n")
                files_with_max = [fn for fn, types in totals["all_files_with_types"].items() if len(types) == max_types]
                if files_with_max:
                    f.write(f"\nFiles with most types ({max_types} types):\n")
                    for fn in files_with_max[:3]:
                        f.write(f"  - {fn}\n")
            else:
                f.write("No false positives found\n")
            f.write("\n" + "-" * 40 + "\n\n")


def main():
    output_file = Path(__file__).parent / "simple_false_positive_analysis.txt"
    dataset_names = ["Evaluation", "Latest", "Obfuscation"]
    tools_config = {
        "bandit4mal": extract_bandit4mal_detection_types,
        "guarddog": extract_guarddog_detection_types,
        "ossgadget": extract_ossgadget_detection_types,
        "pypiwarehouse": extract_pypiwarehouse_detection_types
    }
    all_results = {}
    print("Starting false positive analysis for all tools...")
    print(f"Results base: {RESULTS_BASE}")
    for dataset_name in dataset_names:
        print(f"\nAnalyzing dataset: {dataset_name}")
        all_results[dataset_name] = {}
        for tool_name, extract_function in tools_config.items():
            print(f"  Analyzing tool: {tool_name}")
            results = analyze_tool_simple(dataset_name, tool_name, extract_function)
            all_results[dataset_name][tool_name] = results
            fp_rate = (results["false_positive_files"] / results["total_files"] * 100) if results["total_files"] > 0 else 0
            print(f"    {results['false_positive_files']}/{results['total_files']} ({fp_rate:.2f}%) - avg {results['avg_types_per_file']:.1f} types/file")
    print(f"\nSaving results to: {output_file}")
    save_simple_results(all_results, output_file)
    print("Analysis completed!")


if __name__ == "__main__":
    main()
