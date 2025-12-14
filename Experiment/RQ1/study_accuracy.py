"""
Calculate detection accuracy metrics for security analysis tools.
Evaluates bandit4mal, guarddog, ossgadget, and pypiwarehouse on the study dataset.
"""
import os
import glob
from pathlib import Path


PYGUARD_ROOT = Path(__file__).parent.parent
TOOL_SCAN_OUTPUT = PYGUARD_ROOT / "Core" / "ContextExtractor" / "tool_scan_output"


def analyze_bandit4mal(file_path):
    """Analyze bandit4mal detection result. Returns 'benign' if no issues found."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if "No issues identified." in content or content.strip() == "benign":
            return "benign"
        return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def analyze_guarddog(file_path):
    """Analyze guarddog detection result. Returns 'benign' if no malicious indicators found."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if "Found 0 potentially malicious indicators" in content or content.strip() == "benign":
            return "benign"
        return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def analyze_ossgadget(file_path):
    """Analyze ossgadget detection result. Returns 'benign' if no matches found."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if "0 matches found." in content or content.strip() == "benign":
            return "benign"
        return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def analyze_pypiwarehouse(file_path):
    """Analyze pypiwarehouse detection result. Returns 'benign' if content is empty or 'benign'."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        if content == "benign" or content == "":
            return "benign"
        return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def calculate_metrics(tp, tn, fp, fn):
    """Calculate precision, recall, F1 score and accuracy."""
    total = tp + tn + fp + fn
    if total == 0:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}

    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


def evaluate_tool(base_path, tool_name, analyze_func):
    """Evaluate detection performance for a specific tool."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0
    }

    benign_folder = os.path.join(base_path, tool_name, "benign")
    if os.path.exists(benign_folder):
        for file_path in glob.glob(os.path.join(benign_folder, "*.txt")):
            results["benign_total"] += 1
            prediction = analyze_func(file_path)
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1

    malware_folder = os.path.join(base_path, tool_name, "malware")
    if os.path.exists(malware_folder):
        for file_path in glob.glob(os.path.join(malware_folder, "*.txt")):
            results["malware_total"] += 1
            prediction = analyze_func(file_path)
            if prediction == "malware":
                results["true_positive"] += 1
            elif prediction == "benign":
                results["false_negative"] += 1

    metrics = calculate_metrics(
        results["true_positive"],
        results["true_negative"],
        results["false_positive"],
        results["false_negative"]
    )
    results.update(metrics)

    return results


def main():
    """Evaluate all tools and print results."""
    base_path = str(TOOL_SCAN_OUTPUT)

    tools = {
        "bandit4mal": analyze_bandit4mal,
        "guarddog": analyze_guarddog,
        "ossgadget": analyze_ossgadget,
        "pypiwarehouse": analyze_pypiwarehouse
    }

    print("Tool Detection Performance (Study Dataset):\n")
    print("| Tool | Samples | Accuracy | Precision | Recall | F1 | FP | FN |")
    print("|------|---------|----------|-----------|--------|----|----|-----|")

    all_results = {}

    for tool_name, analyze_func in tools.items():
        results = evaluate_tool(base_path, tool_name, analyze_func)
        all_results[tool_name] = results

        total = results["benign_total"] + results["malware_total"]
        print(
            f"| {tool_name} | {total} | {results['accuracy']:.4f} | "
            f"{results['precision']:.4f} | {results['recall']:.4f} | {results['f1']:.4f} | "
            f"{results['false_positive']} | {results['false_negative']} |"
        )

    print("\n\nDetailed Results:")
    for tool_name, results in all_results.items():
        print(f"\n{tool_name}:")
        print(f"  Benign samples: {results['benign_total']}")
        print(f"  Malware samples: {results['malware_total']}")
        print(f"  TP: {results['true_positive']}, TN: {results['true_negative']}")
        print(f"  FP: {results['false_positive']}, FN: {results['false_negative']}")
        print(f"  Accuracy: {results['accuracy']:.4f}, F1: {results['f1']:.4f}")

        if results['benign_total'] > 0:
            fpr = results['false_positive'] / results['benign_total']
            print(f"  FP Rate: {fpr:.4f}")
        if results['malware_total'] > 0:
            fnr = results['false_negative'] / results['malware_total']
            print(f"  FN Rate: {fnr:.4f}")


if __name__ == "__main__":
    main()
