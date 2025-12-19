"""
Calculate detection accuracy metrics for baseline security analysis tools on NPM packages.
Evaluates guarddog, ossgadget, gpt-4.1, and pyguard on the npm_data dataset.

Directory structure:
    Results/NPM/{tool}/{benign,malware}/*.txt or *.json
    Results/NPM/cerebro/*.csv
"""
import os
import json
import glob
import csv
from pathlib import Path


PYGUARD_ROOT = Path(__file__).parent.parent

RESULTS_BASE = PYGUARD_ROOT / "Experiment" / "Results" / "NPM"


def analyze_guarddog(file_path):
    """
    Analyze guarddog detection result.
    Returns 'benign' if "Found 0 potentially malicious indicators" or content is "benign".
    """
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
    """
    Analyze ossgadget detection result.
    Returns 'benign' if "0 matches found." or content is "benign".
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if "0 matches found." in content or content.strip() == "benign":
            return "benign"
        return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def analyze_json_malicious(file_path):
    """
    Analyze JSON-based detection result (gpt-4.1, pyguard, etc.).
    Returns 'malware' if is_malicious is true, otherwise 'benign'.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        if data.get("is_malicious", False):
            return "malware"
        return "benign"
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


def evaluate_tool(tool_name, analyze_func):
    """Evaluate detection performance for a specific tool."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0
    }

    # Benign samples
    benign_folder = RESULTS_BASE / tool_name / "benign"
    if benign_folder.exists():
        benign_txt_files = glob.glob(str(benign_folder / "*.txt"))
        benign_json_files = glob.glob(str(benign_folder / "*.json"))

        for file_path in benign_txt_files + benign_json_files:
            package_name = os.path.basename(file_path).replace(".txt", "").replace(".json", "")
            prediction = analyze_func(file_path)

            if prediction == "error":
                results["errors"] += 1
                prediction = "benign"

            results["benign_total"] += 1
            if prediction == "benign":
                results["true_negative"] += 1
            else:
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)

    # Malware samples
    malware_folder = RESULTS_BASE / tool_name / "malware"
    if malware_folder.exists():
        malware_txt_files = glob.glob(str(malware_folder / "*.txt"))
        malware_json_files = glob.glob(str(malware_folder / "*.json"))

        for file_path in malware_txt_files + malware_json_files:
            package_name = os.path.basename(file_path).replace(".txt", "").replace(".json", "")
            prediction = analyze_func(file_path)

            if prediction == "error":
                results["errors"] += 1
                prediction = "benign"

            results["malware_total"] += 1
            if prediction == "malware":
                results["true_positive"] += 1
            else:
                results["false_negative"] += 1
                results["misclassified_malware"].append(package_name)

    metrics = calculate_metrics(
        results["true_positive"],
        results["true_negative"],
        results["false_positive"],
        results["false_negative"]
    )
    results.update(metrics)
    return results


def load_cerebro_results(csv_file_path):
    """
    Load cerebro detection results from labeled CSV.
    CSV format: package_name,prediction,ground_truth
    where prediction is 1=malicious, 0=benign
    and ground_truth is "malware" or "benign".
    Returns list of tuples: [(package_name, prediction, ground_truth), ...]
    """
    cerebro_results = []
    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            header = next(reader, None)  # Skip header row
            for row in reader:
                if len(row) >= 3:
                    package_name = row[0].strip()
                    prediction_val = int(row[1].strip()) if row[1].strip().isdigit() else 0
                    prediction = "malware" if prediction_val == 1 else "benign"
                    ground_truth = row[2].strip()
                    cerebro_results.append((package_name, prediction, ground_truth))
    except Exception as e:
        print(f"Error loading cerebro CSV {csv_file_path}: {e}")
    return cerebro_results


def find_cerebro_csv():
    """Find cerebro CSV file in results folder."""
    cerebro_folder = RESULTS_BASE / "cerebro"
    if not cerebro_folder.exists():
        return None

    csv_files = glob.glob(str(cerebro_folder / "*.csv"))
    if csv_files:
        return csv_files[0]
    return None


def evaluate_cerebro_tool(cerebro_results):
    """Evaluate cerebro tool using labeled CSV results."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0
    }

    for package_name, prediction, ground_truth in cerebro_results:
        if ground_truth == "benign":
            results["benign_total"] += 1
            if prediction == "benign":
                results["true_negative"] += 1
            else:
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
        elif ground_truth == "malware":
            results["malware_total"] += 1
            if prediction == "malware":
                results["true_positive"] += 1
            else:
                results["false_negative"] += 1
                results["misclassified_malware"].append(package_name)
        else:
            results["errors"] += 1

    metrics = calculate_metrics(
        results["true_positive"],
        results["true_negative"],
        results["false_positive"],
        results["false_negative"]
    )
    results.update(metrics)
    return results


def print_summary_table(all_results):
    """Print summary table in markdown format."""
    print("\n" + "=" * 100)
    print("Summary Table")
    print("=" * 100)
    print("\n| Tool | Samples | Accuracy | Precision | Recall | F1 | FP | FN | FPR | FNR |")
    print("|------|---------|----------|-----------|--------|----|----|----|----|-----|")

    for tool_name, r in all_results.items():
        total = r["benign_total"] + r["malware_total"]
        fpr = r["false_positive"] / r["benign_total"] if r["benign_total"] > 0 else 0
        fnr = r["false_negative"] / r["malware_total"] if r["malware_total"] > 0 else 0

        print(
            f"| {tool_name} | {total} | "
            f"{r['accuracy']*100:.2f}% | {r['precision']*100:.2f}% | "
            f"{r['recall']*100:.2f}% | {r['f1']*100:.2f}% | "
            f"{r['false_positive']} | {r['false_negative']} | "
            f"{fpr*100:.2f}% | {fnr*100:.2f}% |"
        )


def save_results_to_file(all_results, output_file):
    """Save detailed results to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("NPM Tool Detection Performance Report\n")
        f.write("=" * 80 + "\n\n")

        f.write("| Tool | Samples | Accuracy | Precision | Recall | F1 | FP | FN | FPR | FNR |\n")
        f.write("|------|---------|----------|-----------|--------|----|----|----|----|-----|\n")

        for tool_name, r in all_results.items():
            total = r["benign_total"] + r["malware_total"]
            fpr = r["false_positive"] / r["benign_total"] if r["benign_total"] > 0 else 0
            fnr = r["false_negative"] / r["malware_total"] if r["malware_total"] > 0 else 0

            f.write(
                f"| {tool_name} | {total} | "
                f"{r['accuracy']*100:.2f}% | {r['precision']*100:.2f}% | "
                f"{r['recall']*100:.2f}% | {r['f1']*100:.2f}% | "
                f"{r['false_positive']} | {r['false_negative']} | "
                f"{fpr*100:.2f}% | {fnr*100:.2f}% |\n"
            )

        f.write("\n\nDetailed Results:\n")
        f.write("=" * 80 + "\n")

        for tool_name, r in all_results.items():
            f.write(f"\n{tool_name}:\n")
            f.write(f"  Benign samples: {r['benign_total']}\n")
            f.write(f"  Malware samples: {r['malware_total']}\n")
            f.write(f"  TP: {r['true_positive']}, TN: {r['true_negative']}\n")
            f.write(f"  FP: {r['false_positive']}, FN: {r['false_negative']}\n")
            f.write(f"  Accuracy: {r['accuracy']*100:.2f}%, F1: {r['f1']*100:.2f}%\n")

            if r['benign_total'] > 0:
                f.write(f"  FP Rate: {r['false_positive']/r['benign_total']*100:.2f}%\n")
            if r['malware_total'] > 0:
                f.write(f"  FN Rate: {r['false_negative']/r['malware_total']*100:.2f}%\n")

            if r.get("errors", 0) > 0:
                f.write(f"  Errors: {r['errors']}\n")

            if r["misclassified_benign"]:
                f.write(f"  False Positives: {', '.join(r['misclassified_benign'][:10])}")
                if len(r['misclassified_benign']) > 10:
                    f.write(f" ... and {len(r['misclassified_benign'])-10} more")
                f.write("\n")

            if r["misclassified_malware"]:
                f.write(f"  False Negatives: {', '.join(r['misclassified_malware'][:10])}")
                if len(r['misclassified_malware']) > 10:
                    f.write(f" ... and {len(r['misclassified_malware'])-10} more")
                f.write("\n")


def main():
    """Main function to evaluate all tools on NPM dataset."""
    print(f"Results directory: {RESULTS_BASE}")

    # Tools with file-based results (txt or json)
    file_based_tools = {
        "guarddog": analyze_guarddog,
        "ossgadget": analyze_ossgadget,
        "gpt-4.1": analyze_json_malicious,
        "pyguard": analyze_json_malicious,
    }

    all_results = {}

    print("\n" + "=" * 60)
    print("Evaluating NPM Dataset")
    print("=" * 60)

    # Evaluate file-based tools
    for tool_name, analyze_func in file_based_tools.items():
        tool_path = RESULTS_BASE / tool_name
        if not tool_path.exists():
            continue

        print(f"  Evaluating: {tool_name}")
        results = evaluate_tool(tool_name, analyze_func)
        all_results[tool_name] = results

        total = results["benign_total"] + results["malware_total"]
        fpr = results["false_positive"] / results["benign_total"] * 100 if results["benign_total"] > 0 else 0
        fnr = results["false_negative"] / results["malware_total"] * 100 if results["malware_total"] > 0 else 0
        print(f"    Samples: {total}, Acc: {results['accuracy']*100:.2f}%, "
              f"Prec: {results['precision']*100:.2f}%, Rec: {results['recall']*100:.2f}%, "
              f"F1: {results['f1']*100:.2f}%, FP: {results['false_positive']}, "
              f"FN: {results['false_negative']}, FPR: {fpr:.2f}%, FNR: {fnr:.2f}%")

    # Evaluate cerebro (CSV-based with pre-labeled ground truth)
    cerebro_csv = find_cerebro_csv()
    if cerebro_csv:
        print(f"  Evaluating: cerebro")
        cerebro_results = load_cerebro_results(cerebro_csv)
        results = evaluate_cerebro_tool(cerebro_results)
        all_results["cerebro"] = results

        total = results["benign_total"] + results["malware_total"]
        fpr = results["false_positive"] / results["benign_total"] * 100 if results["benign_total"] > 0 else 0
        fnr = results["false_negative"] / results["malware_total"] * 100 if results["malware_total"] > 0 else 0
        print(f"    Samples: {total}, Acc: {results['accuracy']*100:.2f}%, "
              f"Prec: {results['precision']*100:.2f}%, Rec: {results['recall']*100:.2f}%, "
              f"F1: {results['f1']*100:.2f}%, FP: {results['false_positive']}, "
              f"FN: {results['false_negative']}, FPR: {fpr:.2f}%, FNR: {fnr:.2f}%")

    # Print summary table
    print_summary_table(all_results)

    # Save results to file
    output_file = str(PYGUARD_ROOT / "Experiment" / "npm_detection_results.txt")
    save_results_to_file(all_results, output_file)
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
