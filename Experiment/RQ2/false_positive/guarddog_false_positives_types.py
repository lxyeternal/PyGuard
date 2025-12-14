import os
import re
import argparse
from pathlib import Path
from collections import defaultdict

PYGUARD_ROOT = Path(__file__).parent.parent.parent.parent


def extract_detection_types(file_path):
    """Extract detection types from guarddog detection file."""
    types = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "Found 0 potentially malicious indicators" in content or content.strip() == "benign":
                return []
            matches = re.findall(r'(\w+(?:-\w+)*): found \d+ source code matches', content)
            types.extend(matches)
            other_matches = re.findall(r'(\w+(?:-\w+)*): found \d+ matches', content)
            types.extend(other_matches)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return types


def main():
    parser = argparse.ArgumentParser(description="Analyze guarddog false positive types")
    parser.add_argument("--dataset", type=str, default="Evaluation",
                       choices=["Evaluation", "Latest", "Obfuscation"],
                       help="Dataset name to analyze")
    args = parser.parse_args()
    dataset_name = args.dataset

    benign_folder = PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / dataset_name / "guarddog" / "benign"
    if not benign_folder.exists():
        print(f"Error: Benign folder does not exist: {benign_folder}")
        return

    output_file = Path(__file__).parent / f"guarddog_false_positives_types_{dataset_name}.txt"
    print(f"Analyzing: {benign_folder}")

    false_positives = []
    type_counts = defaultdict(int)
    files_by_type = defaultdict(list)
    total_benign = 0

    for filename in os.listdir(benign_folder):
        if filename.endswith(".txt"):
            total_benign += 1
            file_path = benign_folder / filename
            types = extract_detection_types(file_path)
            if types:
                false_positives.append((str(file_path), types))
                for detection_type in types:
                    type_counts[detection_type] += 1
                    files_by_type[detection_type].append(str(file_path))
            if total_benign % 500 == 0:
                print(f"Processed {total_benign} files...")

    fp_count = len(false_positives)
    print(f"\nCompleted! Found {fp_count} false positives out of {total_benign} benign files")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Guarddog False Positive Types Analysis\n")
        f.write(f"Dataset: {dataset_name}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total benign files: {total_benign}\n")
        f.write(f"False positives: {fp_count} ({fp_count/total_benign*100:.2f}%)\n\n" if total_benign > 0 else "")
        f.write("Detection Type Statistics:\n")
        f.write("-" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            pct = count / fp_count * 100 if fp_count > 0 else 0
            f.write(f"{detection_type}: {count} files ({pct:.2f}%)\n")
        f.write("\n\nDetailed File List by Type:\n")
        f.write("=" * 50 + "\n")
        for detection_type, files in sorted(files_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            f.write(f"\n## {detection_type} ({len(files)} files):\n")
            for i, fp in enumerate(sorted(files), 1):
                f.write(f"{i}. {os.path.basename(fp)}\n")

    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
