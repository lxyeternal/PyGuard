import os
import re
import argparse
from pathlib import Path
from collections import defaultdict

PYGUARD_ROOT = Path(__file__).parent.parent.parent.parent


def extract_detection_types(file_path):
    """Extract detection types from bandit4mal detection file."""
    detection_types = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            issues = re.findall(r'>> Issue: \[(.*?)\]', content)
            for issue in issues:
                detection_types.add(issue)
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
    return detection_types


def main():
    parser = argparse.ArgumentParser(description="Analyze bandit4mal false positive types")
    parser.add_argument("--dataset", type=str, default="Evaluation",
                       choices=["Evaluation", "Latest", "Obfuscation"],
                       help="Dataset name to analyze")
    args = parser.parse_args()
    dataset_name = args.dataset

    benign_folder = PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / dataset_name / "bandit4mal" / "benign"
    if not benign_folder.exists():
        print(f"Error: Benign folder does not exist: {benign_folder}")
        return

    output_file = Path(__file__).parent / f"bandit4mal_false_positives_types_{dataset_name}.txt"
    print(f"Analyzing: {benign_folder}")

    type_to_files = defaultdict(list)
    type_counts = defaultdict(int)
    total_files = 0
    files_with_detections = 0

    for filename in os.listdir(benign_folder):
        if filename.endswith(".txt"):
            total_files += 1
            file_path = benign_folder / filename
            detection_types = extract_detection_types(file_path)
            if detection_types:
                files_with_detections += 1
                for detection_type in detection_types:
                    type_to_files[detection_type].append(str(file_path))
                    type_counts[detection_type] += 1
            if total_files % 500 == 0:
                print(f"Processed {total_files} files...")

    print(f"\nCompleted, processed {total_files} files")
    print(f"Found {files_with_detections} files with false positives ({len(type_counts)} types)")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Bandit4mal False Positive Types Analysis\n")
        f.write(f"Dataset: {dataset_name}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total benign files analyzed: {total_files}\n")
        f.write(f"Files with false positives: {files_with_detections} ({files_with_detections/total_files*100:.2f}%)\n\n" if total_files > 0 else "")
        f.write("Detection Type Statistics:\n")
        f.write("-" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / files_with_detections) * 100 if files_with_detections > 0 else 0
            f.write(f"{detection_type}: {count} files ({pct:.2f}%)\n")
        f.write("\n\nDetailed File List:\n")
        f.write("=" * 50 + "\n")
        for detection_type, files in sorted(type_to_files.items(), key=lambda x: len(x[1]), reverse=True):
            f.write(f"\n## {detection_type} ({len(files)} files):\n")
            for i, fp in enumerate(sorted(files), 1):
                f.write(f"{i}. {os.path.basename(fp)}\n")

    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
