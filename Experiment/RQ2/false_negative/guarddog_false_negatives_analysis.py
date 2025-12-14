import os
import glob
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
                return "missed", []
            indicator_count_match = re.search(r'Found (\d+) potentially malicious indicators', content)
            indicator_count = int(indicator_count_match.group(1)) if indicator_count_match else 0
            matches = re.findall(r'(\w+(?:-\w+)*): found \d+ source code matches', content)
            types.extend(matches)
            other_matches = re.findall(r'(\w+(?:-\w+)*): found \d+ matches', content)
            types.extend(other_matches)
            if indicator_count > 0 and not types:
                return "detected_but_unknown_type", []
            return "detected", types
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error", []


def main():
    parser = argparse.ArgumentParser(description="Analyze guarddog false negatives")
    parser.add_argument("--dataset", type=str, default="Evaluation",
                       choices=["Evaluation", "Latest", "Obfuscation"],
                       help="Dataset name to analyze")
    args = parser.parse_args()
    dataset_name = args.dataset

    malware_folder = PYGUARD_ROOT / "Experiment" / "Results" / "PyPI" / dataset_name / "guarddog" / "malware"
    if not malware_folder.exists():
        print(f"Error: Malware folder does not exist: {malware_folder}")
        return

    output_file = Path(__file__).parent / f"guarddog_malware_analysis_{dataset_name}.txt"

    print(f"Analyzing dataset: {dataset_name}")
    print(f"Malware folder: {malware_folder}")

    all_files, missed_detections, single_behavior_files = [], [], []
    type_counts = defaultdict(int)
    files_by_type = defaultdict(list)
    total_malware, detected_count, missed_count, error_count = 0, 0, 0, 0

    for file_path in glob.glob(str(malware_folder / "*.txt")):
        total_malware += 1
        status, types = extract_detection_types(file_path)
        if status == "error":
            error_count += 1
            continue
        if status == "missed":
            missed_count += 1
            missed_detections.append(file_path)
            all_files.append((file_path, [], "missed"))
            continue
        detected_count += 1
        all_files.append((file_path, types, "detected"))
        for detection_type in types:
            type_counts[detection_type] += 1
            files_by_type[detection_type].append(file_path)
        if len(types) == 1:
            single_behavior_files.append((file_path, types[0]))

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Guarddog Malware Detection Analysis\n")
        f.write(f"Dataset: {dataset_name}\n")
        f.write(f"Total malware samples analyzed: {total_malware}\n")
        f.write(f"Successfully detected: {detected_count} samples ({detected_count/total_malware*100:.2f}%)\n" if total_malware > 0 else "Successfully detected: 0 samples\n")
        f.write(f"Missed (False Negatives): {missed_count} samples ({missed_count/total_malware*100:.2f}%)\n" if total_malware > 0 else "Missed: 0 samples\n")
        if error_count > 0:
            f.write(f"Analysis errors: {error_count} samples ({error_count/total_malware*100:.2f}%)\n")
        f.write("\n")
        if detected_count > 0:
            f.write(f"Files matching only one behavior: {len(single_behavior_files)} ({len(single_behavior_files)/detected_count*100:.2f}% of detected samples)\n\n")
            f.write("Detection Behavior Type Distribution:\n")
            f.write("=" * 30 + "\n")
            for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{detection_type}: {count} files ({count/detected_count*100:.2f}% of detected samples)\n")
            f.write("\n\nDetailed Behavior Classification List:\n")
            f.write("=" * 30 + "\n")
            for detection_type, files in sorted(files_by_type.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"\n## {detection_type} ({len(files)} files):\n")
                for i, fp in enumerate(sorted(files), 1):
                    f.write(f"{i}. {os.path.basename(fp)}\n")
            f.write("\n\nFiles Matching Only One Behavior:\n")
            f.write("=" * 30 + "\n")
            behavior_group = defaultdict(list)
            for fp, behavior in single_behavior_files:
                behavior_group[behavior].append(os.path.basename(fp))
            for behavior, files in sorted(behavior_group.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"\n## {behavior} ({len(files)} files):\n")
                for i, file_name in enumerate(sorted(files), 1):
                    f.write(f"{i}. {file_name}\n")
        f.write("\n\nMissed Files List (No Malicious Behavior Detected):\n")
        f.write("=" * 30 + "\n")
        for i, fp in enumerate(sorted(missed_detections), 1):
            f.write(f"{i}. {os.path.basename(fp)}\n")

    print(f"Analysis completed! Analyzed {total_malware} malware samples")
    if total_malware > 0:
        print(f"Successfully detected: {detected_count} samples ({detected_count/total_malware*100:.2f}%)")
        print(f"Missed (False Negatives): {missed_count} samples ({missed_count/total_malware*100:.2f}%)")
    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
