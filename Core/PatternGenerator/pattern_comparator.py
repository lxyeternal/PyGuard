"""
Pattern Comparator: Compare frequent patterns between benign and malware samples.
Find malware-specific patterns and analyze pattern similarities.
"""
import os
import json
import argparse
from collections import defaultdict
from typing import Dict, List, Any, Set, Tuple

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE_DIR = os.path.join(PYGUARD_ROOT, "Core", "ActionSequence", "action_sequences")
PATTERN_DIR = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "pattern_results")
OUTPUT_DIR = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "analysis_results")

BENIGN_DIRS = [
    os.path.join(BASE_DIR, "benign_guarddog"),
    os.path.join(BASE_DIR, "benign_bandit4mal")
]
MALWARE_DIRS = [
    os.path.join(BASE_DIR, "malware"),
    os.path.join(BASE_DIR, "malware_fn")
]


def load_json_files(directories: List[str]) -> List[Dict]:
    samples = []
    for directory in directories:
        if not os.path.exists(directory):
            print(f"Warning: directory {directory} does not exist")
            continue

        for filename in os.listdir(directory):
            if not filename.endswith(".json"):
                continue
            try:
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            item["_source_file"] = filename
                            samples.append(item)
                elif isinstance(data, dict):
                    data["_source_file"] = filename
                    samples.append(data)
            except Exception as e:
                print(f"Error loading {filename}: {e}")

    return samples


def extract_sequences(samples: List[Dict], granularity: str = "id") -> List[Tuple[List[str], str]]:
    sequences = []

    for sample in samples:
        pattern_key = "pattern_analysis" if "pattern_analysis" in sample else "Pattern analysis"
        if pattern_key not in sample:
            continue

        pattern_analysis = sample[pattern_key]
        source_file = sample.get("_source_file", "unknown")

        if "mapped_sequence" in pattern_analysis:
            mapped_seq = pattern_analysis["mapped_sequence"]
            if isinstance(mapped_seq, list):
                seq = [entry.get(granularity, "") for entry in mapped_seq if isinstance(entry, dict)]
                seq = [s for s in seq if s]
                if seq:
                    sequences.append((seq, source_file))

    return sequences


def find_similar_packages(sequences: List[Tuple[List[str], str]]) -> Dict[str, List[Dict]]:
    sequence_to_packages = defaultdict(list)

    for seq, source_file in sequences:
        seq_str = ",".join(seq)
        package_name = source_file.replace(".json", "")
        sequence_to_packages[seq_str].append(package_name)

    similar_groups = []
    for seq_str, packages in sequence_to_packages.items():
        if len(packages) > 1:
            similar_groups.append({
                "sequence": seq_str.split(","),
                "packages": packages,
                "count": len(packages)
            })

    similar_groups.sort(key=lambda x: x["count"], reverse=True)

    return {
        "total_groups": len(similar_groups),
        "groups": similar_groups[:50]
    }


def compare_pattern_sets(
    benign_sequences: List[Tuple[List[str], str]],
    malware_sequences: List[Tuple[List[str], str]]
) -> Dict[str, Any]:
    benign_set = set(",".join(seq) for seq, _ in benign_sequences)
    malware_set = set(",".join(seq) for seq, _ in malware_sequences)

    common = benign_set.intersection(malware_set)
    benign_only = benign_set - malware_set
    malware_only = malware_set - benign_set

    benign_only_list = [{"sequence": s.split(","), "length": len(s.split(","))} for s in list(benign_only)[:100]]
    malware_only_list = [{"sequence": s.split(","), "length": len(s.split(","))} for s in list(malware_only)[:100]]

    benign_only_list.sort(key=lambda x: x["length"], reverse=True)
    malware_only_list.sort(key=lambda x: x["length"], reverse=True)

    return {
        "statistics": {
            "benign_total": len(benign_set),
            "malware_total": len(malware_set),
            "common_count": len(common),
            "benign_only_count": len(benign_only),
            "malware_only_count": len(malware_only),
            "benign_unique_ratio": f"{len(benign_only)/len(benign_set):.2%}" if benign_set else "0%",
            "malware_unique_ratio": f"{len(malware_only)/len(malware_set):.2%}" if malware_set else "0%"
        },
        "benign_only_patterns": benign_only_list,
        "malware_only_patterns": malware_only_list
    }


def analyze_pattern_lengths(sequences: List[Tuple[List[str], str]]) -> Dict[str, int]:
    length_counts = defaultdict(int)
    for seq, _ in sequences:
        length_counts[len(seq)] += 1
    return dict(sorted(length_counts.items()))


def load_mined_patterns(pattern_file: str) -> List[Dict]:
    if not os.path.exists(pattern_file):
        return []

    with open(pattern_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    patterns = data.get("patterns", [])
    return patterns


def compare_mined_patterns(pattern_file: str) -> Dict[str, Any]:
    patterns = load_mined_patterns(pattern_file)

    if not patterns:
        return {"error": f"No patterns found in {pattern_file}"}

    benign_only = [p for p in patterns if p.get("type") == "benign_only"]
    malware_only = [p for p in patterns if p.get("type") == "malware_only"]

    benign_lengths = [len(p["pattern"]) for p in benign_only]
    malware_lengths = [len(p["pattern"]) for p in malware_only]

    return {
        "total_patterns": len(patterns),
        "benign_only_count": len(benign_only),
        "malware_only_count": len(malware_only),
        "benign_avg_length": sum(benign_lengths) / len(benign_lengths) if benign_lengths else 0,
        "malware_avg_length": sum(malware_lengths) / len(malware_lengths) if malware_lengths else 0,
        "top_benign_patterns": [
            {"pattern": p["pattern"], "support": p.get("support", 0)}
            for p in sorted(benign_only, key=lambda x: x.get("support", 0), reverse=True)[:10]
        ],
        "top_malware_patterns": [
            {"pattern": p["pattern"], "support": p.get("support", 0)}
            for p in sorted(malware_only, key=lambda x: x.get("support", 0), reverse=True)[:10]
        ]
    }


def run_comparison() -> Dict[str, Any]:
    print("Loading benign samples...")
    benign_samples = load_json_files(BENIGN_DIRS)
    print(f"Loaded {len(benign_samples)} benign samples")

    print("Loading malware samples...")
    malware_samples = load_json_files(MALWARE_DIRS)
    print(f"Loaded {len(malware_samples)} malware samples")

    print("\nExtracting sequences...")
    benign_seqs = extract_sequences(benign_samples, "id")
    malware_seqs = extract_sequences(malware_samples, "id")
    print(f"Extracted {len(benign_seqs)} benign sequences, {len(malware_seqs)} malware sequences")

    print("\nAnalyzing similar packages...")
    benign_similar = find_similar_packages(benign_seqs)
    malware_similar = find_similar_packages(malware_seqs)

    print("\nComparing pattern sets...")
    comparison = compare_pattern_sets(benign_seqs, malware_seqs)

    print("\nAnalyzing pattern lengths...")
    benign_lengths = analyze_pattern_lengths(benign_seqs)
    malware_lengths = analyze_pattern_lengths(malware_seqs)

    pattern_file = os.path.join(PATTERN_DIR, "patterns_id.json")
    mined_analysis = {}
    if os.path.exists(pattern_file):
        print("\nAnalyzing mined patterns...")
        mined_analysis = compare_mined_patterns(pattern_file)

    return {
        "sample_counts": {
            "benign_samples": len(benign_samples),
            "malware_samples": len(malware_samples),
            "benign_sequences": len(benign_seqs),
            "malware_sequences": len(malware_seqs)
        },
        "similar_packages": {
            "benign": benign_similar,
            "malware": malware_similar
        },
        "pattern_comparison": comparison,
        "length_distribution": {
            "benign": benign_lengths,
            "malware": malware_lengths
        },
        "mined_patterns_analysis": mined_analysis
    }


def print_summary(results: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("Pattern Comparison Summary")
    print("=" * 60)

    counts = results["sample_counts"]
    print(f"\nSamples: {counts['benign_samples']} benign, {counts['malware_samples']} malware")
    print(f"Sequences: {counts['benign_sequences']} benign, {counts['malware_sequences']} malware")

    print("\n### Similar Packages ###")
    print(f"Benign: {results['similar_packages']['benign']['total_groups']} groups share same sequence")
    print(f"Malware: {results['similar_packages']['malware']['total_groups']} groups share same sequence")

    print("\n### Pattern Comparison ###")
    stats = results["pattern_comparison"]["statistics"]
    print(f"Common patterns: {stats['common_count']}")
    print(f"Benign only: {stats['benign_only_count']} ({stats['benign_unique_ratio']})")
    print(f"Malware only: {stats['malware_only_count']} ({stats['malware_unique_ratio']})")

    if results["mined_patterns_analysis"]:
        print("\n### Mined Patterns Analysis ###")
        mined = results["mined_patterns_analysis"]
        if "error" not in mined:
            print(f"Total patterns: {mined['total_patterns']}")
            print(f"Benign only: {mined['benign_only_count']} (avg length: {mined['benign_avg_length']:.1f})")
            print(f"Malware only: {mined['malware_only_count']} (avg length: {mined['malware_avg_length']:.1f})")

            if mined["top_malware_patterns"]:
                print("\nTop malware-specific patterns:")
                for i, p in enumerate(mined["top_malware_patterns"][:5], 1):
                    pattern_str = " -> ".join(p["pattern"][:5])
                    if len(p["pattern"]) > 5:
                        pattern_str += f" ... ({len(p['pattern'])} total)"
                    print(f"  {i}. {pattern_str} (support: {p['support']})")


def main():
    parser = argparse.ArgumentParser(description="Compare patterns between benign and malware samples")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = run_comparison()
    print_summary(results)

    output_file = args.output or os.path.join(OUTPUT_DIR, "pattern_comparison_results.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\nFull results saved to: {output_file}")


if __name__ == "__main__":
    main()
