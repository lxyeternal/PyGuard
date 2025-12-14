"""
API Sequence Analyzer: Analyze API sequence characteristics before pattern mining.
Includes code duplication analysis, sequence statistics, and benign/malware comparison.
"""
import os
import json
import collections
import hashlib
import argparse
from typing import Dict, List, Tuple, Any

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE_DIR = os.path.join(PYGUARD_ROOT, "Core", "ActionSequence", "action_sequences")
OUTPUT_DIR = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "analysis_results")

BENIGN_DIRS = [
    os.path.join(BASE_DIR, "benign_guarddog"),
    os.path.join(BASE_DIR, "benign_bandit4mal")
]
MALWARE_DIRS = [
    os.path.join(BASE_DIR, "malware"),
    os.path.join(BASE_DIR, "malware_fn")
]


class APISequenceAnalyzer:
    """API sequence analysis tool class."""

    def __init__(self, benign_dirs: List[str], malware_dirs: List[str]):
        self.benign_dirs = benign_dirs
        self.malware_dirs = malware_dirs
        self.benign_data = []
        self.malware_data = []
        self.granularity_levels = ["api_name", "id", "first_id", "second_id", "third_id"]
        self.benign_files = []
        self.malware_files = []
        self.benign_code_hashes = {}
        self.malware_code_hashes = {}

    def load_data(self) -> None:
        """Load all JSON files from directories."""
        print(f"Loading benign data from: {self.benign_dirs}")
        print(f"Loading malware data from: {self.malware_dirs}")

        all_benign_data = []
        all_benign_files = []
        for benign_dir in self.benign_dirs:
            data, files = self._load_json_files(benign_dir)
            all_benign_data.extend(data)
            all_benign_files.extend(files)

        self.benign_data = all_benign_data
        self.benign_files = all_benign_files

        all_malware_data = []
        all_malware_files = []
        for malware_dir in self.malware_dirs:
            data, files = self._load_json_files(malware_dir)
            all_malware_data.extend(data)
            all_malware_files.extend(files)

        self.malware_data = all_malware_data
        self.malware_files = all_malware_files

        print(f"Loaded {len(self.benign_data)} benign files")
        print(f"Loaded {len(self.malware_data)} malware files")

    def _load_json_files(self, directory: str) -> Tuple[List[Dict], List[str]]:
        """Load all JSON files from directory."""
        result = []
        file_paths = []

        if not os.path.exists(directory):
            print(f"Warning: directory {directory} does not exist")
            return result, file_paths

        for filename in os.listdir(directory):
            if filename.endswith('.json'):
                file_path = os.path.join(directory, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        result.append(data)
                        file_paths.append(file_path)
                except Exception as e:
                    print(f"Error loading file {filename}: {e}")

        return result, file_paths

    def analyze_code_duplication(self) -> Dict[str, Any]:
        """Analyze code duplication rate using MD5 hash."""
        benign_stats = self._analyze_duplication_for_files(
            self.benign_data, self.benign_files, "benign"
        )
        malware_stats = self._analyze_duplication_for_files(
            self.malware_data, self.malware_files, "malware"
        )

        return {
            "benign_duplication": benign_stats,
            "malware_duplication": malware_stats
        }

    def _analyze_duplication_for_files(
        self, data_list: List[Dict], file_paths: List[str], category: str
    ) -> Dict[str, Any]:
        """Analyze code duplication for a category."""
        code_hash_map = {}
        file_stats = {}
        total_snippets = 0
        unique_snippets = 0
        duplicated_snippets = 0

        for idx, (data, file_path) in enumerate(zip(data_list, file_paths)):
            filename = os.path.basename(file_path)
            snippets = self._extract_code_snippets(data)
            file_total_snippets = len(snippets)
            file_unique_hashes = set()
            file_duplicate_count = 0

            if file_total_snippets == 0:
                continue

            for snippet in snippets:
                snippet_hash = self._hash_code_snippet(snippet)

                if snippet_hash in code_hash_map:
                    code_hash_map[snippet_hash].append(file_path)
                    duplicated_snippets += 1
                    file_duplicate_count += 1
                else:
                    code_hash_map[snippet_hash] = [file_path]
                    unique_snippets += 1

                file_unique_hashes.add(snippet_hash)

            duplication_rate = file_duplicate_count / file_total_snippets if file_total_snippets > 0 else 0

            if file_duplicate_count > 0:
                file_stats[filename] = {
                    "total_snippets": file_total_snippets,
                    "unique_snippets": len(file_unique_hashes),
                    "duplicated_snippets": file_duplicate_count,
                    "duplication_rate": f"{duplication_rate:.2%}"
                }

            total_snippets += file_total_snippets

        if category == "benign":
            self.benign_code_hashes = code_hash_map
        else:
            self.malware_code_hashes = code_hash_map

        global_duplication_rate = duplicated_snippets / total_snippets if total_snippets > 0 else 0

        most_duplicated = sorted(
            [(hash_val, len(files)) for hash_val, files in code_hash_map.items() if len(files) > 1],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        most_duplicated_info = [
            {"hash": h, "count": count, "files": code_hash_map[h][:5]}
            for h, count in most_duplicated
        ]

        return {
            "total_files": len(data_list),
            "files_with_duplicates": len(file_stats),
            "total_snippets": total_snippets,
            "unique_snippets": unique_snippets,
            "duplicated_snippets": duplicated_snippets,
            "global_duplication_rate": f"{global_duplication_rate:.2%}",
            "most_duplicated": most_duplicated_info
        }

    def _extract_code_snippets(self, data: Any) -> List[str]:
        """Extract code snippets from JSON data."""
        snippets = []

        if isinstance(data, list):
            for item in data:
                snippets.extend(self._extract_snippets_from_item(item))
        else:
            snippets.extend(self._extract_snippets_from_item(data))

        return snippets

    def _extract_snippets_from_item(self, item: Dict) -> List[str]:
        """Extract code snippets from a single item."""
        snippets = []

        pattern_key = "pattern_analysis" if "pattern_analysis" in item else "Pattern analysis"
        if pattern_key in item:
            pattern_analysis = item[pattern_key]

            if "contextual_code" in pattern_analysis and pattern_analysis["contextual_code"]:
                if isinstance(pattern_analysis["contextual_code"], str):
                    snippets.append(pattern_analysis["contextual_code"])
                elif isinstance(pattern_analysis["contextual_code"], list):
                    snippets.extend([str(code) for code in pattern_analysis["contextual_code"] if code])

        return snippets

    def _hash_code_snippet(self, snippet: str) -> str:
        """Calculate MD5 hash of normalized code snippet."""
        normalized = self._normalize_code(snippet)
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()

    def _normalize_code(self, code: str) -> str:
        """Normalize code by removing whitespace and comments."""
        lines = []
        for line in code.split('\n'):
            comment_pos = line.find('#')
            if comment_pos >= 0:
                line = line[:comment_pos]
            line = line.strip()
            if line:
                lines.append(line)
        return ' '.join(lines)

    def extract_sequences(self, data_list: List[Dict]) -> Dict[str, List[List[str]]]:
        """Extract sequences at different granularity levels."""
        sequences = {level: [] for level in self.granularity_levels}

        for data in data_list:
            if isinstance(data, list):
                for item in data:
                    self._process_item(item, sequences)
            else:
                self._process_item(data, sequences)

        return sequences

    def _process_item(self, item: Dict, sequences: Dict[str, List[List[str]]]) -> None:
        """Process a single item to extract sequences."""
        pattern_key = "pattern_analysis" if "pattern_analysis" in item else "Pattern analysis"
        if pattern_key not in item:
            return

        pattern_analysis = item[pattern_key]
        if "mapped_sequence" not in pattern_analysis:
            return

        mapped_sequence = pattern_analysis["mapped_sequence"]

        for level in self.granularity_levels:
            seq = [entry[level] for entry in mapped_sequence if level in entry]
            if seq:
                sequences[level].append(seq)

    def remove_consecutive_duplicates(self, sequence: List[str]) -> List[str]:
        """Remove consecutive duplicates from sequence."""
        if not sequence:
            return []
        result = [sequence[0]]
        for i in range(1, len(sequence)):
            if sequence[i] != sequence[i-1]:
                result.append(sequence[i])
        return result

    def count_sequences(self, sequences: Dict[str, List[List[str]]]) -> Dict[str, Dict[str, int]]:
        """Count sequences at each granularity level."""
        result = {}

        for level, seq_list in sequences.items():
            total_sequences = len(seq_list)

            seq_strings = [','.join(seq) for seq in seq_list]
            unique_sequences = len(set(seq_strings))

            dedup_seqs = [self.remove_consecutive_duplicates(seq) for seq in seq_list]
            dedup_seq_strings = [','.join(seq) for seq in dedup_seqs]
            unique_dedup_sequences = len(set(dedup_seq_strings))

            total_items = sum(len(seq) for seq in seq_list)
            total_dedup_items = sum(len(seq) for seq in dedup_seqs)

            result[level] = {
                "total_sequences": total_sequences,
                "unique_sequences": unique_sequences,
                "total_items": total_items,
                "dedup_total_items": total_dedup_items,
                "dedup_unique_sequences": unique_dedup_sequences
            }

        return result

    def analyze_sequence_lengths(self, sequences: Dict[str, List[List[str]]]) -> Dict[str, Dict[str, Dict[int, int]]]:
        """Analyze sequence length distribution."""
        result = {}

        for level, seq_list in sequences.items():
            length_counts = collections.Counter([len(seq) for seq in seq_list])
            dedup_seqs = [self.remove_consecutive_duplicates(seq) for seq in seq_list]
            dedup_length_counts = collections.Counter([len(seq) for seq in dedup_seqs])

            result[level] = {
                "original": dict(sorted(length_counts.items())),
                "deduplicated": dict(sorted(dedup_length_counts.items()))
            }

        return result

    def compare_sequences(
        self, benign_seqs: Dict[str, List[List[str]]], malware_seqs: Dict[str, List[List[str]]]
    ) -> Dict[str, Dict[str, Any]]:
        """Compare benign and malware sequences."""
        result = {}

        for level in self.granularity_levels:
            if level not in benign_seqs or level not in malware_seqs:
                continue

            benign_seq_strings = [','.join(seq) for seq in benign_seqs[level]]
            malware_seq_strings = [','.join(seq) for seq in malware_seqs[level]]

            benign_set = set(benign_seq_strings)
            malware_set = set(malware_seq_strings)

            common = benign_set.intersection(malware_set)
            benign_only = benign_set - malware_set
            malware_only = malware_set - benign_set

            benign_dedup = set(','.join(self.remove_consecutive_duplicates(seq)) for seq in benign_seqs[level])
            malware_dedup = set(','.join(self.remove_consecutive_duplicates(seq)) for seq in malware_seqs[level])

            common_dedup = benign_dedup.intersection(malware_dedup)
            benign_only_dedup = benign_dedup - malware_dedup
            malware_only_dedup = malware_dedup - benign_dedup

            result[level] = {
                "original": {
                    "common": len(common),
                    "benign_only": len(benign_only),
                    "malware_only": len(malware_only),
                    "benign_total": len(benign_set),
                    "malware_total": len(malware_set)
                },
                "deduplicated": {
                    "common": len(common_dedup),
                    "benign_only": len(benign_only_dedup),
                    "malware_only": len(malware_only_dedup),
                    "benign_total": len(benign_dedup),
                    "malware_total": len(malware_dedup)
                }
            }

        return result

    def run_analysis(self) -> Dict[str, Any]:
        """Run complete analysis."""
        self.load_data()

        duplication_analysis = self.analyze_code_duplication()

        benign_seqs = self.extract_sequences(self.benign_data)
        malware_seqs = self.extract_sequences(self.malware_data)

        benign_counts = self.count_sequences(benign_seqs)
        malware_counts = self.count_sequences(malware_seqs)

        benign_lengths = self.analyze_sequence_lengths(benign_seqs)
        malware_lengths = self.analyze_sequence_lengths(malware_seqs)

        comparison = self.compare_sequences(benign_seqs, malware_seqs)

        return {
            "code_duplication": duplication_analysis,
            "benign_statistics": benign_counts,
            "malware_statistics": malware_counts,
            "benign_length_distribution": benign_lengths,
            "malware_length_distribution": malware_lengths,
            "benign_vs_malware_comparison": comparison
        }

    def print_summary(self, results: Dict[str, Any]) -> None:
        """Print analysis summary."""
        print("\n" + "=" * 60)
        print("API Sequence Analysis Summary")
        print("=" * 60)

        print("\n### Code Duplication ###")
        for category in ["benign", "malware"]:
            dup = results["code_duplication"][f"{category}_duplication"]
            print(f"\n{category.upper()}:")
            print(f"  Total files: {dup['total_files']}")
            print(f"  Total snippets: {dup['total_snippets']}")
            print(f"  Unique snippets: {dup['unique_snippets']}")
            print(f"  Duplication rate: {dup['global_duplication_rate']}")

        print("\n### Sequence Statistics (id level) ###")
        for category in ["benign", "malware"]:
            stats = results[f"{category}_statistics"].get("id", {})
            print(f"\n{category.upper()}:")
            print(f"  Total sequences: {stats.get('total_sequences', 0)}")
            print(f"  Unique sequences: {stats.get('unique_sequences', 0)}")
            print(f"  Dedup unique: {stats.get('dedup_unique_sequences', 0)}")

        print("\n### Benign vs Malware Comparison (id level) ###")
        comp = results["benign_vs_malware_comparison"].get("id", {})
        if comp:
            orig = comp.get("original", {})
            print(f"  Common sequences: {orig.get('common', 0)}")
            print(f"  Benign only: {orig.get('benign_only', 0)}")
            print(f"  Malware only: {orig.get('malware_only', 0)}")


def main():
    parser = argparse.ArgumentParser(description="Analyze API sequences before pattern mining")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    analyzer = APISequenceAnalyzer(BENIGN_DIRS, MALWARE_DIRS)
    results = analyzer.run_analysis()
    analyzer.print_summary(results)

    output_file = args.output or os.path.join(OUTPUT_DIR, "sequence_analysis_results.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\nFull results saved to: {output_file}")


if __name__ == "__main__":
    main()
