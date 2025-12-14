import os
import json
import sys
import time
from typing import List, Dict, Any, Tuple, Set
from collections import defaultdict
from prefixspan import PrefixSpan
import hashlib
from datetime import datetime

PYGUARD_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE_DIR = os.path.join(PYGUARD_ROOT, "Core", "ActionSequence", "action_sequences")
BENIGN_DIRS = [
    os.path.join(BASE_DIR, "benign_guarddog"),
    os.path.join(BASE_DIR, "benign_bandit4mal")
]
MALWARE_DIRS = [
    os.path.join(BASE_DIR, "malware"),
    os.path.join(BASE_DIR, "malware_fn")
]
SUPPORT_LEVELS = [30, 25, 20, 15, 10, 7, 5, 3, 2]
GRANULARITY_LEVELS = ["id"]
MIN_PATTERN_LENGTH = 3
MAX_PATTERN_LENGTH = 10
MAX_PATTERNS_PER_LEVEL = 500
EARLY_STOP_COVERAGE = 0.95
BATCH_SIZE = 100
DYNAMIC_SUPPORT_ADJUSTMENT = True
MAX_PROCESSING_TIME_PER_LEVEL = 300
OUTPUT_DIR = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "pattern_results")
HIERARCHICAL_OUTPUT_DIR = os.path.join(PYGUARD_ROOT, "Core", "PatternGenerator", "hierarchical_patterns")
PURE_PATTERN_ONLY = False
REMOVE_CONSECUTIVE_DUPLICATES = True
DEDUPLICATE_SAMPLES = True
LOG_FILE = os.path.join(OUTPUT_DIR, f"prefixspan_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
DISTINCTION_THRESHOLD = 0.7
DISTINCTION_SUPPORT_LEVELS = [20, 15, 10, 7, 5, 3, 2]
class Tee:
    def __init__(self, *files):
        self.files = files
        
    def write(self, obj):
        for file in self.files:
            file.write(obj)
            file.flush()
            
    def flush(self):
        for file in self.files:
            file.flush()


os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(HIERARCHICAL_OUTPUT_DIR, exist_ok=True)

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
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                extracted_samples = []
                
                if isinstance(data, list):
                    extracted_samples.extend([item for item in data if isinstance(item, dict) and "pattern_analysis" in item])
                
                elif isinstance(data, dict):
                    if "pattern_analysis" in data:
                        extracted_samples.append(data)
                    elif "context" in data or "contexts" in data:
                        contexts = data.get("context") or data.get("contexts") or []
                        if isinstance(contexts, list):
                            extracted_samples.extend([ctx for ctx in contexts if isinstance(ctx, dict) and "pattern_analysis" in ctx])
                
                for sample in extracted_samples:
                    if "file_path" not in sample:
                        sample["file_path"] = filename
                
                samples.extend(extracted_samples)
                    
            except Exception as e:
                print(f"Error loading file {filename}: {e}")
    
    print(f"Loaded {len(samples)} samples")
    return samples

def _extract_contextual_code(sample: Dict) -> Tuple[str, str]:
    if "pattern_analysis" not in sample:
        return None, None
        
    pattern_analysis = sample["pattern_analysis"]
    
    code = pattern_analysis.get("contextual_code")
    
    if code is None:
        contexts = []
        for context_key in ["malicious_contexts", "benign_contexts"]:
            if context_key in pattern_analysis:
                contexts_data = pattern_analysis[context_key]
                if isinstance(contexts_data, list):
                    contexts.extend(contexts_data)
        
        for ctx in contexts:
            if isinstance(ctx, dict) and "contextual_code" in ctx:
                code = ctx["contextual_code"]
                if code:
                    break
    
    if code:
        normalized_code = str(code).strip()
        code_hash = hashlib.md5(normalized_code.encode()).hexdigest()
        return normalized_code, code_hash
    
    return None, None

def deduplicate_samples(samples: List[Dict]) -> List[Dict]:
    if not DEDUPLICATE_SAMPLES:
        return samples
    
    unique_samples = []
    code_hashes = set()
    
    for sample in samples:
        _, code_hash = _extract_contextual_code(sample)
        
        if code_hash and code_hash not in code_hashes:
            code_hashes.add(code_hash)
            unique_samples.append(sample)
    
    print(f"After deduplication, {len(unique_samples)} samples are kept (removed {len(samples) - len(unique_samples)} duplicate samples)")
    return unique_samples

def remove_consecutive_duplicates(sequence):
    if not sequence:
        return []
    return [item for i, item in enumerate(sequence) if i == 0 or item != sequence[i-1]]

def remove_cyclic_patterns(sequence, max_pattern_length=5, min_repeats=3):
    if len(sequence) <= 1:
        return sequence
    
    for pattern_length in range(min(max_pattern_length, len(sequence) // min_repeats), 0, -1):
        i = 0
        while i <= len(sequence) - pattern_length * min_repeats:
            pattern = tuple(sequence[i:i+pattern_length])
            
            max_repeats = 1
            current_repeats = 1
            end_pos = i + pattern_length
            
            while end_pos + pattern_length <= len(sequence):
                next_segment = tuple(sequence[end_pos:end_pos+pattern_length])
                if next_segment == pattern:
                    current_repeats += 1
                    end_pos += pattern_length
                else:
                    break
            
            max_repeats = max(max_repeats, current_repeats)
            
            if max_repeats >= min_repeats:
                return sequence[:i+pattern_length] + sequence[i+pattern_length*max_repeats:]
            
            i += 1
    
    return sequence

def clean_sequence(sequence, remove_duplicates=True, remove_cycles=True):
    if not sequence:
        return []
    
    result = sequence
    
    if remove_duplicates:
        result = remove_consecutive_duplicates(result)
    
    if remove_cycles:
        prev_len = -1
        while prev_len != len(result):
            prev_len = len(result)
            result = remove_cyclic_patterns(result)
    
    return result

def extract_sequences(samples: List[Dict], granularity: str) -> List[Tuple[List[str], str]]:
    """
    Extract sequences of different granularities from samples
    Returns: [(sequence, label), ...], where label is "benign" or "malware"
    """
    sequences = []
    sample_sequence_counts = defaultdict(int)
    
    for sample in samples:
        try:
            if "pattern_analysis" not in sample:
                continue
                
            extracted_seqs = []
            pattern_analysis = sample["pattern_analysis"]
            
            if "mapped_sequence" in pattern_analysis and isinstance(pattern_analysis["mapped_sequence"], list):
                extracted_seqs.append(pattern_analysis["mapped_sequence"])
            
            if "mapped_sequences" in pattern_analysis and isinstance(pattern_analysis["mapped_sequences"], list):
                extracted_seqs.extend(pattern_analysis["mapped_sequences"])
            
            context_keys = [
                ("malicious_contexts", "malicious_contexts"),
                ("benign_contexts", "benign_contexts")
            ]
            
            for key_pair in context_keys:
                for key in key_pair:
                    if key in pattern_analysis:
                        contexts = pattern_analysis[key]
                        if isinstance(contexts, list):
                            for ctx in contexts:
                                if isinstance(ctx, dict) and "mapped_sequence" in ctx:
                                    extracted_seqs.append(ctx["mapped_sequence"])
            
            valid_seqs_count = 0
            label = sample.get("label", "unknown")
            
            for seq_data in extracted_seqs:
                if not isinstance(seq_data, list):
                    continue
                    
                seq = []
                for api in seq_data:
                    if isinstance(api, dict):
                        if granularity == "id" and "id" in api:
                            seq.append(api["id"])
                        elif granularity != "id" and granularity in api:
                            seq.append(api[granularity])
                
                if seq:
                    valid_seqs_count += 1
                    if REMOVE_CONSECUTIVE_DUPLICATES:
                        seq = clean_sequence(seq)
                    sequences.append((seq, label))
            
            if valid_seqs_count > 0:
                sample_sequence_counts[label] += valid_seqs_count
        
        except Exception as e:
            print(f"Error extracting sequences: {e}, sample: {sample.get('file_name', 'unknown')}")
    
    label_counts = defaultdict(int)
    for _, label in sequences:
        label_counts[label] += 1
    
    print(f"Extracted {len(sequences)} sequences from {len(samples)} samples")
    for label, count in label_counts.items():
        print(f"  - {label} label: {count} sequences")
    
    for label, seq_count in sample_sequence_counts.items():
        label_sample_count = sum(1 for s in samples if s.get("label", "unknown") == label)
        if label_sample_count > 0:
            avg_seqs = seq_count / label_sample_count
            print(f"  - {label} sample average generated {avg_seqs:.2f} sequences")
    
    return sequences

def mine_patterns(sequences: List[List[str]], min_support: int) -> List[Tuple[int, List[str]]]:
    """Use PrefixSpan to mine frequent sequence patterns, and filter length"""
    if not sequences:
        return []
    
    try:
        ps = PrefixSpan(sequences)
        patterns = ps.frequent(min_support)
        
        cleaned_patterns = []
        for support, pattern in patterns:
            if len(pattern) < MIN_PATTERN_LENGTH or len(pattern) > MAX_PATTERN_LENGTH:
                continue
                
            if REMOVE_CONSECUTIVE_DUPLICATES:
                cleaned_pattern = clean_sequence(pattern)
                if not cleaned_pattern or len(cleaned_pattern) < MIN_PATTERN_LENGTH:
                    continue
                cleaned_patterns.append((support, cleaned_pattern))
            else:
                cleaned_patterns.append((support, pattern))
        
        unique_patterns = {}
        for support, pattern in cleaned_patterns:
            pattern_tuple = tuple(pattern)
            if pattern_tuple in unique_patterns:
                unique_patterns[pattern_tuple] = max(unique_patterns[pattern_tuple], support)
            else:
                unique_patterns[pattern_tuple] = support
        
        result_patterns = [(support, list(pattern)) for pattern, support in unique_patterns.items()]
        
        patterns_sorted = sorted(result_patterns, key=lambda x: (-len(x[1]), -x[0]))
        
        if len(patterns_sorted) > MAX_PATTERNS_PER_LEVEL:
            print(f"Warning: pattern number {len(patterns_sorted)} exceeds limit {MAX_PATTERNS_PER_LEVEL}, take the first {MAX_PATTERNS_PER_LEVEL} high-quality patterns")
            patterns_sorted = patterns_sorted[:MAX_PATTERNS_PER_LEVEL]
        
        print(f"Original mined pattern number: {len(patterns)}, length filtered: {len(cleaned_patterns)}, deduplicated: {len(result_patterns)}, final output: {len(patterns_sorted)}")
        return patterns_sorted
    except Exception as e:
        print(f"Error mining patterns: {e}")
        return []

def hierarchical_mine_patterns(benign_sequences: List[List[str]], malware_sequences: List[List[str]], 
                              support_levels: List[int] = None) -> List[Tuple[int, List[str], str]]:
    """
    Hierarchical mining frequent sequence patterns, gradually reducing support and filtering covered sequences
    Focus on solving the problem of pattern overlap when support is reduced
    
    Args:
        benign_sequences: Benign sequence list
        malware_sequences: Malware sequence list
        support_levels: Support level list, from high to low
        
    Returns:
        [(support, pattern), ...] Standard format pattern list
        [(support, pattern, type, level), ...] Detailed pattern information
    """
    if support_levels is None:
        support_levels = SUPPORT_LEVELS
        
    final_patterns = []
    
    globally_covered_benign = set()
    globally_covered_malware = set()
    
    level_stats = {}
    
    for level_idx, min_support in enumerate(support_levels):
        level_start_time = time.time()
        print(f"\n{'='*20} Round {level_idx+1} mining (support: {min_support}) {'='*20}")
        
        remaining_benign = [seq for i, seq in enumerate(benign_sequences) if i not in globally_covered_benign]
        remaining_malware = [seq for i, seq in enumerate(malware_sequences) if i not in globally_covered_malware]
        
        print(f"Current remaining sequences: {len(remaining_benign)} benign, {len(remaining_malware)} malware")
        
        if len(remaining_benign) == 0 and len(remaining_malware) == 0:
            print("All sequences are covered, stop mining")
            break
            
        all_sequences = remaining_benign + remaining_malware
        
        if not all_sequences:
            print("No remaining sequences to mine")
            break
            
        current_patterns = mine_patterns(all_sequences, min_support)
        
        if not current_patterns:
            print(f"No patterns found at support {min_support}, try next support level")
            continue
            
        print(f"Found {len(current_patterns)} patterns at support {min_support}")
        
        current_coverage = (len(globally_covered_benign) + len(globally_covered_malware)) / (len(benign_sequences) + len(malware_sequences))
        if current_coverage >= EARLY_STOP_COVERAGE:
            print(f"Target coverage {current_coverage:.2%} >= {EARLY_STOP_COVERAGE:.2%}, stop mining early")
            break
        
        valid_patterns = []
        
        print(f"Start batch analyzing pattern coverage...")
        for batch_start in range(0, len(current_patterns), BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, len(current_patterns))
            batch_patterns = current_patterns[batch_start:batch_end]
            print(f"   Batch {batch_start//BATCH_SIZE + 1}/{(len(current_patterns)-1)//BATCH_SIZE + 1}: pattern {batch_start+1}-{batch_end}")
            
            promising_patterns = []
            for support, pattern in batch_patterns:
                quick_benign_hits = sum(1 for seq in remaining_benign[:min(50, len(remaining_benign))] if any(item in seq for item in pattern[:3]))
                quick_malware_hits = sum(1 for seq in remaining_malware[:min(50, len(remaining_malware))] if any(item in seq for item in pattern[:3]))
                
                if quick_benign_hits + quick_malware_hits >= 2:
                    promising_patterns.append((support, pattern))
            
            print(f"    Quick pre-screening: {len(batch_patterns)} -> {len(promising_patterns)} promising patterns")
            
            for support, pattern in promising_patterns:
                benign_covered_indices = []
                for i, seq in enumerate(remaining_benign):
                    if is_subsequence(pattern, seq):
                        original_idx = [j for j, _ in enumerate(benign_sequences) if j not in globally_covered_benign][i]
                        benign_covered_indices.append(original_idx)
                
                malware_covered_indices = []
                for i, seq in enumerate(remaining_malware):
                    if is_subsequence(pattern, seq):
                        original_idx = [j for j, _ in enumerate(malware_sequences) if j not in globally_covered_malware][i]
                        malware_covered_indices.append(original_idx)
                
                benign_count = len(benign_covered_indices)
                malware_count = len(malware_covered_indices)
                total_count = benign_count + malware_count
                
                if total_count == 0:
                    continue
                    
                benign_ratio = benign_count / total_count
                malware_ratio = malware_count / total_count
                
                pattern_type = None
                is_valid = False
                
                if PURE_PATTERN_ONLY:
                    if benign_count > 0 and malware_count == 0:
                        pattern_type = "benign_only"
                        is_valid = True
                    elif malware_count > 0 and benign_count == 0:
                        pattern_type = "malware_only"
                        is_valid = True
                else:
                    if benign_ratio >= DISTINCTION_THRESHOLD:
                        pattern_type = "benign_biased" if malware_count > 0 else "benign_only"
                        is_valid = True
                    elif malware_ratio >= DISTINCTION_THRESHOLD:
                        pattern_type = "malware_biased" if benign_count > 0 else "malware_only"
                        is_valid = True
                
                if is_valid:
                    if pattern_type in ["benign_only", "benign_biased"]:
                        global_malware_conflicts = 0
                        for i, seq in enumerate(malware_sequences):
                            if is_subsequence(pattern, seq):
                                global_malware_conflicts += 1
                        
                        global_malware_ratio = global_malware_conflicts / len(malware_sequences) if malware_sequences else 0
                        if global_malware_ratio > (1 - DISTINCTION_THRESHOLD):
                            print(f"Reject benign pattern {pattern[:3]}..., global malware coverage: {global_malware_ratio:.2%}")
                            continue
                            
                    elif pattern_type in ["malware_only", "malware_biased"]:
                        global_benign_conflicts = 0
                        for i, seq in enumerate(benign_sequences):
                            if is_subsequence(pattern, seq):
                                global_benign_conflicts += 1
                        
                        global_benign_ratio = global_benign_conflicts / len(benign_sequences) if benign_sequences else 0
                        if global_benign_ratio > (1 - DISTINCTION_THRESHOLD):
                            print(f"Reject malware pattern {pattern[:3]}..., global benign coverage: {global_benign_ratio:.2%}")
                            continue
                    
                    valid_patterns.append({
                        'support': support,
                        'pattern': pattern,
                        'type': pattern_type,
                        'benign_covered': set(benign_covered_indices),
                        'malware_covered': set(malware_covered_indices),
                        'benign_ratio': benign_ratio,
                        'malware_ratio': malware_ratio
                    })
        
        print(f"This round found {len(valid_patterns)} valid patterns")
        
        valid_patterns.sort(key=lambda x: (-len(x['pattern']), -max(x['benign_ratio'], x['malware_ratio']), -x['support']))
        
        selected_patterns = []
        round_covered_benign = set()
        round_covered_malware = set()
        
        for pattern_info in valid_patterns:
            new_benign = pattern_info['benign_covered'] - globally_covered_benign - round_covered_benign
            new_malware = pattern_info['malware_covered'] - globally_covered_malware - round_covered_malware
            
            if len(new_benign) > 0 or len(new_malware) > 0:
                selected_patterns.append(pattern_info)
                round_covered_benign.update(new_benign)
                round_covered_malware.update(new_malware)
                
                print(f"Select pattern: {pattern_info['pattern'][:5]}... (type: {pattern_info['type']}, length: {len(pattern_info['pattern'])}, new coverage: benign{len(new_benign)}/malware{len(new_malware)})")
        
        globally_covered_benign.update(round_covered_benign)
        globally_covered_malware.update(round_covered_malware)
        
        for pattern_info in selected_patterns:
            final_patterns.append((pattern_info['support'], pattern_info['pattern'], pattern_info['type'], level_idx))
        
        pattern_type_count = {}
        for pattern_info in selected_patterns:
            ptype = pattern_info['type']
            pattern_type_count[ptype] = pattern_type_count.get(ptype, 0) + 1
        
        level_stats[min_support] = {
            "total_selected": len(selected_patterns),
            "pattern_types": pattern_type_count,
            "new_covered_benign": len(round_covered_benign),
            "new_covered_malware": len(round_covered_malware),
            "total_covered_benign": len(globally_covered_benign),
            "total_covered_malware": len(globally_covered_malware)
        }
        
        print(f"This round new coverage: {len(round_covered_benign)} benign sequences, {len(round_covered_malware)} malware sequences")
        print(f"Total coverage: benign {len(globally_covered_benign)}/{len(benign_sequences)} ({len(globally_covered_benign)/len(benign_sequences):.2%}), " +
              f"malware {len(globally_covered_malware)}/{len(malware_sequences)} ({len(globally_covered_malware)/len(malware_sequences):.2%})")
        
        level_time = time.time() - level_start_time
        print(f"This round processing time: {level_time:.2f} seconds")
        
        if DYNAMIC_SUPPORT_ADJUSTMENT and level_time > MAX_PROCESSING_TIME_PER_LEVEL:
            remaining_levels = len(support_levels) - level_idx - 1
            if remaining_levels > 0:
                print(f"Warning: This round processing time {level_time:.2f} seconds exceeds the limit {MAX_PROCESSING_TIME_PER_LEVEL} seconds")
                print(f"To avoid too long processing, skip the remaining {remaining_levels} lower support levels")
                break
    
    print("\nHierarchical mining final statistics:")
    for level_idx, min_support in enumerate(support_levels):
        if min_support in level_stats:
            stats = level_stats[min_support]
            print(f"Round {level_idx+1} (support: {min_support}): selected {stats['total_selected']} patterns, " +
                 f"type distribution: {stats['pattern_types']}, " +
                 f"new coverage: benign {stats['new_covered_benign']} malware {stats['new_covered_malware']}")
    
    standard_patterns = [(support, pattern) for support, pattern, _, _ in final_patterns]
    
    print(f"Final high-quality pattern number: {len(standard_patterns)}")
    
    return standard_patterns, final_patterns

def optimize_patterns_by_greedy_set_cover(patterns_with_coverage, min_pattern_length=3, coverage_threshold=0.95):
    """
    Optimize pattern selection based on greedy set cover algorithm, reduce redundancy

    Args:
        patterns_with_coverage: [(index, support, pattern, covered_indices), ...] format pattern list
        min_pattern_length: Minimum pattern length required for the first round of selection
        coverage_threshold: Target coverage threshold, e.g., 0.95 means covering 95% of the original covered cases

    Returns: Optimized pattern list [(support, pattern), ...]
    """
    if not patterns_with_coverage:
        return []
    
    all_covered_indices = set()
    for _, _, _, covered_indices in patterns_with_coverage:
        all_covered_indices.update(covered_indices)
    
    total_cases = len(all_covered_indices)
    target_cases = int(total_cases * coverage_threshold)
    print(f"  Original covered cases: {total_cases}, target covered cases: {target_cases}")
    
    uncovered_indices = all_covered_indices.copy()
    selected_patterns = []
    
    for round_num, current_min_length in enumerate([min_pattern_length, 2, 1]):
        print(f"  Round {round_num+1} selection (minimum length: {current_min_length}) - current uncovered cases: {len(uncovered_indices)}")
        
        if len(uncovered_indices) == 0 or len(uncovered_indices) <= total_cases - target_cases:
            break
            
        eligible_patterns = [(i, s, p, covered) for i, s, p, covered in patterns_with_coverage 
                            if i not in [idx for idx, _, _, _ in selected_patterns] and len(p) >= current_min_length]
        
        if not eligible_patterns:
            continue
            
        while eligible_patterns and uncovered_indices and len(uncovered_indices) > total_cases - target_cases:
            patterns_new_coverage = []
            for i, s, p, covered in eligible_patterns:
                new_covered = len(covered.intersection(uncovered_indices))
                if new_covered > 0:
                    patterns_new_coverage.append((i, s, p, covered, new_covered, len(p)))
            
            if not patterns_new_coverage:
                break
                
            patterns_new_coverage.sort(key=lambda x: (x[4], x[5]), reverse=True)
            
            best_i, best_s, best_p, best_covered, _, _ = patterns_new_coverage[0]
            selected_patterns.append((best_i, best_s, best_p, best_covered))
            
            uncovered_indices -= best_covered
            
            eligible_patterns = [(i, s, p, c) for i, s, p, c in eligible_patterns if i != best_i]
            
            covered_percent = (total_cases - len(uncovered_indices)) / total_cases * 100
            print(f"    Selected pattern length: {len(best_p)}, new coverage: {len(best_covered.intersection(all_covered_indices - uncovered_indices))}, total coverage: {covered_percent:.2f}%")
    
    print(f"  Finally selected {len(selected_patterns)} patterns, covering {(total_cases - len(uncovered_indices))/total_cases:.2%} of the original cases")
    
    optimized_patterns = [(s, p) for _, s, p, _ in selected_patterns]
    return optimized_patterns

def is_subsequence(pattern: List[str], sequence: List[str]) -> bool:
    """Check if the pattern is a subsequence of the sequence"""
    i, j = 0, 0
    while i < len(pattern) and j < len(sequence):
        if pattern[i] == sequence[j]:
            i += 1
        j += 1
    return i == len(pattern)

def analyze_sequence_coverage(patterns, benign_sequences, malware_sequences):
    """Analyze the coverage of patterns on sequences"""
    benign_covered_indices = set()
    malware_covered_indices = set()
    
    for _, pattern in patterns:
        for i, seq in enumerate(benign_sequences):
            if i not in benign_covered_indices and is_subsequence(pattern, seq):
                benign_covered_indices.add(i)
        
        for i, seq in enumerate(malware_sequences):
            if i not in malware_covered_indices and is_subsequence(pattern, seq):
                malware_covered_indices.add(i)
    
    benign_count = len(benign_sequences)
    malware_count = len(malware_sequences)
    total_count = benign_count + malware_count
    
    benign_covered = len(benign_covered_indices)
    malware_covered = len(malware_covered_indices)
    total_covered = benign_covered + malware_covered
    
    return {
        'benign_covered': benign_covered,
        'benign_uncovered': benign_count - benign_covered,
        'malware_covered': malware_covered,
        'malware_uncovered': malware_count - malware_covered,
        'benign_coverage_ratio': benign_covered / benign_count if benign_count else 0,
        'malware_coverage_ratio': malware_covered / malware_count if malware_count else 0,
        'total_coverage_ratio': total_covered / total_count if total_count else 0
    }

def save_optimized_patterns(patterns, benign_sequences, malware_sequences, granularity: str):
    """
    Save a comprehensive JSON file for each granularity, containing:
    1. The number and proportion of benign/malware cases covered by each pattern
    2. Statistics (total pattern number, coverage rate, etc.)
    """
    output_file = os.path.join(OUTPUT_DIR, f"patterns_{granularity}.json")
    
    patterns_info = []
    pattern_types = {
        "benign_only": 0,
        "malware_only": 0,
        "benign_biased": 0,
        "malware_biased": 0
    }

    benign_only_covered_cases = set()
    malware_only_covered_cases = set()

    all_covered_benign = set()
    all_covered_malware = set()

    for support, pattern in patterns:
        benign_covered_cases = []
        malware_covered_cases = []

        for i, seq in enumerate(benign_sequences):
            if is_subsequence(pattern, seq):
                benign_covered_cases.append(i)
                all_covered_benign.add(i)

        for i, seq in enumerate(malware_sequences):
            if is_subsequence(pattern, seq):
                malware_covered_cases.append(i)
                all_covered_malware.add(i)

        benign_count = len(benign_covered_cases)
        malware_count = len(malware_covered_cases)
        total_count = benign_count + malware_count

        benign_ratio = benign_count / len(benign_sequences) if benign_sequences else 0
        malware_ratio = malware_count / len(malware_sequences) if malware_sequences else 0

        benign_percent = benign_count / total_count if total_count > 0 else 0
        malware_percent = malware_count / total_count if total_count > 0 else 0

        # Determine pattern type
        if benign_count > 0 and malware_count == 0:
            pattern_type = "benign_only"
            pattern_types["benign_only"] += 1
            for idx in benign_covered_cases:
                benign_only_covered_cases.add(idx)
        elif malware_count > 0 and benign_count == 0:
            pattern_type = "malware_only"
            pattern_types["malware_only"] += 1
            for idx in malware_covered_cases:
                malware_only_covered_cases.add(idx)
        elif benign_percent >= DISTINCTION_THRESHOLD:
            pattern_type = "benign_biased"
            pattern_types["benign_biased"] += 1
        elif malware_percent >= DISTINCTION_THRESHOLD:
            pattern_type = "malware_biased"
            pattern_types["malware_biased"] += 1
        else:
            # Skip patterns that are not distinctive enough
            continue

        pattern_info = {
            "pattern": pattern,
            "support": support,
            "type": pattern_type,
            "coverage": {
                "benign_count": benign_count,
                "malware_count": malware_count,
                "total_count": total_count,
                "benign_coverage_ratio": float(benign_ratio),
                "malware_coverage_ratio": float(malware_ratio),
                "benign_percent": float(benign_percent),
                "malware_percent": float(malware_percent)
            },
            "benign_sequences": benign_covered_cases,
            "malware_sequences": malware_covered_cases
        }

        patterns_info.append(pattern_info)

    output_data = {
        "granularity": granularity,
        "patterns": patterns_info
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\nSaved to: {output_file}")
    print(f"Total patterns: {len(patterns_info)}")
    for ptype, count in pattern_types.items():
        if count > 0:
            print(f"  - {ptype}: {count}")

def distinction_mine_patterns(remaining_benign: List[List[str]], remaining_malware: List[List[str]], 
                            support_levels: List[int] = None) -> List[Tuple[int, List[str], str, float]]:
    """
    Second stage distinction mining:
    Mine sequences that are not covered by pure patterns, find patterns with high distinction
    
    Args:
        remaining_benign: Remaining uncovered benign sequences
        remaining_malware: Remaining uncovered malware sequences
        support_levels: Support level list
        
    Returns:
        [(support, pattern, type, distinction), ...] pattern list, where type is "benign_biased" or "malware_biased"
    """
    if not remaining_benign and not remaining_malware:
        print("No remaining sequences need to be mined for distinction")
        return []
        
    print(f"\n{'='*20} Start second stage distinction mining {'='*20}")
    print(f"Remaining sequences: {len(remaining_benign)} benign, {len(remaining_malware)} malware")
    
    if support_levels is None:
        support_levels = DISTINCTION_SUPPORT_LEVELS
    
    final_patterns = []
    
    covered_benign_indices = set()
    covered_malware_indices = set()
    
    for level_idx, min_support in enumerate(support_levels):
        print(f"\n--- {level_idx+1}th round of distinction mining (support: {min_support}) ---")
        
        current_benign = [seq for i, seq in enumerate(remaining_benign) if i not in covered_benign_indices]
        current_malware = [seq for i, seq in enumerate(remaining_malware) if i not in covered_malware_indices]
        
        print(f"Current remaining sequences: {len(current_benign)} benign, {len(current_malware)} malware")
        
        if not current_benign and not current_malware:
            print("All sequences are covered, stop mining")
            break
            
        all_sequences = current_benign + current_malware
        
        if not all_sequences:
            print("No remaining sequences to mine")
            break
            
        current_patterns = mine_patterns(all_sequences, min_support)
        
        if not current_patterns:
            print(f"No patterns found at support {min_support}, trying next support level")
            continue
            
        print(f"Found {len(current_patterns)} candidate patterns at support {min_support}")
        
        high_distinction_patterns = []
        
        for support, pattern in current_patterns:
            benign_covered = []
            for i, seq in enumerate(current_benign):
                if is_subsequence(pattern, seq):
                    benign_covered.append(i)
            
            malware_covered = []
            for i, seq in enumerate(current_malware):
                if is_subsequence(pattern, seq):
                    malware_covered.append(i)
            
            benign_count = len(benign_covered)
            malware_count = len(malware_covered)
            total_count = benign_count + malware_count
            
            if total_count > 0:
                benign_ratio = benign_count / total_count
                malware_ratio = malware_count / total_count
                
                if benign_ratio >= DISTINCTION_THRESHOLD:
                    distinction = benign_ratio
                    pattern_type = "benign_biased"
                    high_distinction_patterns.append((support, pattern, pattern_type, distinction, set(benign_covered), set(malware_covered)))
                elif malware_ratio >= DISTINCTION_THRESHOLD:
                    distinction = malware_ratio
                    pattern_type = "malware_biased"
                    high_distinction_patterns.append((support, pattern, pattern_type, distinction, set(benign_covered), set(malware_covered)))
        
        high_distinction_patterns.sort(key=lambda x: (x[3], len(x[1])), reverse=True)
        
        print(f"Found {len(high_distinction_patterns)} high distinction patterns")
        
        if not high_distinction_patterns:
            continue
        
        selected_patterns = []
        
        new_covered_benign = set()
        new_covered_malware = set()
        
        while high_distinction_patterns:
            pattern_new_coverage = []
            for support, pattern, pattern_type, distinction, benign_covered, malware_covered in high_distinction_patterns:
                new_benign_coverage = len(benign_covered - covered_benign_indices - new_covered_benign)
                new_malware_coverage = len(malware_covered - covered_malware_indices - new_covered_malware)
                new_coverage = new_benign_coverage + new_malware_coverage
                
                if new_coverage > 0:
                    pattern_new_coverage.append((support, pattern, pattern_type, distinction, 
                                               benign_covered, malware_covered, new_coverage))
            
            if not pattern_new_coverage:
                break
                
            pattern_new_coverage.sort(key=lambda x: (x[6], x[3]), reverse=True)
            
            best_support, best_pattern, best_type, best_distinction, best_benign, best_malware, _ = pattern_new_coverage[0]
            
            new_covered_benign.update(best_benign)
            new_covered_malware.update(best_malware)
            
            selected_patterns.append((best_support, best_pattern, best_type, best_distinction))
            
            high_distinction_patterns = [(s, p, t, d, b, m) for s, p, t, d, b, m in high_distinction_patterns 
                                      if p != best_pattern]
            
            print(f"  Selected {best_type} pattern, distinction: {best_distinction:.2%}, new covered: {len(best_benign - covered_benign_indices)} benign, {len(best_malware - covered_malware_indices)} malware")
        
        covered_benign_indices.update(new_covered_benign)
        covered_malware_indices.update(new_covered_malware)
        
        final_patterns.extend(selected_patterns)
        
        print(f"Current round new covered: {len(new_covered_benign)} benign, {len(new_covered_malware)} malware")
        print(f"Total coverage: benign {len(covered_benign_indices)}/{len(remaining_benign)} ({len(covered_benign_indices)/len(remaining_benign):.2%} if remaining_benign else 0), " +
              f"malware {len(covered_malware_indices)}/{len(remaining_malware)} ({len(covered_malware_indices)/len(remaining_malware):.2%} if remaining_malware else 0)")
    
    print(f"\nDistinction mining results:")
    print(f"Total found {len(final_patterns)} high distinction patterns")
    benign_biased = sum(1 for _, _, t, _ in final_patterns if t == "benign_biased")
    malware_biased = sum(1 for _, _, t, _ in final_patterns if t == "malware_biased")
    print(f"Among them, benign biased patterns: {benign_biased}, malware biased patterns: {malware_biased}")
    
    return final_patterns

def save_distinction_patterns(patterns, remaining_benign, remaining_malware, granularity: str):
    """Save distinction patterns to file"""
    output_file = os.path.join(OUTPUT_DIR, f"distinction_patterns_{granularity}.json")
    
    patterns_info = []
    
    for support, pattern, pattern_type, distinction in patterns:
        benign_covered = []
        for i, seq in enumerate(remaining_benign):
            if is_subsequence(pattern, seq):
                benign_covered.append(i)
        
        malware_covered = []
        for i, seq in enumerate(remaining_malware):
            if is_subsequence(pattern, seq):
                malware_covered.append(i)
        
        benign_count = len(benign_covered)
        malware_count = len(malware_covered)
        total_count = benign_count + malware_count
        
        benign_ratio = benign_count / total_count if total_count > 0 else 0
        malware_ratio = malware_count / total_count if total_count > 0 else 0
        
        pattern_info = {
            "pattern": pattern,
            "support": support,
            "type": pattern_type,
            "distinction": float(distinction),
            "coverage": {
                "benign_count": benign_count,
                "malware_count": malware_count,
                "total_count": total_count,
                "benign_ratio": float(benign_ratio),
                "malware_ratio": float(malware_ratio)
            },
            "benign_sequences": benign_covered,
            "malware_sequences": malware_covered
        }
        
        patterns_info.append(pattern_info)
    
    output_data = {
        "granularity": granularity,
        "distinction_threshold": DISTINCTION_THRESHOLD,
        "total_patterns": len(patterns),
        "benign_biased_patterns": sum(1 for _, _, t, _ in patterns if t == "benign_biased"),
        "malware_biased_patterns": sum(1 for _, _, t, _ in patterns if t == "malware_biased"),
        "total_remaining_sequences": {
            "benign": len(remaining_benign),
            "malware": len(remaining_malware)
        },
        "patterns": patterns_info
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"Distinction patterns saved to: {output_file}")

def main():
    log_file = open(LOG_FILE, 'w', encoding='utf-8')
    original_stdout = sys.stdout
    sys.stdout = Tee(sys.stdout, log_file)

    try:
        print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Load samples
        benign_samples = load_json_files(BENIGN_DIRS)
        malware_samples = load_json_files(MALWARE_DIRS)

        for sample in benign_samples:
            sample["label"] = "benign"
        for sample in malware_samples:
            sample["label"] = "malware"

        if DEDUPLICATE_SAMPLES:
            benign_samples = deduplicate_samples(benign_samples)
            malware_samples = deduplicate_samples(malware_samples)

        print(f"Samples: {len(benign_samples)} benign, {len(malware_samples)} malware")

        all_samples = benign_samples + malware_samples
        granularity = "id"

        # Extract sequences
        all_sequences_with_labels = extract_sequences(all_samples, granularity)
        benign_sequences = [seq for seq, label in all_sequences_with_labels if label == "benign"]
        malware_sequences = [seq for seq, label in all_sequences_with_labels if label == "malware"]
        all_sequences = [seq for seq, _ in all_sequences_with_labels]

        print(f"Sequences: {len(benign_sequences)} benign, {len(malware_sequences)} malware")

        if not benign_sequences and not malware_sequences:
            print("Error: No valid sequences extracted")
            return

        # Mine patterns
        final_patterns, detailed_patterns = hierarchical_mine_patterns(
            benign_sequences,
            malware_sequences
        )

        if not final_patterns:
            print("No patterns found")
            return

        # Count pattern types
        pattern_type_stats = {}
        for _, pattern, pattern_type, _ in detailed_patterns:
            pattern_type_stats[pattern_type] = pattern_type_stats.get(pattern_type, 0) + 1

        # Print summary
        print(f"\n{'='*50}")
        print(f"Pattern Mining Results")
        print(f"{'='*50}")
        print(f"Total patterns: {len(final_patterns)}")
        print(f"\nPattern types:")
        for ptype in ["benign_only", "malware_only", "benign_biased", "malware_biased"]:
            count = pattern_type_stats.get(ptype, 0)
            if count > 0:
                print(f"  - {ptype}: {count}")

        # Coverage
        coverage = analyze_sequence_coverage(final_patterns, benign_sequences, malware_sequences)
        print(f"\nCoverage:")
        print(f"  - Benign: {coverage['benign_covered']}/{len(benign_sequences)} ({coverage['benign_coverage_ratio']:.1%})")
        print(f"  - Malware: {coverage['malware_covered']}/{len(malware_sequences)} ({coverage['malware_coverage_ratio']:.1%})")

        # Save results
        save_optimized_patterns(final_patterns, benign_sequences, malware_sequences, granularity)

        all_lengths = [len(seq) for seq in all_sequences if seq]
        avg_length = sum(all_lengths) / len(all_lengths) if all_lengths else 0
        long_sequences = [seq for seq in all_sequences if len(seq) >= MIN_PATTERN_LENGTH]

        hierarchical_output_file = os.path.join(HIERARCHICAL_OUTPUT_DIR, f"enhanced_patterns_{granularity}.json")
        hierarchical_results = {
            "granularity": granularity,
            "support_levels": SUPPORT_LEVELS,
            "min_pattern_length": MIN_PATTERN_LENGTH,
            "max_pattern_length": MAX_PATTERN_LENGTH,
            "distinction_threshold": DISTINCTION_THRESHOLD,
            "pure_pattern_only": PURE_PATTERN_ONLY,
            "patterns": [
                {
                    "pattern": pattern,
                    "support": support,
                    "type": pattern_type,
                    "level": level,
                    "length": len(pattern)
                }
                for support, pattern, pattern_type, level in detailed_patterns
            ],
            "coverage": coverage,
            "pattern_type_distribution": pattern_type_stats,
            "sequence_statistics": {
                "total_benign_sequences": len(benign_sequences),
                "total_malware_sequences": len(malware_sequences),
                "avg_sequence_length": avg_length,
                "long_sequences_ratio": len(long_sequences)/len(all_sequences) if all_sequences else 0
            }
        }

        with open(hierarchical_output_file, 'w') as f:
            json.dump(hierarchical_results, f, indent=2, ensure_ascii=False)

        print(f"\nOutput: {hierarchical_output_file}")
        print(f"End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    finally:
        sys.stdout = original_stdout
        log_file.close()

if __name__ == "__main__":
    main() 