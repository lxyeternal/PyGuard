#!/usr/bin/env python3

import os
import pickle
import sys
from pathlib import Path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.insert(0, project_root)
from Core.RAG.rag_knowledge_builder import PatternKnowledge, CaseKnowledge


KB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rag_knowledge_base")


def show_complete_knowledge():
    try:
        with open(os.path.join(KB_DIR, 'pattern_knowledge.pkl'), 'rb') as f:
            patterns = pickle.load(f)
        with open(os.path.join(KB_DIR, 'case_knowledge.pkl'), 'rb') as f:
            cases = pickle.load(f)
        print("Complete Pattern-Case Knowledge Structure Display")
        print("=" * 120)
        selected_pattern_id = None
        selected_pattern = None
        max_cases = 0
        for pattern_id, pattern in patterns.items():
            if 'malware' in pattern.pattern_type:
                case_count = len([c for c in cases.values() if c.pattern_id == pattern_id])
                if case_count > max_cases and case_count >= 3:
                    max_cases = case_count
                    selected_pattern_id = pattern_id
                    selected_pattern = pattern
        if not selected_pattern:
            print("No suitable Pattern found")
            return
        print(f"PATTERN DETAILED INFORMATION")
        print("=" * 120)
        print(f"Pattern ID: {selected_pattern_id}")
        print(f"Pattern Sequence: {selected_pattern.pattern}")
        print(f"Pattern Type: {selected_pattern.pattern_type}")
        print(f"Support: {selected_pattern.support}")
        print(f"Coverage: {selected_pattern.coverage}")
        print()
        print("Pattern Semantic Summary:")
        print("-" * 80)
        print(selected_pattern.semantic_summary)
        print()
        print("Security Assessment:")
        print("-" * 80)
        print(selected_pattern.security_assessment)
        print()
        print("Typical Scenarios:")
        print("-" * 80)
        for i, scenario in enumerate(selected_pattern.typical_scenarios, 1):
            print(f"  {i}. {scenario}")
        print()
        print("Malware Characteristics:")
        print("-" * 80)
        for i, char in enumerate(selected_pattern.malware_characteristics, 1):
            print(f"  {i}. {char}")
        print()
        print("Distinction Rules:")
        print("-" * 80)
        for i, rule in enumerate(selected_pattern.distinction_rules, 1):
            print(f"  {i}. {rule}")
        print()
        print("Pattern Embedding Information:")
        print("-" * 80)
        if hasattr(selected_pattern, 'pattern_embedding') and selected_pattern.pattern_embedding is not None:
            print(f"  Embedding Shape: {selected_pattern.pattern_embedding.shape}")
            print(f"  Embedding Dtype: {selected_pattern.pattern_embedding.dtype}")
            print(f"  Embedding Range: [{selected_pattern.pattern_embedding.min():.6f}, {selected_pattern.pattern_embedding.max():.6f}]")
            print(f"  Embedding Mean: {selected_pattern.pattern_embedding.mean():.6f}")
            print(f"  Embedding Std: {selected_pattern.pattern_embedding.std():.6f}")
            print(f"  First 10 values: {selected_pattern.pattern_embedding[:10]}")
        else:
            print("  No pattern embedding found")
        print()
        related_cases = [(cid, case) for cid, case in cases.items()
                        if case.pattern_id == selected_pattern_id]
        print(f"Total Associated Cases: {len(related_cases)}")
        print("=" * 120)
        display_cases = related_cases[:10]
        for i, (case_id, case) in enumerate(display_cases, 1):
            print(f"\nCASE {i} DETAILED INFORMATION")
            print("=" * 120)
            print(f"Case ID: {case_id}")
            print(f"Filename: {case.filename}")
            print(f"Label: {case.label}")
            print(f"Associated Pattern ID: {case.pattern_id}")
            print()
            print("API Call Sequence:")
            print("-" * 80)
            api_info = []
            for j, api in enumerate(case.case_action_sequence, 1):
                api_id = api.get('id', 'unknown')
                api_info.append(f"{j}. {api_id}")
            for info in api_info:
                print(f"  {info}")
            print()
            print("Code Context:")
            print("-" * 80)
            print("```python")
            print(case.code_context)
            print("```")
            print()
            print("Case Summary:")
            print("-" * 80)
            print(case.case_summary)
            print()
            print("Key Behaviors:")
            print("-" * 80)
            for j, behavior in enumerate(case.key_behaviors, 1):
                print(f"  {j}. {behavior}")
            print()
            print("Risk Indicators:")
            print("-" * 80)
            for j, risk in enumerate(case.risk_indicators, 1):
                print(f"  {j}. {risk}")
            print()
            if hasattr(case, 'detection_features') and case.detection_features:
                print("Detection Features:")
                print("-" * 80)
                for j, feature in enumerate(case.detection_features, 1):
                    print(f"  {j}. {feature}")
                print()
            if hasattr(case, 'malware_family') and case.malware_family:
                print(f"Malware Family: {case.malware_family}")
                print()
            if hasattr(case, 'attack_techniques') and case.attack_techniques:
                print("Attack Techniques:")
                print("-" * 80)
                for j, technique in enumerate(case.attack_techniques, 1):
                    print(f"  {j}. {technique}")
                print()
            print("Case Embedding Information:")
            print("-" * 80)
            if hasattr(case, 'similarity_embedding') and case.similarity_embedding is not None:
                print("  Similarity Embedding:")
                print(f"    - Shape: {case.similarity_embedding.shape}")
                print(f"    - Dtype: {case.similarity_embedding.dtype}")
                print(f"    - Range: [{case.similarity_embedding.min():.6f}, {case.similarity_embedding.max():.6f}]")
                print(f"    - Mean: {case.similarity_embedding.mean():.6f}")
                print(f"    - Std: {case.similarity_embedding.std():.6f}")
                print(f"    - First 10 values: {case.similarity_embedding[:10]}")
            else:
                print("    No similarity embedding found")
            if hasattr(case, 'action_sequence_embedding') and case.action_sequence_embedding is not None:
                print("  Action Sequence Embedding:")
                print(f"    - Shape: {case.action_sequence_embedding.shape}")
                print(f"    - Dtype: {case.action_sequence_embedding.dtype}")
                print(f"    - Range: [{case.action_sequence_embedding.min():.6f}, {case.action_sequence_embedding.max():.6f}]")
                print(f"    - Mean: {case.action_sequence_embedding.mean():.6f}")
                print(f"    - Std: {case.action_sequence_embedding.std():.6f}")
                print(f"    - First 10 values: {case.action_sequence_embedding[:10]}")
            else:
                print("    No action sequence embedding found")
            print()
            print("=" * 120)
        print(f"\nDisplay Complete! Pattern {selected_pattern_id} and its first {len(display_cases)} of {len(related_cases)} associated Cases complete knowledge structure")
    except Exception as e:
        print(f"Error reading database: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    show_complete_knowledge()
