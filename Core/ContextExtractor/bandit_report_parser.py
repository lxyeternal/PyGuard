"""
Parse bandit4mal security reports and generate detailed_reports.json.
Merges and deduplicates bandit4mal detection results.
"""
import os
import re
import json
from pathlib import Path
from collections import defaultdict


PYGUARD_ROOT = Path(__file__).parent.parent.parent
REPORT_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "tool_scan_output" / "bandit4mal" / "benign")
OUTPUT_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def parse_security_report(file_path):
    """Parse a single security report file."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    package_name = os.path.basename(file_path).replace('.txt', '')

    issue_pattern = r'>> Issue: \[([^:]+):([^\]]+)\].*?\n.*?Severity: ([^\s]+).*?Confidence: ([^\n]+)\n.*?Location: ([^\n]+):(\d+)\n.*?More Info: ([^\n]+)\n(.*?)(?=\n-{50}|\nCode scanned:)'
    issues = re.findall(issue_pattern, content, re.DOTALL)

    issue_types = defaultdict(int)
    detailed_issues = []

    for issue in issues:
        issue_id, issue_name, severity, confidence, location, line_num, more_info, context = issue
        issue_type = f"{issue_id}:{issue_name}"
        issue_types[issue_type] += 1

        code_lines = context.strip().split('\n')
        code = '\n'.join([line.strip() for line in code_lines if not line.strip().startswith('--')])

        detailed_issues.append({
            'type': issue_type,
            'severity': severity,
            'confidence': confidence,
            'location': location,
            'line': line_num,
            'code': code,
            'more_info': more_info
        })

    return {
        'package_name': package_name,
        'issue_count': len(issues),
        'issue_types': dict(issue_types),
        'detailed_issues': detailed_issues
    }


def process_all_reports():
    """Process all report files in the directory."""
    if not os.path.exists(REPORT_DIR):
        print(f"Report directory not found: {REPORT_DIR}")
        return None

    report_files = [f for f in os.listdir(REPORT_DIR) if f.endswith('.txt')]
    print(f"Found {len(report_files)} report files")

    all_issue_types = defaultdict(int)
    all_reports = []

    for i, report_file in enumerate(report_files):
        try:
            file_path = os.path.join(REPORT_DIR, report_file)
            result = parse_security_report(file_path)

            for issue_type, count in result['issue_types'].items():
                all_issue_types[issue_type] += count

            all_reports.append(result)

            if (i + 1) % 50 == 0 or (i + 1) == len(report_files):
                print(f"Processed {i+1}/{len(report_files)} files")

        except Exception as e:
            print(f"Error processing file {report_file}: {e}")

    summary = {
        'total_reports': len(report_files),
        'processed_reports': len(all_reports),
        'total_issues': sum(all_issue_types.values()),
        'issue_types': dict(all_issue_types)
    }

    with open(os.path.join(OUTPUT_DIR, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    with open(os.path.join(OUTPUT_DIR, 'detailed_reports.json'), 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, ensure_ascii=False, indent=2)

    generate_issue_type_report(all_reports, 'B814:read', 'read_issues.json')

    print(f"Processing complete, results saved in {OUTPUT_DIR}")
    return summary


def generate_issue_type_report(all_reports, target_type, output_filename):
    """Generate detailed report for a specific issue type."""
    type_issues = []

    for report in all_reports:
        package_name = report['package_name']
        issues = [issue for issue in report['detailed_issues'] if issue['type'] == target_type]

        if issues:
            type_issues.append({
                'package_name': package_name,
                'issues': issues
            })

    with open(os.path.join(OUTPUT_DIR, output_filename), 'w', encoding='utf-8') as f:
        json.dump(type_issues, f, ensure_ascii=False, indent=2)

    print(f"Found {sum(len(r['issues']) for r in type_issues)} {target_type} issues, saved in {output_filename}")


def print_sample_report():
    """Print a sample report for testing."""
    sample_files = [f for f in os.listdir(REPORT_DIR) if f.endswith('.txt')]
    if not sample_files:
        print("No sample files found")
        return None

    sample_file = os.path.join(REPORT_DIR, sample_files[0])
    result = parse_security_report(sample_file)

    print(f"\nSample report ({result['package_name']}) analysis:")
    print(f"Total issues: {result['issue_count']}")
    print("Issue type statistics:")
    for issue_type, count in result['issue_types'].items():
        print(f"  - {issue_type}: {count}")

    return result


if __name__ == "__main__":
    summary = process_all_reports()
