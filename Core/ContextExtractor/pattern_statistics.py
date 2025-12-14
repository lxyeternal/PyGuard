"""
Statistics for malware code pattern frequency analysis.
"""
import os
import json
import re
from collections import defaultdict
from pathlib import Path
import hashlib

PYGUARD_ROOT = Path(__file__).parent.parent.parent
SOURCE_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "tool_scan_output" / "guarddog" / "malware")
OUTPUT_DIR = str(PYGUARD_ROOT / "Core" / "ContextExtractor" / "statistics")

os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_malicious_code_from_txt(txt_content, package_name, txt_file_path):
    """
    从报告中提取所有恶意代码片段，确保获取完整的代码
    """
    lines = txt_content.split('\n')
    
    code_snippets = []
    
    archive_pattern = r'Found \d+ potentially malicious indicators in (.*?)(\.tar\.gz|\.zip|\.whl)'
    archive_match = re.search(archive_pattern, txt_content)
    archive_path = ""
    if archive_match:
        archive_path = archive_match.group(1) + archive_match.group(2)
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        location_match = re.search(r'\*.*?\s+at\s+([\w\-\.\/]+\.py):(\d+)', line)
        if location_match:
            relative_path = location_match.group(1)
            line_number = location_match.group(2)
            
            malicious_type = ""
            for j in range(i-5, i):
                if j >= 0 and j < len(lines):
                    type_match = re.match(r'^([\w\-]+): found \d+ .* matches', lines[j].strip())
                    if type_match:
                        malicious_type = type_match.group(1)
                        break
            
            code_lines = []
            j = i + 1
            while j < len(lines):
                next_line = lines[j].strip()
                if not next_line or next_line.startswith('*') or re.match(r'^[\w\-]+: found \d+ .* matches', next_line):
                    break
                code_line = re.sub(r'^\s+', '', next_line)
                code_lines.append(code_line)
                j += 1
            
            code_snippet = '\n'.join(code_lines)
            
            if code_snippet:
                if not code_snippet.strip():
                    i = j
                    continue
                
                unzip_path = ""
                archive_name = ""
                if archive_path:
                    unzip_path = archive_path.replace('zip_malware', 'unzip_malware') \
                                          .replace('.tar.gz', '') \
                                          .replace('.zip', '') \
                                          .replace('.whl', '')
                    archive_name = os.path.basename(unzip_path)
                
                source_code_path = os.path.join(unzip_path, relative_path) if unzip_path else ""
                
                snippet_info = {
                    'package': package_name,
                    'path': relative_path,
                    'line': line_number,
                    'type': malicious_type,
                    'code': code_snippet,
                    'description': line,
                    'full_path': source_code_path,
                    'txt_file': txt_file_path,
                    'archive_path': archive_path,
                    'archive_name': archive_name
                }
                code_snippets.append(snippet_info)
            
            i = j
            continue
        
        i += 1
    
    return code_snippets

def is_benign(txt_content):
    """判断报告是否表明代码是良性的（没有恶意代码）"""
    if "Found 0 potentially malicious indicators" in txt_content or "benign" in txt_content.lower():
        return True
    return False

def normalize_code(code_snippet):
    """标准化代码片段，移除可能的变化（如变量名、空格等）"""
    normalized = re.sub(r'\s+', '', code_snippet)
    normalized = normalized.lower()
    return normalized

def hash_code(code_snippet):
    """对代码片段生成哈希值，用于比较相似性"""
    normalized = normalize_code(code_snippet)
    return hashlib.md5(normalized.encode()).hexdigest()

def main():
    """主函数，处理所有报告文件并统计恶意代码片段的频率"""
    txt_files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    print(f"找到 {len(txt_files)} 个txt文件")
    
    code_pattern_count = defaultdict(list)
    package_code_map = defaultdict(list)
    malicious_packages = 0
    benign_packages = 0
    
    all_code_snippets = []
    
    for txt_file in txt_files:
        package_name = os.path.splitext(txt_file)[0]
        txt_path = os.path.join(SOURCE_DIR, txt_file)
        
        try:
            with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
                txt_content = f.read()
            
            if is_benign(txt_content):
                print(f"{txt_file} 没有恶意代码")
                benign_packages += 1
                continue
            
            code_snippets = extract_malicious_code_from_txt(txt_content, package_name, txt_path)
            
            if not code_snippets:
                print(f"未从 {txt_file} 中提取到恶意代码片段")
                continue
            
            malicious_packages += 1
            
            all_code_snippets.extend(code_snippets)
            
            for snippet_info in code_snippets:
                code = snippet_info['code']
                if not code.strip():
                    continue
                
                hash_value = hash_code(code)
                
                if package_name not in code_pattern_count[hash_value]:
                    code_pattern_count[hash_value].append(package_name)
                    
                package_code_map[package_name].append((
                    hash_value,
                    code,
                    f"{snippet_info['path']}:{snippet_info['line']}",
                    snippet_info['type'],
                    snippet_info['txt_file'],
                    snippet_info['full_path'],
                    snippet_info['archive_path']
                ))
            
            print(f"从 {txt_file} 中提取并处理了 {len(code_snippets)} 个代码片段")
            
        except Exception as e:
            print(f"处理文件 {txt_file} 时出错: {e}")
    
    
    pattern_frequency = [(hash_val, len(packages), packages) 
                         for hash_val, packages in code_pattern_count.items()]
    pattern_frequency.sort(key=lambda x: x[1], reverse=True)
    
    report = {
        "summary": {
            "total_packages": len(txt_files),
            "malicious_packages": malicious_packages,
            "benign_packages": benign_packages,
            "unique_code_patterns": len(code_pattern_count)
        },
        "pattern_frequency": [],
        "pattern_details": {},
        "all_code_snippets": []
    }
    
    for hash_val, count, packages in pattern_frequency:
        example_code = ""
        example_type = ""
        example_txt_file = ""
        example_full_path = ""
        example_archive_path = ""
        
        for pkg in packages:
            for h, code, path, type_desc, txt_file, full_path, archive_path in package_code_map[pkg]:
                if h == hash_val:
                    example_code = code
                    example_type = type_desc
                    example_txt_file = txt_file
                    example_full_path = full_path
                    example_archive_path = archive_path
                    break
            if example_code:
                break
        
        report["pattern_frequency"].append({
            "hash": hash_val,
            "count": count,
            "packages": packages,
            "example_code": example_code,
            "type": example_type,
            "example_txt_file": example_txt_file,
            "example_full_path": example_full_path,
            "example_archive_path": example_archive_path
        })
    
    for pkg, code_list in package_code_map.items():
        pkg_patterns = []
        for hash_val, code, path, type_desc, txt_file, full_path, archive_path in code_list:
            pkg_patterns.append({
                "hash": hash_val,
                "code": code,
                "path": path,
                "type": type_desc,
                "txt_file": txt_file,
                "full_path": full_path,
                "archive_path": archive_path,
                "shared_with": len(code_pattern_count[hash_val])
            })
        report["pattern_details"][pkg] = pkg_patterns
    
    report["all_code_snippets"] = [
        {
            "package": snippet['package'],
            "path": snippet['path'],
            "line": snippet['line'],
            "type": snippet['type'],
            "code": snippet['code'],
            "description": snippet['description'],
            "txt_file": snippet['txt_file'],
            "full_path": snippet['full_path'],
            "archive_path": snippet['archive_path'],
            "archive_name": snippet['archive_name'],
            "hash": hash_code(snippet['code'])
        }
        for snippet in all_code_snippets
    ]
    
    with open(os.path.join(OUTPUT_DIR, "malware_pattern_stats.json"), 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    code_by_type = defaultdict(list)
    for snippet in all_code_snippets:
        code_by_type[snippet['type']].append(snippet)
    
    for type_name, snippets in code_by_type.items():
        with open(os.path.join(OUTPUT_DIR, f"malware_code_{type_name}.json"), 'w', encoding='utf-8') as f:
            json.dump(snippets, f, ensure_ascii=False, indent=2)
    
    with open(os.path.join(OUTPUT_DIR, "malware_pattern_summary.txt"), 'w', encoding='utf-8') as f:
        f.write(f"恶意代码模式统计报告\n")
        f.write(f"====================\n\n")
        f.write(f"总共分析包数量: {report['summary']['total_packages']}\n")
        f.write(f"恶意包数量: {report['summary']['malicious_packages']}\n")
        f.write(f"良性包数量: {report['summary']['benign_packages']}\n")
        f.write(f"唯一恶意代码模式数量: {report['summary']['unique_code_patterns']}\n\n")
        
        f.write(f"前10个最常见恶意代码模式:\n")
        f.write(f"========================\n\n")
        
        for i, pattern in enumerate(report["pattern_frequency"][:10], 1):
            f.write(f"{i}. 出现次数: {pattern['count']} 个包 (类型: {pattern['type']})\n")
            f.write(f"   示例代码:\n")
            for line in pattern['example_code'].split('\n'):
                f.write(f"      {line}\n")
            f.write(f"   哈希值: {pattern['hash']}\n")
            f.write(f"   示例检测报告: {pattern['example_txt_file']}\n")
            f.write(f"   源代码文件: {pattern['example_full_path']}\n")
            f.write(f"   包列表: {', '.join(pattern['packages'][:5])}{'...' if len(pattern['packages']) > 5 else ''}\n\n")
    
    print(f"\n统计完成！结果已保存到 {OUTPUT_DIR} 目录")
    print(f"- 总包数: {report['summary']['total_packages']}")
    print(f"- 恶意包: {report['summary']['malicious_packages']}")
    print(f"- 良性包: {report['summary']['benign_packages']}")
    print(f"- 唯一恶意代码模式: {report['summary']['unique_code_patterns']}")
    
    print("\n最常见的恶意代码模式:")
    for i, pattern in enumerate(pattern_frequency[:5], 1):
        hash_val, count, packages = pattern
        print(f"{i}. 出现在 {count} 个包中")

if __name__ == "__main__":
    main() 