import os
import json
import shutil
from pathlib import Path
from socketai import SocketAI
from config import Config
from datetime import datetime
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dataset_analysis.log'),
        logging.StreamHandler()
    ]
)

class DatasetAnalyzer:
    def __init__(self):
        self.benign_dataset = "/home2/blue/Documents/NPMAnalysis/Dataset/unzip_benign"
        self.malware_dataset = "/home2/blue/Documents/NPMAnalysis/Dataset/unzip_malware"
        
        
        self.benign_output = "/home2/blue/Documents/NPMAnalysis/Codes/tool_detect/tool_output/socketai/benign"
        self.malware_output = "/home2/blue/Documents/NPMAnalysis/Codes/tool_detect/tool_output/socketai/malware"
        
        
        os.makedirs(self.benign_output, exist_ok=True)
        os.makedirs(self.malware_output, exist_ok=True)
        
        
        self.socketai = SocketAI()
        
        
        self.max_file_size = 175 * 1024
        
        
        self.max_js_files = 25

    def get_package_versions(self, dataset_path):   
        package_versions = []
        
        for package_name in os.listdir(dataset_path):
            package_path = os.path.join(dataset_path, package_name)
            if os.path.isdir(package_path):
                
                for version in os.listdir(package_path):
                    version_path = os.path.join(package_path, version)
                    if os.path.isdir(version_path):
                        package_versions.append((package_name, version, version_path))
        
        return package_versions

    def collect_js_files(self, version_path):

        js_files = []
        priority_files = []
        
        
        package_json = os.path.join(version_path, "package.json")
        if os.path.isfile(package_json) and os.path.getsize(package_json) <= self.max_file_size:
            priority_files.append(package_json)
        
        index_js = os.path.join(version_path, "index.js")
        if os.path.isfile(index_js) and os.path.getsize(index_js) <= self.max_file_size:
            priority_files.append(index_js)
        
        
        for root, _, files in os.walk(version_path):
            for file in files:
                if file.endswith('.js'):
                    file_path = os.path.join(root, file)
                    
                    
                    if os.path.getsize(file_path) > self.max_file_size:
                        continue
                    
                    
                    if file_path not in priority_files:
                        js_files.append(file_path)
        

        return priority_files + js_files[:self.max_js_files - len(priority_files)]

    def analyze_file(self, file_path, output_dir, package_name, version):
        try:
            relative_path = os.path.basename(file_path)
            file_output_dir = os.path.join(output_dir, package_name, version, relative_path)
            os.makedirs(file_output_dir, exist_ok=True)
            
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            logging.info(f"Analysing file: {file_path}")
            

            initial_reports = self.socketai.step1_initial_reports(code)
            
            
            for i, report in enumerate(initial_reports):
                report_path = os.path.join(file_output_dir, f"step1_report_{i+1}.txt")
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
            
            
            critical_reports = self.socketai.step2_critical_reports(initial_reports, code)
            
            
            for i, report in enumerate(critical_reports):
                report_path = os.path.join(file_output_dir, f"step2_report_{i+1}.txt")
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
            
            
            final_report = self.socketai.step3_final_report(critical_reports, code)
            
            
            final_report_path = os.path.join(file_output_dir, "step3_final_report.txt")
            with open(final_report_path, 'w', encoding='utf-8') as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)
            
            
            summary = {
                "file_path": file_path,
                "is_malicious": final_report.get('malware', 0) > Config.MALWARE_THRESHOLD,
                "malware_score": final_report.get('malware', 0),
                "security_risk": final_report.get('securityRisk', 0),
                "obfuscated": final_report.get('obfuscated', 0),
                "confidence": final_report.get('confidence', 0),
                "conclusion": final_report.get('conclusion', '')
            }
            
            summary_path = os.path.join(file_output_dir, "summary.txt")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            
            return summary
            
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            return {
                "file_path": file_path,
                "error": str(e),
                "is_malicious": False
            }

    def analyze_dataset(self):

        
        logging.info("Processing benign dataset...")
        benign_packages = self.get_package_versions(self.benign_dataset)
        self._process_packages(benign_packages, self.benign_output, "benign")
        
        
        logging.info("Processing malware dataset...")
        malware_packages = self.get_package_versions(self.malware_dataset)
        self._process_packages(malware_packages, self.malware_output, "malware")
        
        logging.info("Dataset analysis completed")

    def _process_packages(self, packages, output_dir, dataset_type):

        total = len(packages)
        
        for i, (package_name, version, version_path) in enumerate(packages):
            try:
                logging.info(f"Processing {dataset_type} package [{i+1}/{total}]: {package_name}@{version}")
                

                js_files = self.collect_js_files(version_path)
                logging.info(f"Found {len(js_files)} Python files to analyze")
                
                
                package_version_dir = os.path.join(output_dir, package_name, version)
                os.makedirs(package_version_dir, exist_ok=True)
                
                
                results = []
                for file_path in js_files:
                    result = self.analyze_file(file_path, output_dir, package_name, version)
                    results.append(result)
                

                malicious_files = [r for r in results if r.get('is_malicious', False)]
                package_summary = {
                    "package_name": package_name,
                    "version": version,
                    "total_files": len(js_files),
                    "analyzed_files": len(results),
                    "malicious_files": len(malicious_files),
                    "is_malicious": len(malicious_files) > 0,
                    "analysis_date": datetime.now().isoformat()
                }
                
                summary_path = os.path.join(package_version_dir, "package_summary.txt")
                with open(summary_path, 'w', encoding='utf-8') as f:
                    json.dump(package_summary, f, indent=2, ensure_ascii=False)
                
            except Exception as e:
                logging.error(f"Error processing package {package_name}@{version}: {str(e)}")


def main():
    logging.info("Starting dataset analysis")
    analyzer = DatasetAnalyzer()
    analyzer.analyze_dataset()
    logging.info("Dataset analysis completed")


if __name__ == "__main__":
    main() 