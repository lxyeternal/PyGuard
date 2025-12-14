#!/usr/bin/env python3

import os
import json
import time
import multiprocessing
from pathlib import Path
from datetime import datetime
import logging
import random
from socketai import SocketAI
from config import Config


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(processName)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('multiprocess_analysis.log'),
        logging.StreamHandler()
    ]
)


logger = logging.getLogger()

def is_analysis_complete(file_output_dir):
    """
    Check if the analysis result of the file is complete
    """
    try:

        if not os.path.exists(file_output_dir):
            return False
        

        step1_reports = [f for f in os.listdir(file_output_dir) if f.startswith("step1_report_") and f.endswith(".txt")]
        if len(step1_reports) != 5:
            return False
        

        step2_reports = [f for f in os.listdir(file_output_dir) if f.startswith("step2_report_") and f.endswith(".txt")]
        if len(step2_reports) != 5:
            return False
        

        if not os.path.exists(os.path.join(file_output_dir, "step3_final_report.txt")):
            return False
        

        if not os.path.exists(os.path.join(file_output_dir, "summary.txt")):
            return False
        

        try:
            with open(os.path.join(file_output_dir, "step3_final_report.txt"), 'r', encoding='utf-8') as f:
                final_report = json.load(f)
            

            required_fields = ["malware", "securityRisk", "obfuscated", "confidence", "conclusion"]
            for field in required_fields:
                if field not in final_report:
                    return False
            

            return True
        
        except (json.JSONDecodeError, UnicodeDecodeError, IOError):
            return False
    
    except Exception as e:
        logger.error(f"Error checking analysis completeness: {str(e)}")
        return False

def process_package(package_info):
    package_name, version, version_path, is_malware = package_info
    
    output_dir = Config.MALWARE_OUTPUT_PATH if is_malware else Config.BENIGN_OUTPUT_PATH
    dataset_type = "malware" if is_malware else "benign"
    
    process_id = os.getpid()
    
    try:
        logger.info(f"Process {process_id} started processing {dataset_type} package: {package_name}@{version}")
        
        package_version_dir = os.path.join(output_dir, package_name, version)
        os.makedirs(package_version_dir, exist_ok=True)
        
        package_summary_path = os.path.join(package_version_dir, "package_summary.txt")
        package_already_analyzed = False
        
        if os.path.exists(package_summary_path):
            try:
                with open(package_summary_path, 'r', encoding='utf-8') as f:
                    package_summary = json.load(f)
                
                required_fields = ["package_name", "version", "total_files", "analyzed_files", "malicious_files", "is_malicious"]
                if all(field in package_summary for field in required_fields):
                    package_already_analyzed = True
            except:
                package_already_analyzed = False
        
        js_files = collect_js_files(version_path)
        logger.info(f"Process {process_id}: found {len(js_files)} Python files to analyze - {package_name}@{version}")
        
        if package_already_analyzed:
            all_files_analyzed = True
            for file_path in js_files:
                relative_path = os.path.basename(file_path)
                file_output_dir = os.path.join(output_dir, package_name, version, relative_path)
                if not is_analysis_complete(file_output_dir):
                    all_files_analyzed = False
                    break
            
            if all_files_analyzed:
                logger.info(f"Process {process_id}: package {package_name}@{version} is fully analyzed, skipping")
                return package_name, version, True
            else:
                logger.info(f"Process {process_id}: package {package_name}@{version} has some files not analyzed, continuing")
        
        socketai = SocketAI()
        
        results = []
        for file_path in js_files:
            try:
                relative_path = os.path.basename(file_path)
                file_output_dir = os.path.join(output_dir, package_name, version, relative_path)
                                
                if is_analysis_complete(file_output_dir):
                    logger.info(f"Process {process_id}: file {file_path} is fully analyzed, skipping")
                    
                    try:
                        with open(os.path.join(file_output_dir, "summary.txt"), 'r', encoding='utf-8') as f:
                            summary = json.load(f)
                        results.append(summary)
                        continue
                    except:
                        logger.warning(f"Process {process_id}: file {file_path} summary read failed, re-analyzing")
                
                os.makedirs(file_output_dir, exist_ok=True)
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                logger.info(f"Process {process_id}: analyzing file: {file_path}")
                
                logger.info(f"Process {process_id}: Step 1: generating initial report... - {package_name}@{version}")
                initial_reports = socketai.step1_initial_reports(code)
                
                for i, report in enumerate(initial_reports):
                    report_path = os.path.join(file_output_dir, f"step1_report_{i+1}.txt")
                    with open(report_path, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Process {process_id}: Step 2: generating critical report... - {package_name}@{version}")
                critical_reports = socketai.step2_critical_reports(initial_reports, code)
                
                for i, report in enumerate(critical_reports):
                    report_path = os.path.join(file_output_dir, f"step2_report_{i+1}.txt")
                    with open(report_path, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Process {process_id}: Step 3: generating final report... - {package_name}@{version}")
                final_report = socketai.step3_final_report(critical_reports, code)
                
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
                
                results.append(summary)
                
            except Exception as e:
                logger.error(f"Process {process_id}: error analyzing file {file_path}: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                results.append({
                    "file_path": file_path,
                    "error": str(e),
                    "is_malicious": False
                })
        
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
        
        logger.info(f"Process {process_id}: package {package_name}@{version} analysis completed")
        return package_name, version, True
        
    except Exception as e:
        logger.error(f"Process {process_id}: error processing package {package_name}@{version}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return package_name, version, False

def collect_js_files(version_path):
    """Collect Python files from the version directory, prioritizing package.json and index.js"""
    js_files = []
    priority_files = []
    
    # First find package.json and index.js
    package_json = os.path.join(version_path, "package.json")
    if os.path.isfile(package_json) and os.path.getsize(package_json) <= Config.MAX_FILE_SIZE:
        priority_files.append(package_json)
    
    index_js = os.path.join(version_path, "index.js")
    if os.path.isfile(index_js) and os.path.getsize(index_js) <= Config.MAX_FILE_SIZE:
        priority_files.append(index_js)
    
    # Then traverse all other JS files
    for root, _, files in os.walk(version_path):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                
                # Check file size
                if os.path.getsize(file_path) > Config.MAX_FILE_SIZE:
                    continue
                
                # If it's not already added as a priority file
                if file_path not in priority_files:
                    js_files.append(file_path)
    
    # Merge priority files and other JS files, and limit total number
    return priority_files + js_files[:Config.MAX_JS_FILES_PER_PACKAGE - len(priority_files)]

def get_package_versions(dataset_path):
    """Get all packages and versions in the dataset"""
    package_versions = []
    
    # Traverse the dataset directory
    for package_name in os.listdir(dataset_path):
        package_path = os.path.join(dataset_path, package_name)
        if os.path.isdir(package_path):
            # Traverse all versions of the package
            for version in os.listdir(package_path):
                version_path = os.path.join(package_path, version)
                if os.path.isdir(version_path):
                    package_versions.append((package_name, version, version_path))
    
    return package_versions

def print_banner():
    """Print program banner"""
    print("\nDataset paths:")
    print(f"- Benign dataset: {Config.BENIGN_DATASET_PATH}")
    print(f"- Malware dataset: {Config.MALWARE_DATASET_PATH}")
    print("\nOutput paths:")
    print(f"- Benign results: {Config.BENIGN_OUTPUT_PATH}")
    print(f"- Malware results: {Config.MALWARE_OUTPUT_PATH}")
    print(f"\nParallel processing: using {Config.PROCESS_COUNT} processes to analyze")
    print("="*60)

def main():
    """Main function"""
    print_banner()
    logging.info("Starting multiprocess dataset analysis")
    
    # Create output directories
    os.makedirs(Config.BENIGN_OUTPUT_PATH, exist_ok=True)
    os.makedirs(Config.MALWARE_OUTPUT_PATH, exist_ok=True)
    
    start_time = time.time()
    
    try:
        # Get all packages in the benign dataset
        logging.info("Getting benign dataset package list...")
        benign_packages = []
        for package_name in os.listdir(Config.BENIGN_DATASET_PATH):
            package_path = os.path.join(Config.BENIGN_DATASET_PATH, package_name)
            if os.path.isdir(package_path):
                for version in os.listdir(package_path):
                    version_path = os.path.join(package_path, version)
                    if os.path.isdir(version_path):
                        benign_packages.append((package_name, version, version_path, False))
        
        logging.info(f"Found {len(benign_packages)} benign package versions")
        
        logging.info("Getting malware dataset package list...")
        malware_packages = []
        for package_name in os.listdir(Config.MALWARE_DATASET_PATH):
            package_path = os.path.join(Config.MALWARE_DATASET_PATH, package_name)
            if os.path.isdir(package_path):
                for version in os.listdir(package_path):
                    version_path = os.path.join(package_path, version)
                    if os.path.isdir(version_path):
                        malware_packages.append((package_name, version, version_path, True))
        
        logging.info(f"Found {len(malware_packages)} malware package versions")
        
        # Merge and shuffle the task list
        all_packages = benign_packages + malware_packages
        random.shuffle(all_packages)
        
        logging.info(f"Total {len(all_packages)} packages to analyze, using {Config.PROCESS_COUNT} processes to analyze")
        
        # Use process pool to process tasks
        with multiprocessing.Pool(processes=Config.PROCESS_COUNT) as pool:
            results = []
            for i, package_info in enumerate(all_packages):
                package_name, version, _, is_malware = package_info
                dataset_type = "Malware" if is_malware else "Benign"
                logging.info(f"Submitting task [{i+1}/{len(all_packages)}]: {package_name}@{version} ({dataset_type})")
                
                # Asynchronous submit tasks
                result = pool.apply_async(process_package, (package_info,))
                results.append(result)
            
            # Wait for all tasks to complete and collect results
            completed = 0
            for result in results:
                package_name, version, success = result.get()  # This will block until the task is completed
                status = "Success" if success else "Failed"
                completed += 1
                logging.info(f"Progress: [{completed}/{len(all_packages)}] package {package_name}@{version} analysis {status}")
        
        # Show completion information
        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        logging.info("All packages analysis completed")
        print("\nAnalysis completed!")
        print(f"Total time: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds")
        print("Results saved to specified directory")
        
    except KeyboardInterrupt:
        logging.warning("Analysis interrupted by user")
        print("\n\nAnalysis interrupted by user")
    except Exception as e:
        logging.error(f"Error during analysis: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        print(f"\nError: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    # Set multiprocessing start method
    multiprocessing.set_start_method('spawn')
    main() 