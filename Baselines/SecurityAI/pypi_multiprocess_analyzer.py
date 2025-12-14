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

# Set up main logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(processName)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pypi_multiprocess_analysis.log'),
        logging.StreamHandler()
    ]
)

# Get main logger
logger = logging.getLogger()

def get_output_dir(dataset_name, is_malware):
    """Get output directory path"""
    dataset_config = Config.DATASETS[dataset_name]
    return dataset_config["output_malware"] if is_malware else dataset_config["output_benign"]

def should_skip_package(package_name, dataset_name, is_malware):
    """
    Check if the package has been analyzed
    Simple logic: skip if package summary file exists, otherwise re-analyze the entire package
    """
    try:
        # Build package summary file path
        output_dir = get_output_dir(dataset_name, is_malware)
        package_summary_path = os.path.join(output_dir, package_name, f"{package_name}.txt")
        
        # Simple check: skip if file exists
        return os.path.exists(package_summary_path)
    
    except Exception as e:
        logger.error(f"Error checking package {package_name} completion status: {str(e)}")
        return False

def collect_py_files(package_path):
    """Collect Python files from the package directory, prioritizing setup.py and __init.py"""
    py_files = []
    priority_files = []
    
    # First find setup.py and __init.py
    setup_py = os.path.join(package_path, "setup.py")
    if os.path.isfile(setup_py) and os.path.getsize(setup_py) <= Config.MAX_FILE_SIZE:
        priority_files.append(setup_py)
    
    init_py = os.path.join(package_path, "__init__.py")
    if os.path.isfile(init_py) and os.path.getsize(init_py) <= Config.MAX_FILE_SIZE:
        priority_files.append(init_py)
    
    # Then traverse all other Python files
    for root, _, files in os.walk(package_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                
                # Check file size
                try:
                    if os.path.getsize(file_path) > Config.MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                
                # If it's not already added as a priority file
                if file_path not in priority_files:
                    py_files.append(file_path)
    
    # Merge priority files and other Python files, and limit total number
    return priority_files + py_files[:Config.MAX_PY_FILES_PER_PACKAGE - len(priority_files)]

def process_package(package_info):
    """Function to process a single package (run in a separate process)"""
    package_name, package_path, dataset_name, is_malware = package_info
    
    # Determine output directory
    dataset_config = Config.DATASETS[dataset_name]
    output_dir = dataset_config["output_malware"] if is_malware else dataset_config["output_benign"]
    dataset_type = "malware" if is_malware else "benign"
    
    # Get process ID for logging
    process_id = os.getpid()
    
    try:
        logger.info(f"Process {process_id} started processing {dataset_name}/{dataset_type} package: {package_name}")
        
        # Create package output directory (directly create a folder with the package name)
        package_output_dir = os.path.join(output_dir, package_name)
        os.makedirs(package_output_dir, exist_ok=True)
        
        # Collect Python files
        py_files = collect_py_files(package_path)
        logger.info(f"进程 {process_id}: 找到 {len(py_files)} 个Python文件进行分析 - {package_name}")
        
        # Create SocketAI instance (one instance per process)
        socketai = SocketAI()
        
        # Analyze each file
        results = []
        for file_path in py_files:
            try:
                # Get relative file name as directory name
                relative_path = os.path.relpath(file_path, package_path).replace(os.sep, '_')
                file_output_dir = os.path.join(package_output_dir, relative_path)
                
                # Create output directory
                os.makedirs(file_output_dir, exist_ok=True)
                
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                logger.info(f"Process {process_id}: analyzing file: {file_path}")
                
                # Execute three-step analysis
                # Step 1: initial report
                logger.info(f"Process {process_id}: Step 1: generating initial report... - {package_name}")
                initial_reports = socketai.step1_initial_reports(code)
                
                # Save initial report
                for i, report in enumerate(initial_reports):
                    report_path = os.path.join(file_output_dir, f"step1_report_{i+1}.txt")
                    with open(report_path, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                
                # Step 2: critical report
                logger.info(f"Process {process_id}: Step 2: generating critical report... - {package_name}")
                critical_reports = socketai.step2_critical_reports(initial_reports, code)
                
                # Save critical report
                for i, report in enumerate(critical_reports):
                    report_path = os.path.join(file_output_dir, f"step2_report_{i+1}.txt")
                    with open(report_path, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                
                # Step 3: final report
                logger.info(f"Process {process_id}: Step 3: generating final report... - {package_name}")
                final_report = socketai.step3_final_report(critical_reports, code)
                
                # Save final report
                final_report_path = os.path.join(file_output_dir, "step3_final_report.txt")
                with open(final_report_path, 'w', encoding='utf-8') as f:
                    json.dump(final_report, f, indent=2, ensure_ascii=False)
                
                # Save summary
                summary = {
                    "file_path": file_path,
                    "relative_path": relative_path,
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
        
        # Save package level summary (named the same as the package name)
        malicious_files = [r for r in results if r.get('is_malicious', False)]
        package_summary = {
            "package_name": package_name,
            "dataset": dataset_name,
            "dataset_type": dataset_type,
            "total_files": len(py_files),
            "analyzed_files": len(results),
            "malicious_files": len(malicious_files),
            "is_malicious": len(malicious_files) > 0,
            "analysis_date": datetime.now().isoformat(),
            "file_details": results
        }
        
        # Save to txt file named after the package name
        summary_path = os.path.join(package_output_dir, f"{package_name}.txt")
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(package_summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Process {process_id}: package {package_name} analysis completed")
        return package_name, dataset_name, True
        
    except Exception as e:
        logger.error(f"Process {process_id}: error processing package {package_name}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return package_name, dataset_name, False

def get_all_packages():
    """Get all packages in all datasets"""
    all_packages = []
    
    for dataset_name, dataset_config in Config.DATASETS.items():
        logger.info(f"Scanning dataset: {dataset_name}")
        
        # Scan benign packages
        benign_path = dataset_config["benign"]
        if os.path.exists(benign_path):
            for package_name in os.listdir(benign_path):
                package_path = os.path.join(benign_path, package_name)
                if os.path.isdir(package_path):
                    all_packages.append((package_name, package_path, dataset_name, False))
        
        # Scan malware packages
        malware_path = dataset_config["malware"]
        if os.path.exists(malware_path):
            for package_name in os.listdir(malware_path):
                package_path = os.path.join(malware_path, package_name)
                if os.path.isdir(package_path):
                    all_packages.append((package_name, package_path, dataset_name, True))
    
    return all_packages

def print_banner():
    """Print program banner"""
    print("\nDataset configuration:")   
    for dataset_name, config in Config.DATASETS.items():
        print(f"\n{dataset_name.upper()} dataset:")
        print(f"  - Benign data: {config['benign']}")
        print(f"  - Malware data: {config['malware']}")
        print(f"  - Benign output: {config['output_benign']}")
        print(f"  - Malware output: {config['output_malware']}")
    print(f"\nParallel processing: using {Config.PROCESS_COUNT} processes to analyze")
    print("="*80)

def main():
    """Main function"""
    print_banner()
    logging.info("Starting multiprocess dataset analysis")
    
    # Create all output directories
    for dataset_config in Config.DATASETS.values():
        os.makedirs(dataset_config["output_benign"], exist_ok=True)
        os.makedirs(dataset_config["output_malware"], exist_ok=True)
    
    start_time = time.time()
    
    try:
        # Get all packages
        logger.info("Getting all dataset package list...")
        all_packages = get_all_packages()
        total_packages = len(all_packages)
        
        # Check package processing status
        logger.info("Checking package processing status...")
        dataset_stats = {}
        skip_stats = {}
        packages_to_process = []
        
        for package_name, package_path, dataset_name, is_malware in all_packages:
            # Initialize statistics
            if dataset_name not in dataset_stats:
                dataset_stats[dataset_name] = {"benign": 0, "malware": 0}
                skip_stats[dataset_name] = {"benign_skip": 0, "malware_skip": 0, "benign_process": 0, "malware_process": 0}
            
            # Update total statistics
            if is_malware:
                dataset_stats[dataset_name]["malware"] += 1
            else:
                dataset_stats[dataset_name]["benign"] += 1
            
            # Check if skip
            should_skip = should_skip_package(package_name, dataset_name, is_malware)
            if should_skip:
                if is_malware:
                    skip_stats[dataset_name]["malware_skip"] += 1
                else:
                    skip_stats[dataset_name]["benign_skip"] += 1
            else:
                if is_malware:
                    skip_stats[dataset_name]["malware_process"] += 1
                else:
                    skip_stats[dataset_name]["benign_process"] += 1
                packages_to_process.append((package_name, package_path, dataset_name, is_malware))
        
        # Display detailed statistics
        total_skipped = sum(stats["benign_skip"] + stats["malware_skip"] for stats in skip_stats.values())
        total_to_process = len(packages_to_process)
        
        print("\n" + "="*80)
        print("📊 Package processing status statistics")
        print("="*80)
        for dataset_name, stats in dataset_stats.items():
            skip = skip_stats[dataset_name]
            total_benign = stats["benign"]
            total_malware = stats["malware"]
            total_dataset = total_benign + total_malware
            
            print(f"\n📁 {dataset_name.upper()} dataset:")  
            print(f"   Benign: {skip['benign_skip']} skip + {skip['benign_process']} process = {total_benign} total")
            print(f"   Malware: {skip['malware_skip']} skip + {skip['malware_process']} process = {total_malware} total")
            print(f"   Total: {skip['benign_skip'] + skip['malware_skip']} skip + {skip['benign_process'] + skip['malware_process']} process = {total_dataset} total")
        
        print(f"\n🎯 Total statistics:")
        print(f"   Total packages: {total_packages}")
        print(f"   Completed (skipped): {total_skipped} ({total_skipped/total_packages*100:.1f}%)")
        print(f"   To process: {total_to_process} ({total_to_process/total_packages*100:.1f}%)")
        print("="*80)
        
        logger.info(f"Total packages: {total_packages}, skipped {total_skipped}, to process {total_to_process}")
        
        # If there are no packages to process, return
        if total_to_process == 0:
            print("\n✅ All packages are analyzed, no new packages to process.")
            logger.info("All packages are analyzed")
            return
        
        # Randomly shuffle the task list to process
        random.shuffle(packages_to_process)
        
        logger.info(f"Using {Config.PROCESS_COUNT} processes to process {total_to_process} packages")
        
        # Use process pool to process tasks
        with multiprocessing.Pool(processes=Config.PROCESS_COUNT) as pool:
            results = []
            
            for i, package_info in enumerate(packages_to_process):
                package_name, _, dataset_name, is_malware = package_info
                dataset_type = "Malware" if is_malware else "Benign"
                
                logger.info(f"Submit task [{i+1}/{total_to_process}]: {dataset_name}/{package_name} ({dataset_type})")
                
                # Asynchronous submit tasks
                result = pool.apply_async(process_package, (package_info,))
                results.append(result)
            
            # Wait for all tasks to complete and collect results
            completed = 0
            success_count = 0
            for result in results:
                package_name, dataset_name, success = result.get()  # This will block until the task is completed
                status = "Success" if success else "Failed"
                completed += 1
                if success:
                    success_count += 1
                logger.info(f"Progress: [{completed}/{total_to_process}] package {dataset_name}/{package_name} analysis {status}")
        
        # Display completion information
        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        
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