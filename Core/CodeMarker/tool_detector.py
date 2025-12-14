"""
Run security analysis tools to detect potentially malicious code in packages.
Supports bandit4mal, guarddog, ossgadget, and pypiwarehouse.

Tool Input Requirements:
    - bandit4mal:    Extracted directory (unzip_folder_path)
    - guarddog:      Compressed package (zip_file_path: .tar.gz, .whl, .zip)
    - ossgadget:     Extracted directory (unzip_folder_path)
    - pypiwarehouse: Extracted directory (unzip_folder_path)
"""
import os
import glob
import time
import subprocess
import multiprocessing
from pathlib import Path


PYGUARD_ROOT = Path(__file__).parent.parent.parent

NUM_PROCESSES = 24
TOOL_TIMEOUT = 120

SUPPORTED_TOOLS = ["bandit4mal", "guarddog", "ossgadget", "pypiwarehouse"]

OSSGADGET_PATH = str(PYGUARD_ROOT / "Baselines" / "OSSGadget" / "oss-detect-backdoor")
YARA_RULES_PATH = str(PYGUARD_ROOT / "Baselines" / "PyPIWarehouse" / "setup_py_rules.yara")


def run_with_timeout(cmd, timeout=TOOL_TIMEOUT):
    start_time = time.time()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return (process.returncode, stdout, stderr, time.time() - start_time)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except:
            pass
        return (-1, f"Command timed out after {timeout} seconds", "", timeout)


class ToolDetector:

    def __init__(self, dataset_dirs, output_dir):
        self.datasets = dataset_dirs
        self.output_base = output_dir
        self.tools = SUPPORTED_TOOLS
        self.data_types = ["benign", "malware"]
        self._ensure_output_dirs()


    def _ensure_output_dirs(self):
        for dataset_name in self.datasets:
            for tool in self.tools:
                for data_type in self.data_types:
                    output_dir = os.path.join(self.output_base, dataset_name, tool, data_type)
                    os.makedirs(output_dir, exist_ok=True)


    def _get_output_path(self, dataset_name, tool, data_type, package_name):
        return os.path.join(self.output_base, dataset_name, tool, data_type, f"{package_name}.txt")


    def _find_zip_file(self, dataset_name, data_type, package_name):
        dataset_path = self.datasets[dataset_name]
        zip_base = os.path.join(dataset_path, f"zip_{data_type}")

        package_dir = os.path.join(zip_base, package_name)
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            for item in os.listdir(package_dir):
                item_path = os.path.join(package_dir, item)
                if os.path.isfile(item_path) and any(item.endswith(ext) for ext in ['.zip', '.tar.gz', '.whl', '.tgz']):
                    return item_path

        pattern = os.path.join(zip_base, f"**/{package_name}*.*")
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isfile(match) and any(match.endswith(ext) for ext in ['.zip', '.tar.gz', '.whl', '.tgz']):
                return match

        return None


    def _find_unzip_dir(self, dataset_name, data_type, package_name):
        dataset_path = self.datasets[dataset_name]
        unzip_base = os.path.join(dataset_path, f"unzip_{data_type}")

        package_dir = os.path.join(unzip_base, package_name)
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            return package_dir

        pattern = os.path.join(unzip_base, f"**/{package_name}")
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isdir(match):
                return match

        return None


    def run_bandit(self, unzip_folder_path, output_file):
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = ["bandit", "-r", unzip_folder_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            return None

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        return output


    def run_guarddog(self, zip_file_path, output_file):
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = ["guarddog", "pypi", "scan", zip_file_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            return None

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        return output


    def run_ossgadget(self, unzip_folder_path, output_file):
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = [OSSGADGET_PATH, unzip_folder_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            return None

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        return output


    def run_pypiwarehouse(self, unzip_folder_path, output_file):
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = ["yara", "-r", "-s", YARA_RULES_PATH, unzip_folder_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            return None

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        return output


    def process_package(self, dataset_name, data_type, package_name):
        try:
            unzip_folder_path = self._find_unzip_dir(dataset_name, data_type, package_name)
            zip_file_path = self._find_zip_file(dataset_name, data_type, package_name)

            if not unzip_folder_path:
                print(f"Warning: Cannot find extracted dir for {package_name}")
                return

            output_files = {
                "bandit4mal": self._get_output_path(dataset_name, "bandit4mal", data_type, package_name),
                "guarddog": self._get_output_path(dataset_name, "guarddog", data_type, package_name),
                "ossgadget": self._get_output_path(dataset_name, "ossgadget", data_type, package_name),
                "pypiwarehouse": self._get_output_path(dataset_name, "pypiwarehouse", data_type, package_name),
            }

            all_processed = all(
                os.path.exists(f) and os.path.getsize(f) > 0
                for f in output_files.values()
            )
            if all_processed:
                return

            print(f"Processing {dataset_name}/{data_type}/{package_name}...")

            if unzip_folder_path:
                self.run_bandit(unzip_folder_path, output_files["bandit4mal"])
                self.run_ossgadget(unzip_folder_path, output_files["ossgadget"])
                self.run_pypiwarehouse(unzip_folder_path, output_files["pypiwarehouse"])

            if zip_file_path:
                self.run_guarddog(zip_file_path, output_files["guarddog"])

            print(f"Completed {dataset_name}/{data_type}/{package_name}")

        except Exception as e:
            print(f"Error processing {dataset_name}/{data_type}/{package_name}: {e}")


    def collect_packages(self, dataset_name):
        dataset_path = self.datasets[dataset_name]
        tasks = []

        for data_type in self.data_types:
            type_path = os.path.join(dataset_path, f"unzip_{data_type}")
            if os.path.exists(type_path):
                packages = [f for f in os.listdir(type_path) if os.path.isdir(os.path.join(type_path, f))]
                for pkg in packages:
                    tasks.append((dataset_name, data_type, pkg))

        return tasks


    def process_dataset(self, dataset_name, num_processes=NUM_PROCESSES):
        print(f"Processing dataset: {dataset_name}")
        tasks = self.collect_packages(dataset_name)
        print(f"Found {len(tasks)} packages in {dataset_name}")

        if num_processes > 1:
            with multiprocessing.Pool(processes=num_processes) as pool:
                pool.starmap(self.process_package, tasks)
        else:
            for task in tasks:
                self.process_package(*task)

        print(f"Completed dataset: {dataset_name}")


    def process_all_datasets(self, num_processes=NUM_PROCESSES):
        for dataset_name in self.datasets:
            self.process_dataset(dataset_name, num_processes)
        print("All datasets processed.")


if __name__ == "__main__":
    # Example usage:
    #
    # Dataset directory structure:
    #   /path/to/Dataset/2025/
    #   ├── zip_benign/package_name/package_name-1.0.0.tar.gz
    #   ├── zip_malware/package_name/package_name-1.0.0.whl
    #   ├── unzip_benign/package_name/...
    #   └── unzip_malware/package_name/...
    #
    # Output directory structure (auto-created):
    #   /path/to/Output/tool_detection/
    #   └── 2025/
    #       ├── bandit4mal/{benign,malware}/package_name.txt
    #       ├── guarddog/{benign,malware}/package_name.txt
    #       ├── ossgadget/{benign,malware}/package_name.txt
    #       └── pypiwarehouse/{benign,malware}/package_name.txt

    DATASETS = {
        "2025": "/path/to/Dataset/2025",
        # "other_dataset": "/path/to/Dataset/other",
    }
    OUTPUT_DIR = "/path/to/Output/tool_detection"

    detector = ToolDetector(DATASETS, OUTPUT_DIR)
    detector.process_all_datasets()
