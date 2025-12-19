"""
Run security analysis tools on NPM packages.
Supports guarddog and ossgadget.

Tool Input Requirements:
    - guarddog:  Compressed package (zip_file_path: .tgz, .tar.gz)
    - ossgadget: Extracted directory (unzip_folder_path)
"""
import os
import subprocess
import multiprocessing
from pathlib import Path
import glob
import time


PYGUARD_ROOT = Path(__file__).parent.parent

NUM_PROCESSES = 24
TOOL_TIMEOUT = 300

SUPPORTED_TOOLS = ["guarddog", "ossgadget"]

OSSGADGET_PATH = str(PYGUARD_ROOT / "Baselines" / "OSSGadget" / "oss-detect-backdoor")


def run_with_timeout(cmd, timeout=TOOL_TIMEOUT):
    """Run command with timeout, return (return_code, stdout, stderr, exec_time)."""
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

    def __init__(self, dataset_dir, output_dir):
        self.dataset_dir = dataset_dir
        self.output_dir = output_dir
        self.tools = SUPPORTED_TOOLS
        self.data_types = ["benign", "malware"]
        self._ensure_output_dirs()

    def _ensure_output_dirs(self):
        """Create output directories for all tools."""
        for tool in self.tools:
            for data_type in self.data_types:
                output_path = os.path.join(self.output_dir, tool, data_type)
                os.makedirs(output_path, exist_ok=True)

    def _get_output_path(self, tool, data_type, package_name):
        """Get output file path for a detection result."""
        return os.path.join(self.output_dir, tool, data_type, f"{package_name}.txt")

    def _find_zip_file(self, data_type, package_name):
        """Find archive file for a package."""
        zip_base = os.path.join(self.dataset_dir, f"zip_{data_type}")

        package_dir = os.path.join(zip_base, package_name)
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            for item in os.listdir(package_dir):
                item_path = os.path.join(package_dir, item)
                if os.path.isfile(item_path) and any(item.endswith(ext) for ext in ['.tgz', '.tar.gz', '.zip']):
                    return item_path

        pattern = os.path.join(zip_base, f"**/{package_name}*.*")
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isfile(match) and any(match.endswith(ext) for ext in ['.tgz', '.tar.gz', '.zip']):
                return match

        return None

    def _find_unzip_dir(self, data_type, package_name):
        """Find extracted directory for a package."""
        unzip_base = os.path.join(self.dataset_dir, f"unzip_{data_type}")

        package_dir = os.path.join(unzip_base, package_name)
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            return package_dir

        pattern = os.path.join(unzip_base, f"**/{package_name}")
        matches = glob.glob(pattern, recursive=True)
        for match in matches:
            if os.path.isdir(match):
                return match

        return None

    def run_guarddog(self, zip_file_path, output_file):
        """Run Guarddog malware scanner. Input: compressed package."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = ["guarddog", "npm", "scan", zip_file_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("TIMEOUT")
            print(f"Guarddog timeout: {os.path.basename(zip_file_path)}")
            return "TIMEOUT"

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Guarddog done: {os.path.basename(zip_file_path)} ({exec_time:.1f}s)")
        return output

    def run_ossgadget(self, unzip_folder_path, output_file):
        """Run OSS Gadget backdoor detector. Input: extracted directory."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return None

        cmd = [OSSGADGET_PATH, unzip_folder_path]
        return_code, stdout, stderr, exec_time = run_with_timeout(cmd)

        if return_code == -1:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("TIMEOUT")
            print(f"OSSGadget timeout: {os.path.basename(unzip_folder_path)}")
            return "TIMEOUT"

        output = stdout if stdout.strip() else "benign"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"OSSGadget done: {os.path.basename(unzip_folder_path)} ({exec_time:.1f}s)")
        return output

    def process_package(self, data_type, package_name):
        """Process a single package with all detection tools."""
        try:
            unzip_folder_path = self._find_unzip_dir(data_type, package_name)
            zip_file_path = self._find_zip_file(data_type, package_name)

            if not unzip_folder_path and not zip_file_path:
                print(f"Warning: Cannot find package {package_name}")
                return

            output_files = {
                "guarddog": self._get_output_path("guarddog", data_type, package_name),
                "ossgadget": self._get_output_path("ossgadget", data_type, package_name),
            }

            all_processed = all(
                os.path.exists(f) and os.path.getsize(f) > 0
                for f in output_files.values()
            )
            if all_processed:
                return

            print(f"Processing {data_type}/{package_name}...")

            if zip_file_path:
                self.run_guarddog(zip_file_path, output_files["guarddog"])

            if unzip_folder_path:
                self.run_ossgadget(unzip_folder_path, output_files["ossgadget"])

            print(f"Completed {data_type}/{package_name}")

        except Exception as e:
            print(f"Error processing {data_type}/{package_name}: {e}")

    def collect_packages(self):
        """Collect all package names from the dataset."""
        tasks = []

        for data_type in self.data_types:
            zip_path = os.path.join(self.dataset_dir, f"zip_{data_type}")
            if os.path.exists(zip_path):
                packages = [f for f in os.listdir(zip_path) if os.path.isdir(os.path.join(zip_path, f))]
                for pkg in packages:
                    tasks.append((data_type, pkg))

        return tasks

    def process_all(self, num_processes=NUM_PROCESSES):
        """Process all packages in the dataset."""
        tasks = self.collect_packages()
        print(f"Found {len(tasks)} packages")

        if num_processes > 1:
            with multiprocessing.Pool(processes=num_processes) as pool:
                pool.starmap(self.process_package, tasks)
        else:
            for task in tasks:
                self.process_package(*task)

        print("All packages processed.")


def cleanup_processes():
    """Kill any zombie detection tool processes."""
    cleanup_cmd = """
    pkill -f guarddog || true
    pkill -f oss-detect-backdoor || true
    """
    try:
        subprocess.call(cleanup_cmd, shell=True)
    except:
        pass


if __name__ == "__main__":
    # Dataset directory structure:
    #   /path/to/dataset/
    #   ├── zip_benign/package_name/package_name-1.0.0.tgz
    #   ├── zip_malware/package_name/package_name-1.0.0.tgz
    #   ├── unzip_benign/package_name/...
    #   └── unzip_malware/package_name/...
    #
    # Output directory structure (auto-created):
    #   /path/to/output/
    #   ├── guarddog/{benign,malware}/package_name.txt
    #   └── ossgadget/{benign,malware}/package_name.txt

    print("Cleaning up zombie processes...")
    cleanup_processes()

    DATASET_DIR = str(PYGUARD_ROOT.parent / "Dataset" / "npm_data")
    OUTPUT_DIR = str(PYGUARD_ROOT / "Experiment" / "Results" / "NPM")

    print(f"Dataset: {DATASET_DIR}")
    print(f"Output: {OUTPUT_DIR}")
    print(f"Workers: {NUM_PROCESSES}, Timeout: {TOOL_TIMEOUT}s")

    detector = ToolDetector(DATASET_DIR, OUTPUT_DIR)
    detector.process_all()
