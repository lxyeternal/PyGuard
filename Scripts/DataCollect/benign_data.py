"""
Multithreaded PyPI Package Downloader with automatic file splitting
"""
import os
import json
import random
import shutil
import concurrent.futures
from pkg_download import pypi_pkg_links


def load_packages_from_json(json_file_path):
    with open(json_file_path, 'r') as file:
        data = json.load(file)
    return [item['package_name'] for item in data]


def download_package(package_name, output_dir):
    print(f"Downloading package: {package_name}")
    try:
        package_file = pypi_pkg_links(package_name, output_dir)
        if package_file:
            print(f"Successfully downloaded {package_name} to {package_file}")
            return package_name, True, package_file
        return package_name, False, None
    except Exception as e:
        print(f"Error downloading package {package_name}: {str(e)}")
        return package_name, False, None


def download_packages_parallel(package_names, output_dir, limit=10, max_workers=10):
    os.makedirs(output_dir, exist_ok=True)
    packages_to_process = package_names[:limit]
    successful_downloads = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_package = {
            executor.submit(download_package, pkg_name, output_dir): pkg_name
            for pkg_name in packages_to_process
        }
        for future in concurrent.futures.as_completed(future_to_package):
            package_name, success, file_path = future.result()
            if success:
                successful_downloads.append(package_name)

    print(f"\nDownloaded {len(successful_downloads)} packages successfully")
    return successful_downloads


def split_files(source_dir, eval_dir, study_dir, eval_ratio=0.2):
    """Split files into evaluation and study directories by ratio."""
    os.makedirs(eval_dir, exist_ok=True)
    os.makedirs(study_dir, exist_ok=True)

    files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    if not files:
        print(f"No files found in {source_dir}")
        return 0, 0

    random.shuffle(files)
    split_index = int(len(files) * eval_ratio)
    eval_files = files[:split_index]
    study_files = files[split_index:]

    for file in eval_files:
        shutil.copy2(os.path.join(source_dir, file), os.path.join(eval_dir, file))

    for file in study_files:
        shutil.copy2(os.path.join(source_dir, file), os.path.join(study_dir, file))

    print(f"Split complete: {len(eval_files)} eval, {len(study_files)} study")
    return len(eval_files), len(study_files)


if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RECORDS_DIR = os.path.join(BASE_DIR, "Records")

    json_file_path = os.path.join(RECORDS_DIR, "top_packages.json")
    output_dir = "/path/to/dataset/benign"
    eval_dir = "/path/to/dataset/evaluation/benign"
    study_dir = "/path/to/dataset/study/benign"

    package_names = load_packages_from_json(json_file_path)
    download_packages_parallel(package_names, output_dir, limit=1000, max_workers=24)
    split_files(output_dir, eval_dir, study_dir)
