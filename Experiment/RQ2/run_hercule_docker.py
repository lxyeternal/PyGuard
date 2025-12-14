#!/usr/bin/env python3
"""
Hercule Docker Runner - Disposable Container Strategy

Each package runs in a fresh container that is destroyed after analysis.
N workers process tasks in parallel, each creating/destroying containers as needed.
"""
import argparse
import concurrent.futures
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple


PYGUARD_ROOT = Path(__file__).parent.parent

DEFAULT_NUM_WORKERS = 10
DEFAULT_IMAGE = "rshariffdeen/hercule"
DEFAULT_TIMEOUT_SEC = 3600
DEFAULT_CONTAINER_MEMORY = "16g"

BASE_DATASET_DIR = str(PYGUARD_ROOT.parent / "Dataset")
BASE_OUTPUT_DIR = str(PYGUARD_ROOT / "Experiment" / "Results" / "PyPI")

SUPPORTED_DATASETS = ["Latest", "Obfuscation", "Evaluation"]

HOST_EMITTER_FIX = str(PYGUARD_ROOT / "Baselines" / "Hercule" / "app" / "core" / "emitter.py")
CONTAINER_EMITTER_PATH = "/opt/hercule/app/core/emitter.py"

CONTAINER_BENIGN_DIR = "/data/benign"
CONTAINER_MALWARE_DIR = "/data/malware"


def get_dataset_paths(dataset_name: str) -> dict:
    if dataset_name not in SUPPORTED_DATASETS:
        raise ValueError(f"Unsupported dataset: {dataset_name}. Supported: {SUPPORTED_DATASETS}")
    dataset_lower = dataset_name.lower()
    return {
        "benign_dir": f"{BASE_DATASET_DIR}/{dataset_lower}/zip_benign",
        "malware_dir": f"{BASE_DATASET_DIR}/{dataset_lower}/zip_malware",
        "output_benign": f"{BASE_OUTPUT_DIR}/{dataset_name}/hercule/benign",
        "output_malware": f"{BASE_OUTPUT_DIR}/{dataset_name}/hercule/malware",
    }


def run_command(cmd: List[str], timeout: Optional[int] = None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_image_exists(image: str) -> bool:
    result = run_command(["docker", "image", "inspect", image])
    return result.returncode == 0


def docker_pull_image(image: str):
    print(f"Pulling image: {image}")
    result = run_command(["docker", "pull", image])
    if result.returncode != 0:
        raise RuntimeError(f"Failed to pull image {image}: {result.stderr}")


def ensure_image_exists(image: str):
    if not docker_image_exists(image):
        docker_pull_image(image)


def generate_container_name(worker_id: int, task_idx: int) -> str:
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"hercule_w{worker_id}_t{task_idx}_{random_suffix}"


def create_disposable_container(name: str, image: str, benign_dir: str, malware_dir: str, memory_limit: str) -> bool:
    cmd = [
        "docker", "run", "-d",
        "--name", name,
        "--memory", memory_limit,
        "--memory-swap", memory_limit,
        "--rm",
    ]
    if os.path.exists(benign_dir):
        cmd.extend(["-v", f"{benign_dir}:{CONTAINER_BENIGN_DIR}:ro"])
    if os.path.exists(malware_dir):
        cmd.extend(["-v", f"{malware_dir}:{CONTAINER_MALWARE_DIR}:ro"])
    cmd.extend([image, "tail", "-f", "/dev/null"])

    result = run_command(cmd)
    if result.returncode != 0:
        print(f"[ERROR] Failed to create container {name}: {result.stderr}")
        return False

    time.sleep(1)
    if os.path.exists(HOST_EMITTER_FIX):
        copy_cmd = ["docker", "cp", HOST_EMITTER_FIX, f"{name}:{CONTAINER_EMITTER_PATH}"]
        run_command(copy_cmd)
    return True


def force_remove_container(name: str):
    try:
        run_command(["docker", "rm", "-f", name], timeout=60)
    except (subprocess.TimeoutExpired, Exception):
        pass


def list_all_archives(root_dir: str) -> List[str]:
    archives = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith(".tar.gz") or fname.endswith(".zip") or fname.endswith(".whl"):
                archives.append(os.path.join(dirpath, fname))
    return sorted(archives)


def derive_package_name(archive_path: str) -> str:
    fname = Path(archive_path).name
    if fname.endswith(".tar.gz"):
        return fname[:-7]
    if fname.endswith(".zip"):
        return fname[:-4]
    if fname.endswith(".whl"):
        return fname[:-4]
    return fname


def build_task_list(benign_root: str, malware_root: str, out_benign: str, out_malware: str) -> List[Tuple[str, str, str]]:
    tasks = []
    for archive in list_all_archives(malware_root):
        pkg_name = derive_package_name(archive)
        out_path = os.path.join(out_malware, f"{pkg_name}.txt")
        tasks.append(("malware", archive, out_path))
    for archive in list_all_archives(benign_root):
        pkg_name = derive_package_name(archive)
        out_path = os.path.join(out_benign, f"{pkg_name}.txt")
        tasks.append(("benign", archive, out_path))
    return tasks


def host_to_container_path(kind: str, host_path: str, host_benign_dir: str, host_malware_dir: str) -> str:
    if kind == "benign":
        rel_path = os.path.relpath(host_path, host_benign_dir)
        return os.path.join(CONTAINER_BENIGN_DIR, rel_path)
    else:
        rel_path = os.path.relpath(host_path, host_malware_dir)
        return os.path.join(CONTAINER_MALWARE_DIR, rel_path)


def run_hercule_in_container(container_name: str, container_file_path: str, timeout_sec: int) -> Tuple[int, str, str]:
    cmd = [
        "docker", "exec",
        container_name,
        "bash", "-c",
        f"timeout -s KILL {timeout_sec}s hercule -F {container_file_path}"
    ]
    try:
        result = run_command(cmd, timeout=timeout_sec + 10)
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "Docker exec timeout"


def save_result(output_path: str, content: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, output_path)


def process_one_task(worker_id: int, task_idx: int, task: Tuple[str, str, str],
                     image: str, timeout_sec: int, memory_limit: str,
                     host_benign_dir: str, host_malware_dir: str) -> Tuple[bool, Optional[str]]:
    kind, host_tarball, output_path = task
    if os.path.exists(output_path):
        return True, None

    container_name = generate_container_name(worker_id, task_idx)
    pkg_name = Path(host_tarball).name
    container_path = host_to_container_path(kind, host_tarball, host_benign_dir, host_malware_dir)

    print(f"[Worker-{worker_id}] Processing: {pkg_name} ({kind})")

    try:
        if not create_disposable_container(container_name, image, host_benign_dir, host_malware_dir, memory_limit):
            error_msg = "Failed to create container"
            content = f"#####Analysis time: N/A (container creation failed)####\n# ERROR: {error_msg}\n"
            save_result(output_path, content)
            return False, error_msg

        start_time = time.time()
        start_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))
        exit_code, stdout, stderr = run_hercule_in_container(container_name, container_path, timeout_sec)
        end_time = time.time()
        duration = end_time - start_time
        end_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        if exit_code == 124 or exit_code == -1:
            error_msg = f"Timeout after {timeout_sec}s"
            content = f"#####Analysis time: {duration:.3f}s#### start={start_iso} end={end_iso}\n"
            content += f"# ERROR: {error_msg}\n# --- STDOUT ---\n{stdout}\n# --- STDERR ---\n{stderr}\n"
            save_result(output_path, content)
            print(f"[Worker-{worker_id}] TIMEOUT: {pkg_name} ({duration:.1f}s)")
            return False, error_msg

        content = f"#####Analysis time: {duration:.3f}s#### start={start_iso} end={end_iso}\n"
        content += f"# hercule exit_code: {exit_code}\n# --- STDOUT ---\n{stdout}\n# --- STDERR ---\n{stderr}\n"
        save_result(output_path, content)
        print(f"[Worker-{worker_id}] Done: {pkg_name} ({duration:.1f}s) -> {output_path}")
        return True, None

    except Exception as e:
        error_msg = f"Error: {str(e)}"
        content = f"#####Analysis time: N/A####\n# ERROR: {error_msg}\n"
        save_result(output_path, content)
        print(f"[Worker-{worker_id}] ERROR: {pkg_name} - {error_msg}")
        return False, error_msg

    finally:
        force_remove_container(container_name)


def worker_thread(worker_id: int, task_queue: List[Tuple[str, str, str]],
                  image: str, timeout_sec: int, memory_limit: str,
                  host_benign_dir: str, host_malware_dir: str) -> dict:
    stats = {"processed": 0, "skipped": 0, "errors": 0}
    for task_idx, task in enumerate(task_queue):
        _, _, output_path = task
        if os.path.exists(output_path):
            stats["skipped"] += 1
            continue
        success, _ = process_one_task(worker_id, task_idx, task, image, timeout_sec, memory_limit,
                                      host_benign_dir, host_malware_dir)
        if success:
            stats["processed"] += 1
        else:
            stats["errors"] += 1
    return stats


def main():
    parser = argparse.ArgumentParser(description="Hercule Docker Runner")
    parser.add_argument("--dataset", "-d", type=str, default="Evaluation",
                        choices=SUPPORTED_DATASETS + ["all"],
                        help=f"Dataset to analyze. Default: Evaluation")
    parser.add_argument("--workers", "-w", type=int, default=DEFAULT_NUM_WORKERS,
                        help=f"Number of parallel workers. Default: {DEFAULT_NUM_WORKERS}")
    parser.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT_SEC,
                        help=f"Timeout in seconds per package. Default: {DEFAULT_TIMEOUT_SEC}")
    parser.add_argument("--memory", "-m", type=str, default=DEFAULT_CONTAINER_MEMORY,
                        help=f"Memory limit per container. Default: {DEFAULT_CONTAINER_MEMORY}")
    args = parser.parse_args()

    datasets_to_process = SUPPORTED_DATASETS if args.dataset == "all" else [args.dataset]
    num_workers = args.workers
    timeout_sec = args.timeout
    memory_limit = args.memory
    image = DEFAULT_IMAGE

    print(f"Ensuring Docker image exists: {image}")
    try:
        ensure_image_exists(image)
    except Exception as e:
        print(f"[ERROR] Failed to ensure image: {e}")
        return 1

    total_summary = {"processed": 0, "skipped": 0, "errors": 0}

    for dataset_name in datasets_to_process:
        print("\n" + "=" * 60)
        print(f"Processing dataset: {dataset_name}")
        print("=" * 60)

        paths = get_dataset_paths(dataset_name)
        host_benign_dir = paths["benign_dir"]
        host_malware_dir = paths["malware_dir"]
        host_output_benign = paths["output_benign"]
        host_output_malware = paths["output_malware"]

        if not os.path.exists(host_benign_dir) and not os.path.exists(host_malware_dir):
            print(f"[WARNING] Dataset {dataset_name} directories not found, skipping...")
            continue

        os.makedirs(host_output_benign, exist_ok=True)
        os.makedirs(host_output_malware, exist_ok=True)

        all_tasks = build_task_list(host_benign_dir, host_malware_dir, host_output_benign, host_output_malware)
        pending_tasks = [t for t in all_tasks if not os.path.exists(t[2])]
        already_done = len(all_tasks) - len(pending_tasks)

        print(f"Total tasks: {len(all_tasks)}, Already done: {already_done}, Pending: {len(pending_tasks)}")
        print(f"Workers: {num_workers}, Timeout: {timeout_sec}s, Memory: {memory_limit}")

        if not pending_tasks:
            print("No pending tasks!")
            total_summary["skipped"] += already_done
            continue

        tasks_per_worker = [[] for _ in range(num_workers)]
        for idx, task in enumerate(pending_tasks):
            tasks_per_worker[idx % num_workers].append(task)

        print(f"Starting {num_workers} workers...\n")

        with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for worker_id in range(num_workers):
                if tasks_per_worker[worker_id]:
                    future = executor.submit(
                        worker_thread, worker_id, tasks_per_worker[worker_id],
                        image, timeout_sec, memory_limit, host_benign_dir, host_malware_dir
                    )
                    futures.append(future)

            dataset_stats = {"processed": 0, "skipped": already_done, "errors": 0}
            for future in concurrent.futures.as_completed(futures):
                try:
                    stats = future.result()
                    dataset_stats["processed"] += stats["processed"]
                    dataset_stats["skipped"] += stats["skipped"]
                    dataset_stats["errors"] += stats["errors"]
                except Exception as e:
                    print(f"[ERROR] Worker failed: {e}")
                    dataset_stats["errors"] += 1

        print(f"\nDataset {dataset_name}: Processed={dataset_stats['processed']}, "
              f"Skipped={dataset_stats['skipped']}, Errors={dataset_stats['errors']}")

        total_summary["processed"] += dataset_stats["processed"]
        total_summary["skipped"] += dataset_stats["skipped"]
        total_summary["errors"] += dataset_stats["errors"]

    print("\n" + "=" * 60)
    print(f"Overall: Processed={total_summary['processed']}, "
          f"Skipped={total_summary['skipped']}, Errors={total_summary['errors']}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
