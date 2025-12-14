"""
Collect False Negative packages from NPM detection results.

False Negatives are malware packages that were misclassified as benign.
This script collects them for further analysis.
"""
import os
import json
import shutil
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("NPMFNCollector")

PYGUARD_ROOT = Path(__file__).parent.parent

DATASET_BASE = PYGUARD_ROOT / "Dataset" / "NPM"
RESULTS_BASE = PYGUARD_ROOT / "Experiment" / "Results" / "NPM"
OUTPUT_BASE = PYGUARD_ROOT / "Experiment" / "NPM_FN"


def collect_false_negatives():
    """Collect false negatives from gpt-4.1 and pyguard detection results."""
    logger.info("Collecting false negatives (malware misclassified as benign)...")

    model_dirs = {
        "gpt-4.1": RESULTS_BASE / "gpt-4.1" / "malware",
        "pyguard": RESULTS_BASE / "pyguard" / "malware"
    }

    false_negatives = {
        "gpt-4.1": [],
        "pyguard": []
    }

    for model_name, model_dir in model_dirs.items():
        if not model_dir.exists():
            logger.warning(f"Directory not found: {model_dir}")
            continue

        logger.info(f"Checking {model_name} detection results...")

        for json_file in os.listdir(model_dir):
            if not json_file.endswith(".json"):
                continue

            json_path = model_dir / json_file
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    result = json.load(f)

                package_name = result.get("package_name", "")
                is_malicious = result.get("is_malicious", True)

                # False negative: malware (in malware folder) but detected as benign
                if not is_malicious:
                    false_negatives[model_name].append(package_name)
                    logger.info(f"{model_name} false negative: {package_name}")

            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")

    logger.info(f"gpt-4.1 false negatives: {len(false_negatives['gpt-4.1'])}")
    logger.info(f"pyguard false negatives: {len(false_negatives['pyguard'])}")

    common_fn = set(false_negatives["gpt-4.1"]) & set(false_negatives["pyguard"])
    logger.info(f"Common false negatives: {len(common_fn)}")

    return false_negatives, common_fn


def copy_false_negative_packages(false_negatives, common_fn):
    """Copy false negative packages to output directory for analysis."""
    malware_path = DATASET_BASE / "unzip_malware"

    # Create output directories
    dirs = {
        "gpt41_only": OUTPUT_BASE / "gpt41_only",
        "pyguard_only": OUTPUT_BASE / "pyguard_only",
        "common": OUTPUT_BASE / "common"
    }

    for d in dirs.values():
        os.makedirs(d, exist_ok=True)

    # gpt-4.1 only false negatives
    gpt41_only = set(false_negatives["gpt-4.1"]) - common_fn
    for package_name in gpt41_only:
        src_path = malware_path / package_name
        dst_path = dirs["gpt41_only"] / package_name

        if src_path.exists() and not dst_path.exists():
            try:
                shutil.copytree(src_path, dst_path)
                logger.info(f"Copied {package_name} to gpt41_only")
            except Exception as e:
                logger.error(f"Error copying {package_name}: {e}")

    # pyguard only false negatives
    pyguard_only = set(false_negatives["pyguard"]) - common_fn
    for package_name in pyguard_only:
        src_path = malware_path / package_name
        dst_path = dirs["pyguard_only"] / package_name

        if src_path.exists() and not dst_path.exists():
            try:
                shutil.copytree(src_path, dst_path)
                logger.info(f"Copied {package_name} to pyguard_only")
            except Exception as e:
                logger.error(f"Error copying {package_name}: {e}")

    # Common false negatives
    for package_name in common_fn:
        src_path = malware_path / package_name
        dst_path = dirs["common"] / package_name

        if src_path.exists() and not dst_path.exists():
            try:
                shutil.copytree(src_path, dst_path)
                logger.info(f"Copied {package_name} to common")
            except Exception as e:
                logger.error(f"Error copying {package_name}: {e}")

    # Summary
    gpt41_count = len(list(dirs["gpt41_only"].iterdir())) if dirs["gpt41_only"].exists() else 0
    pyguard_count = len(list(dirs["pyguard_only"].iterdir())) if dirs["pyguard_only"].exists() else 0
    common_count = len(list(dirs["common"].iterdir())) if dirs["common"].exists() else 0

    logger.info(f"Copied to gpt41_only: {gpt41_count}")
    logger.info(f"Copied to pyguard_only: {pyguard_count}")
    logger.info(f"Copied to common: {common_count}")
    logger.info(f"Total: {gpt41_count + pyguard_count + common_count}")


def main():
    """Main function."""
    logger.info("Starting false negative collection...")
    logger.info(f"Dataset: {DATASET_BASE}")
    logger.info(f"Results: {RESULTS_BASE}")
    logger.info(f"Output: {OUTPUT_BASE}")

    false_negatives, common_fn = collect_false_negatives()
    copy_false_negative_packages(false_negatives, common_fn)

    logger.info("Collection completed!")


if __name__ == "__main__":
    main()
