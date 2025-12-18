#!/usr/bin/env python3
"""
NPM package downloader.
Usage: python download_npm_packages.py <packages.txt>
"""

import sys
import re
import requests
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


def parse_package_filename(filename: str) -> tuple:
    """Parse NPM package filename, return (pkg_name, version, base_name)."""
    filename = filename.strip()
    if not filename.endswith('.tgz'):
        return None, None, None

    base = filename[:-4]

    # Handle scoped packages: @scope##pkg-name-version -> @scope/pkg-name
    if base.startswith('@') and '##' in base:
        base = base.replace('##', '/')

    # Find version: last occurrence of -X.X.X pattern
    match = re.match(r'^(.+)-(\d+\.\d+.*)$', base)
    if match:
        pkg_name = match.group(1)
        version = match.group(2)
        return pkg_name, version, filename[:-4]

    return None, None, None


def get_download_url(pkg_name: str, version: str) -> str:
    """Build NPM registry download URL."""
    # For scoped packages: @scope/pkg -> @scope%2fpkg in URL path
    if pkg_name.startswith('@'):
        parts = pkg_name.split('/')
        scope = parts[0]
        name = parts[1] if len(parts) > 1 else ''
        return f"https://registry.npmjs.org/{scope}/{name}/-/{name}-{version}.tgz"
    else:
        return f"https://registry.npmjs.org/{pkg_name}/-/{pkg_name}-{version}.tgz"


def download_file(url: str, save_path: Path) -> bool:
    """Download file to specified path."""
    try:
        resp = requests.get(url, stream=True, timeout=120)
        resp.raise_for_status()
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception:
        return False


def download_package(filename: str, save_dir: Path) -> tuple:
    """Download single package, return (filename, success, message)."""
    filename = filename.strip()
    if not filename:
        return filename, False, "empty filename"

    pkg_name, version, base_name = parse_package_filename(filename)
    if not pkg_name:
        return filename, False, "parse failed"

    # Use original filename (with ##) for directory structure
    save_path = save_dir / filename[:-4] / filename
    if save_path.exists():
        return filename, True, "skipped"

    download_url = get_download_url(pkg_name, version)

    if download_file(download_url, save_path):
        return filename, True, "success"
    return filename, False, f"download failed ({pkg_name}@{version})"


def main():
    parser = argparse.ArgumentParser(description='Download NPM packages')
    parser.add_argument('packages_txt', type=str, help='packages.txt file path')
    parser.add_argument('--workers', type=int, default=4, help='concurrent downloads (default: 4)')
    parser.add_argument('--output', type=str, default=None, help='output directory')
    args = parser.parse_args()

    packages_txt = Path(args.packages_txt)
    if not packages_txt.exists():
        print(f"Error: file not found {packages_txt}")
        sys.exit(1)

    save_dir = Path(args.output) if args.output else packages_txt.parent
    save_dir.mkdir(parents=True, exist_ok=True)

    with open(packages_txt, 'r') as f:
        packages = [line.strip() for line in f if line.strip()]

    print(f"Total: {len(packages)} packages")
    print(f"Save to: {save_dir}")

    success_count = 0
    fail_count = 0
    skip_count = 0
    failed_packages = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(download_package, pkg, save_dir): pkg for pkg in packages}

        with tqdm(total=len(packages), desc="Downloading") as pbar:
            for future in as_completed(futures):
                filename, success, message = future.result()
                if success:
                    if message == "skipped":
                        skip_count += 1
                    else:
                        success_count += 1
                else:
                    fail_count += 1
                    failed_packages.append((filename, message))
                pbar.update(1)
                pbar.set_postfix({'ok': success_count, 'skip': skip_count, 'fail': fail_count})

    print(f"Done: success={success_count}, skipped={skip_count}, failed={fail_count}")

    if failed_packages:
        failed_log = save_dir / "download_failed.txt"
        with open(failed_log, 'w') as f:
            for pkg, msg in failed_packages:
                f.write(f"{pkg}\t{msg}\n")
        print(f"Failed list saved to: {failed_log}")


if __name__ == '__main__':
    main()
