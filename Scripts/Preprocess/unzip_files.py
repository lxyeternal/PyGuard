"""
Extract Python packages from various archive formats (.tar.gz, .zip, .whl).
"""
import os
import glob
import shutil
import tarfile
import zipfile


SUPPORTED_EXTENSIONS = ['.tar.gz', '.tgz', '.zip', '.whl']


def extract_package(file_path, output_dir):
    """Extract a single package archive with fallback methods."""
    os.makedirs(output_dir, exist_ok=True)

    extractors = [
        ('.tar.gz', lambda f, o: tarfile.open(f, "r:gz").extractall(o)),
        ('.tgz', lambda f, o: tarfile.open(f, "r:gz").extractall(o)),
        ('.zip', lambda f, o: zipfile.ZipFile(f, "r").extractall(o)),
        ('.whl', lambda f, o: zipfile.ZipFile(f, "r").extractall(o)),
    ]

    # Try matching extension first
    for ext, extractor in extractors:
        if file_path.endswith(ext):
            try:
                extractor(file_path, output_dir)
                return output_dir
            except Exception as primary_error:
                # Try other methods as fallback
                for other_ext, other_extractor in extractors:
                    if other_ext != ext:
                        try:
                            other_extractor(file_path, output_dir)
                            return output_dir
                        except Exception:
                            continue
                raise primary_error

    raise ValueError(f"Unsupported format: {file_path}")


def get_output_folder_name(filename):
    """Get output folder name by stripping archive extension."""
    for ext in SUPPORTED_EXTENSIONS:
        if filename.endswith(ext):
            return filename[:-len(ext)]
    return filename


def find_archives(directory):
    """Find all supported archive files in a directory."""
    archives = []
    for ext in SUPPORTED_EXTENSIONS:
        archives.extend(glob.glob(os.path.join(directory, f"*{ext}")))
    return archives


def extract_directory(input_dir, output_dir, recursive=False):
    """
    Extract all archives from input directory to output directory.

    Args:
        input_dir: Directory containing archive files
        output_dir: Directory to extract files to
        recursive: If True, search subdirectories for archives

    Returns:
        Tuple of (success_count, error_count, error_list)
    """
    os.makedirs(output_dir, exist_ok=True)
    success_count = 0
    errors = []

    if recursive:
        archives = []
        for root, _, files in os.walk(input_dir):
            for f in files:
                if any(f.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                    archives.append(os.path.join(root, f))
    else:
        archives = find_archives(input_dir)

    total = len(archives)
    for i, archive_path in enumerate(archives):
        filename = os.path.basename(archive_path)
        folder_name = get_output_folder_name(filename)
        extract_dir = os.path.join(output_dir, folder_name)

        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)

        try:
            extract_package(archive_path, extract_dir)
            success_count += 1
            print(f"[{i+1}/{total}] Extracted: {filename}")
        except Exception as e:
            errors.append((archive_path, str(e)))
            print(f"[{i+1}/{total}] Failed: {filename} - {e}")

    return success_count, len(errors), errors


def extract_nested_packages(input_dir, output_dir):
    """
    Extract packages with nested directory structure.
    Handles: input_dir/package_name/archive.tar.gz
    """
    os.makedirs(output_dir, exist_ok=True)
    success_count = 0
    errors = []

    for package_name in os.listdir(input_dir):
        package_path = os.path.join(input_dir, package_name)
        if not os.path.isdir(package_path):
            continue

        archives = find_archives(package_path)
        if not archives:
            continue

        extract_base = os.path.join(output_dir, package_name)
        os.makedirs(extract_base, exist_ok=True)

        for archive_path in archives:
            filename = os.path.basename(archive_path)
            folder_name = get_output_folder_name(filename)
            extract_dir = os.path.join(extract_base, folder_name)

            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)

            try:
                extract_package(archive_path, extract_dir)
                success_count += 1
                print(f"Extracted: {package_name}/{filename}")
            except Exception as e:
                errors.append((archive_path, str(e)))
                print(f"Failed: {package_name}/{filename} - {e}")

    return success_count, len(errors), errors


def write_error_log(errors, log_path):
    """Write extraction errors to log file."""
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write("# Extraction errors\n\n")
        for path, error in errors:
            f.write(f"{path}\t{error}\n")


if __name__ == "__main__":
    # Example usage
    input_dir = "/path/to/archives"
    output_dir = "/path/to/extracted"
