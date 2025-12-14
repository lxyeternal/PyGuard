"""
Obfuscate Python packages for research purposes.
Supports both benign and malware packages from local directories.
"""
import os
import io
import ast
import stat
import gzip
import astor
import random
import string
import struct
import shutil
import tarfile
import zipfile
import hashlib
import threading
import subprocess
import concurrent.futures
from datetime import datetime


def generate_random_name(length=16):
    letters = string.ascii_lowercase
    alphanumeric = string.ascii_lowercase + string.digits
    first_char = random.choice(letters)
    remaining_chars = ''.join(random.choices(alphanumeric, k=length - 1))
    return first_char + remaining_chars


def obfuscate_code(package_dir, timeout=30):
    """Run intensio_obfuscator with timeout."""
    output_dir = os.path.join(package_dir, 'obfuscated')
    command = [
        'intensio_obfuscator',
        '-i', package_dir,
        '-o', output_dir,
        '-ind', '4',
        '-mlen', 'lower',
        '-rts',
    ]

    def worker():
        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for root, _, files in os.walk(output_dir):
                for file in files:
                    src = os.path.join(root, file)
                    dst = os.path.join(package_dir, os.path.relpath(src, output_dir))
                    os.rename(src, dst)
            return True
        except Exception:
            return False
        finally:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            print(f"Obfuscation timed out: {package_dir}")
            return False


def extract_package(file_path, extract_path):
    os.makedirs(extract_path, exist_ok=True)
    if file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
        with tarfile.open(file_path, "r:gz") as tf:
            tf.extractall(extract_path)
    elif file_path.endswith('.zip') or file_path.endswith('.whl'):
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_path)
    else:
        raise ValueError(f"Unsupported format: {file_path}")
    return extract_path


def extract_package_name(filename):
    """Extract package name from filename."""
    name = filename
    for suffix in ['.tar.gz', '.tgz', '.zip', '.whl', '-py3-none-any', '-py2-none-any']:
        name = name.replace(suffix, '')
    parts = name.split('-')
    if len(parts) > 1:
        return '-'.join(parts[:-1])
    return name


def get_main_package_dir(extract_dir):
    """Find the main package directory after extraction."""
    contents = os.listdir(extract_dir)
    contents = [c for c in contents if c != '__MACOSX']

    if len(contents) == 1 and os.path.isdir(os.path.join(extract_dir, contents[0])):
        return os.path.join(extract_dir, contents[0])

    # Multiple files/dirs at root - create a container
    main_dir = os.path.join(extract_dir, '_package')
    os.makedirs(main_dir, exist_ok=True)
    for item in contents:
        src = os.path.join(extract_dir, item)
        if os.path.exists(src):
            shutil.move(src, main_dir)
    return main_dir


def rename_folders(directory, old_name, new_name):
    old_underscore = old_name.replace('-', '_')
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        if not os.path.isdir(item_path):
            continue
        new_item = item.replace(old_name, new_name).replace(old_underscore, new_name)
        if new_item != item:
            os.rename(item_path, os.path.join(directory, new_item))


def replace_in_file(file_path, old_name, new_name):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        old_underscore = old_name.replace('-', '_')
        content = content.replace(old_name, new_name).replace(old_underscore, new_name)
        with open(file_path, 'w') as f:
            f.write(content)
    except Exception:
        pass


def modify_setup_py(setup_path, new_name, old_name):
    """Modify setup.py to use new package name and remove identifying info."""
    try:
        with open(setup_path, 'r') as f:
            content = f.read()
        tree = ast.parse(content)

        fields_to_remove = ['description', 'long_description', 'author', 'author_email', 'url', 'packages']
        old_underscore = old_name.replace('-', '_')

        class SetupTransformer(ast.NodeTransformer):
            def visit_Str(self, node):
                if node.s in (old_name, old_underscore):
                    return ast.Str(s=new_name)
                return node

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) and node.func.id == 'setup':
                    node.keywords = [
                        kw for kw in node.keywords
                        if kw.arg not in fields_to_remove
                    ]
                    for kw in node.keywords:
                        if kw.arg == 'name':
                            kw.value = ast.Str(s=new_name)
                        elif kw.arg == 'version':
                            kw.value = ast.Str(s="1.0.0")
                return node

        tree = SetupTransformer().visit(tree)
        with open(setup_path, 'w') as f:
            f.write(astor.to_source(tree))
        return True
    except Exception as e:
        print(f"Error modifying setup.py: {e}")
        return False


def add_marker_file(package_dir):
    """Add a marker file for research tracking."""
    marker_path = os.path.join(package_dir, 'DataCon.txt')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    content = f"Create_Time: {timestamp}\nDescription: Package processed for research purposes."
    with open(marker_path, 'w') as f:
        f.write(content)


def set_fixed_timestamps(package_dir):
    fixed_time = datetime(1970, 1, 1).timestamp()
    for root, _, files in os.walk(package_dir):
        for file in files:
            try:
                os.utime(os.path.join(root, file), (fixed_time, fixed_time))
            except Exception:
                pass


def set_permissions(path):
    for root, dirs, files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), stat.S_IRWXU)
            except Exception:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), stat.S_IRWXU)
            except Exception:
                pass


def standardize_gzip_header(data):
    """Standardize gzip header for reproducible output."""
    header = data[:10]
    body = data[10:]
    fixed_mtime = struct.pack('<L', 0)
    new_header = header[:4] + fixed_mtime + header[8:9] + b'\xff'
    return new_header + body


def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha1.update(chunk)
    return sha1.hexdigest()


def repackage(package_dir, output_dir):
    """Repackage directory as .tgz with SHA1 filename."""
    set_permissions(package_dir)
    set_fixed_timestamps(package_dir)

    temp_tar = io.BytesIO()
    with tarfile.open(fileobj=temp_tar, mode="w") as tar:
        for root, _, files in os.walk(package_dir):
            for file in sorted(files):
                fullpath = os.path.join(root, file)
                tar.add(fullpath, arcname=os.path.relpath(fullpath, package_dir))
    temp_tar.seek(0)

    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', compresslevel=9) as gz:
        gz.write(temp_tar.getvalue())

    standardized = standardize_gzip_header(compressed.getvalue())
    temp_file = os.path.join(output_dir, 'temp.tgz')
    with open(temp_file, 'wb') as f:
        f.write(standardized)

    sha1 = calculate_sha1(temp_file)
    final_path = os.path.join(output_dir, f"{sha1}.tgz")
    os.rename(temp_file, final_path)
    return f"{sha1}.tgz"


def process_single_package(package_path, output_dir, extract_dir):
    """Process a single package: extract, obfuscate, repackage."""
    package_name = os.path.basename(package_path)
    new_name = generate_random_name()
    os.makedirs(output_dir, exist_ok=True)

    try:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir)

        extract_package(package_path, extract_dir)
        main_dir = get_main_package_dir(extract_dir)
        old_name = extract_package_name(package_name)

        # Modify setup.py
        setup_path = os.path.join(main_dir, 'setup.py')
        if os.path.exists(setup_path):
            modify_setup_py(setup_path, new_name, old_name)

        # Rename folders
        rename_folders(main_dir, old_name, new_name)

        # Replace package name in metadata files
        metadata_files = ['pyproject.toml', 'pkg-info', 'setup.cfg', 'manifest.in', 'metadata', 'readme.md', 'readme.rst']
        for root, _, files in os.walk(main_dir):
            for file in files:
                if file.lower() in metadata_files:
                    replace_in_file(os.path.join(root, file), old_name, new_name)

        # Process egg-info/dist-info
        for item in os.listdir(main_dir):
            if item.endswith('.egg-info') or item.endswith('.dist-info'):
                info_dir = os.path.join(main_dir, item)
                for root, _, files in os.walk(info_dir):
                    for file in files:
                        replace_in_file(os.path.join(root, file), old_name, new_name)

        add_marker_file(main_dir)
        obfuscated = obfuscate_code(main_dir)
        output_file = repackage(main_dir, output_dir)

        return obfuscated, output_file

    except Exception as e:
        print(f"Error processing {package_name}: {e}")
        return False, None

    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)


def load_processed_packages(record_file):
    processed = set()
    if os.path.exists(record_file):
        with open(record_file, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    processed.add(parts[1])
    return processed


def save_record(record_file, success, package_name, sha1):
    with open(record_file, 'a') as f:
        f.write(f"{success}\t{package_name}\t{sha1}\n")


def process_directory(input_dir, output_dir, record_file, max_count=None):
    """Process all packages in a directory."""
    os.makedirs(output_dir, exist_ok=True)

    processed = load_processed_packages(record_file)
    all_packages = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    to_process = [p for p in all_packages if p not in processed]

    if max_count:
        to_process = to_process[:max_count]

    print(f"Processing {len(to_process)} packages...")

    for i, pkg in enumerate(to_process):
        package_path = os.path.join(input_dir, pkg)
        extract_dir = f'/tmp/obfuscate_extract_{os.getpid()}'

        success, output_file = process_single_package(package_path, output_dir, extract_dir)

        if output_file:
            sha1 = output_file.replace('.tgz', '')
            save_record(record_file, success, pkg, sha1)
            print(f"[{i+1}/{len(to_process)}] {pkg} -> {sha1}")
        else:
            print(f"[{i+1}/{len(to_process)}] {pkg} -> FAILED")

    print(f"Completed processing.")


if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RECORDS_DIR = os.path.join(BASE_DIR, "Records")
    os.makedirs(RECORDS_DIR, exist_ok=True)

    # Example: Process malware packages
    malware_input = "/path/to/malware/packages"
    malware_output = "/path/to/output/malware"
    malware_record = os.path.join(RECORDS_DIR, "obfuscated_malware.txt")

    # Example: Process benign packages
    benign_input = "/path/to/benign/packages"
    benign_output = "/path/to/output/benign"
    benign_record = os.path.join(RECORDS_DIR, "obfuscated_benign.txt")

    # Uncomment to run:
    # process_directory(malware_input, malware_output, malware_record, max_count=500)
    # process_directory(benign_input, benign_output, benign_record, max_count=500)
