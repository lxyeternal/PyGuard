import os
import tarfile
import zipfile


def mkdir(unzip_filepath) -> None:
    if not os.path.exists(unzip_filepath):
        os.makedirs(unzip_filepath)


def untar_file(raw_filepath, unzip_filepath):
    '''Extract tar.gz package'''
    with tarfile.open(raw_filepath) as tf:
        tf.extractall(unzip_filepath)
    return unzip_filepath


def unzip_file(raw_filepath, unzip_filepath):
    '''Extract zip package'''
    with zipfile.ZipFile(raw_filepath, "r") as zFile:
        for fileM in zFile.namelist():
            zFile.extract(fileM, unzip_filepath)
    return unzip_filepath


def unzip_whl_file(raw_filepath, unzip_filepath):
    '''Extract whl package'''
    with zipfile.ZipFile(raw_filepath, "r") as zFile:
        for fileM in zFile.namelist():
            zFile.extract(fileM, unzip_filepath)
    return unzip_filepath


def depresspkg(filepath, unzip_filepath):
    tar_suffix = ".tar.gz"
    zip_suffix = ".zip"
    whl_suffix = ".whl"
    tgz_suffix = ".tgz"

    mkdir(unzip_filepath)

    output_path = filepath
    if filepath.endswith(tar_suffix):
        output_path = untar_file(filepath, unzip_filepath)
    elif filepath.endswith(tgz_suffix):
        output_path = untar_file(filepath, unzip_filepath)
    elif filepath.endswith(zip_suffix) or filepath.endswith(whl_suffix):
        output_path = unzip_file(filepath, unzip_filepath)
    return output_path


def depress_all_files(input_dir, output_dir):
    """
    Traverse all name/version/zipfile structures under input_dir,
    and save the extracted files to the corresponding directory under output_dir.
    """
    for name in os.listdir(input_dir):
        name_path = os.path.join(input_dir, name)
        if os.path.isdir(name_path):
            for version in os.listdir(name_path):
                version_path = os.path.join(name_path, version)
                if os.path.isdir(version_path):
                    for file in os.listdir(version_path):
                        raw_filepath = os.path.join(version_path, file)
                        unzip_filepath = os.path.join(output_dir, name, version)
                        try:
                            depresspkg(raw_filepath, unzip_filepath)
                            print(f"Extracting {raw_filepath} to {unzip_filepath}")
                        except Exception as e:
                            print(f"Extracting {raw_filepath} failed: {e}")
