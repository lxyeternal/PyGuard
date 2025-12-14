
"""
# @File     : pkg_download.py
# @Project  : pythonProject
# Time      : 18/7/24 9:08 pm
# version   : python 3.8
# Description：
"""


import os
import requests
from bs4 import BeautifulSoup


def pypi_pkg_links(pkgname, dataset_dir):
    pypi_org = "https://pypi.org/"
    extension_tar = ".tar.gz"
    extension_zip = ".zip"
    extension_whl = ".whl"
    pkg_versions = []
    pkgurl = os.path.join(pypi_org, "simple", pkgname)
    rq = requests.get(pkgurl)
    if rq.status_code == 200:
        soup = BeautifulSoup(rq.content, 'html.parser')
        for a in soup.find_all('a'):
            link = a.get('href')
            if link.startswith("http:") or link.startswith("https:"):
                download_link = link
            elif link.startswith("../../"):
                download_link = pypi_org + link.replace("../../", "")
            else:
                download_link = pypi_org + link.replace("../../", "")
            link_filename = a.text.lower()
            if link_filename.endswith(extension_whl) or link_filename.endswith(extension_tar) or link_filename.endswith(extension_zip):
                pkg_versions.append((download_link, link_filename))
    random_choice = pkg_versions[-1]
    download_link, link_filename = random_choice
    source_code_filename = os.path.join(dataset_dir, link_filename)
    file_response = requests.get(download_link)
    if file_response.status_code == 200:
        with open(source_code_filename, "ab") as f:
            f.write(file_response.content)
            f.flush()
    return source_code_filename