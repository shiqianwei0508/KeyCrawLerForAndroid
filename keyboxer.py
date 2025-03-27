import sys

import requests
import hashlib
import os

from lxml import etree
from pathlib import Path
from dotenv import load_dotenv

from check import keybox_check as CheckValid

# Load environment variables from .env file
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
# 检查 GITHUB_TOKEN 是否为空
if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN is not set. Please define it in your .env file.")
    sys.exit(1)  # 使用非零退出码退出程序
# print(f'GITHUB_TOKEN: {GITHUB_TOKEN}')

# Load proxy settings
HTTP_PROXY = os.getenv("HTTP_PROXY")
HTTPS_PROXY = os.getenv("HTTPS_PROXY")
# 检查两个变量是否同时不为空
if HTTP_PROXY and HTTPS_PROXY:
    print(f'HTTP_PROXY: {HTTP_PROXY}')
    print(f'HTTPS_PROXY: {HTTPS_PROXY}')

session = requests.Session()
session.proxies = {
    "http": HTTP_PROXY,
    "https": HTTPS_PROXY,
}

# Search query
search_query = "<AndroidAttestation>"
search_url = f"https://api.github.com/search/code?q={search_query}"

# Headers for the API request
headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

savedKeys = Path(__file__).resolve().parent / "keys"
savedKeys.mkdir(parents=True, exist_ok=True)

cache_file = Path(__file__).resolve().parent / "cache.txt"
if not cache_file.exists():
    cache_file.touch()  # Create an empty file
cached_urls = set(cache_file.read_text().splitlines())

def process_and_save_xml(raw_url, file_content, saved_keys_dir):
    try:
        root = etree.fromstring(file_content)
        canonical_xml = etree.tostring(root, method="c14n")
        hash_value = hashlib.sha256(canonical_xml).hexdigest()
        file_name_save = saved_keys_dir / f"{hash_value}.xml"
        if not file_name_save.exists() and file_content and CheckValid(file_content):
            print(f"{raw_url} is new")
            with open(file_name_save, "wb") as f:
                f.write(file_content)
    except etree.XMLSyntaxError:
        pass

# Function to fetch and print search results
def fetch_and_process_results(page):
    params = {"per_page": 100, "page": page}

    try:
        response = session.get(search_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")

    if response.status_code != 200:
        raise RuntimeError(f"Failed to retrieve search results: {response.status_code}")
    search_results = response.json()
    if "items" in search_results:
        for item in search_results["items"]:
            file_name = item["name"]
            # Process only XML files
            if file_name.lower().endswith(".xml"):
                raw_url: str = (
                    item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                )

                # print(f'raw_url: {raw_url}')

                # check if the file exists in cache
                if raw_url in cached_urls:
                    continue
                else:
                    cached_urls.add(raw_url)  # 保留原始 URL

                # Fetch the file content
                file_content = fetch_file_content(raw_url)

                process_and_save_xml(raw_url, file_content, savedKeys)
    return len(search_results["items"]) > 0  # Return True if there could be more results


# Function to fetch file content
def fetch_file_content(url: str):
    response = session.get(url)
    if response.status_code == 200:
        return response.content
    else:
        raise RuntimeError(f"Failed to download {url}")


# Fetch all pages
page = 1
has_more = True
while has_more:
    has_more = fetch_and_process_results(page)
    page += 1

# 更新缓存文件，直接写入集合中的内容
with open(cache_file, "w") as cache:
    cache.writelines(f"{url}\n" for url in cached_urls)  # 这里添加换行符

for file_path in savedKeys.glob("*.xml"):
    print(f'Begin to CheckValid: {file_path}')
    file_content = file_path.read_text()  # Read file content as a string

    # 遍历文件并检查其有效性
    if not CheckValid(file_content):
        file_path.unlink()  # 自动删除无效文件
        print(f"Deleted invalid file: {file_path.name}")
    else:
        # 对有效文件进行打印
        print(f"Valid file: {file_path.name}")

