import os
import requests
from dotenv import load_dotenv





# Load environment variables from .env file
load_dotenv()

HTTP_PROXY = os.getenv("HTTP_PROXY")
HTTPS_PROXY = os.getenv("HTTPS_PROXY")
print(f'HTTP_PROXY: {HTTP_PROXY}')
print(f'HTTPS_PROXY: {HTTPS_PROXY}')

proxies = {
    "http": HTTP_PROXY,
    "https": HTTPS_PROXY,
}

try:
    response = requests.get("https://api.github.com", proxies=proxies, timeout=10)
    print(response.status_code)
except requests.exceptions.RequestException as e:
    print(f"Proxy test failed: {e}")
