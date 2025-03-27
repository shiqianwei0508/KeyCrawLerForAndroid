# 导入必要的模块
import requests
import lxml.etree as ET
# 用于处理日期和时间
from datetime import datetime, timezone
# 加载并操作证书相关的模块
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
import os
# 用于加载环境变量
from dotenv import load_dotenv

PUBLIC_KEYS = {
        "google": "pem/google.pem",
        "aosp_ec": "pem/aosp_ec.pem",
        "aosp_rsa": "pem/aosp_rsa.pem",
        "knox": "pem/knox.pem",
    }

# 加载环境变量
load_dotenv()

# 从环境变量中获取代理配置
HTTP_PROXY = os.getenv("HTTP_PROXY")
HTTPS_PROXY = os.getenv("HTTPS_PROXY")
# 为 HTTP 和 HTTPS 请求配置代理
proxies = {
    "http": HTTP_PROXY,
    "https": HTTPS_PROXY,
}

# 定义目标 URL 和 HTTP 请求头部信息
url = "https://android.googleapis.com/attestation/status"
headers = {
    "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate", # 不允许缓存
    "Pragma": "no-cache", # HTTP 1.0 禁止缓存
    "Expires": "0", # 强制立即失效
}
# 发送 HTTP 请求
response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
# 如果响应状态码不是 200，则抛出异常
if response.status_code != 200:
    raise Exception(f"Error fetching data: {response.reason}")
# 将 JSON 响应转换为 Python 字典
status_json = response.json()


# 定义一个函数用于解析 XML 文件中的证书数量
def parse_number_of_certificates(xml_file):
    # 如果输入是字符串，先将其编码为字节类型
    if isinstance(xml_file, str):
        xml_file = xml_file.encode("utf-8")

    # 使用 lxml.etree 解析 XML 文件
    root = ET.fromstring(xml_file)
    # 查找包含证书数量的节点
    number_of_certificates = root.find(".//NumberOfCertificates")

    # 如果找到该节点，解析并返回其值
    if number_of_certificates is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        # 如果找不到节点，则抛出异常
        raise Exception("No NumberOfCertificates found.")


# 定义函数，用于从 XML 文件中解析证书内容
def parse_certificates(xml_file, pem_number):
    # 如果输入是字符串，先将其编码为字节类型
    if isinstance(xml_file, str):
        xml_file = xml_file.encode("utf-8")

    # 使用 lxml.etree 解析 XML 文件
    root = ET.fromstring(xml_file)

    # 查找格式为 PEM 的证书内容
    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    # 提取指定数量的 PEM 证书
    if pem_certificates is not None:
        pem_contents = [cert.text.strip() for cert in pem_certificates[:pem_number]]
        return pem_contents
    else:
        # 如果没有找到证书，抛出异常
        raise Exception("No Certificate found.")


# 定义函数，从文件中加载 PEM 格式的公钥
def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    return public_key


# 比较两个公钥是否一致
def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def verify_signature(signature_algorithm, signature, tbs_certificate, public_key):
    rsa_algorithms = ["sha256WithRSAEncryption", "sha1WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption"]
    ecdsa_algorithms = ["ecdsa-with-SHA256", "ecdsa-with-SHA1", "ecdsa-with-SHA384", "ecdsa-with-SHA512"]
    hash_map = {
        "sha256WithRSAEncryption": hashes.SHA256(),
        "sha1WithRSAEncryption": hashes.SHA1(),
        "sha384WithRSAEncryption": hashes.SHA384(),
        "sha512WithRSAEncryption": hashes.SHA512(),
        "ecdsa-with-SHA256": hashes.SHA256(),
        "ecdsa-with-SHA1": hashes.SHA1(),
        "ecdsa-with-SHA384": hashes.SHA384(),
        "ecdsa-with-SHA512": hashes.SHA512(),
    }
    hash_algorithm = hash_map.get(signature_algorithm)
    if signature_algorithm in rsa_algorithms:
        public_key.verify(signature, tbs_certificate, padding.PKCS1v15(), hash_algorithm)
    elif signature_algorithm in ecdsa_algorithms:
        public_key.verify(signature, tbs_certificate, ec.ECDSA(hash_algorithm))
    else:
        raise ValueError("Unsupported signature algorithms")

# 定义主函数，用于验证证书链及其相关的属性
def keybox_check(certificate_text):
    try:
        # 获取证书数量及其内容
        pem_number = parse_number_of_certificates(certificate_text)
        pem_certificates = parse_certificates(certificate_text, pem_number)

        # 加载第一个证书（通常为叶子证书）
        certificate = x509.load_pem_x509_certificate(pem_certificates[0].encode(), default_backend())
    except Exception as e:
        print(f"[Keybox Check Error]: {e}")
        return False

    # 验证证书是否在有效期范围内
    # 如果当前时间不在有效期内，返回 False
    current_time = datetime.now(timezone.utc)
    if not (certificate.not_valid_before_utc <= current_time <= certificate.not_valid_after_utc):
        return False

    # 验证证书链的完整性
    for i in range(pem_number - 1):
        # 加载当前证书和父证书
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        # 检查子证书的签发者是否与父证书的主题匹配
        if son_certificate.issuer != father_certificate.subject:
            return False

        # 验证签名
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            verify_signature(signature_algorithm, signature, tbs_certificate, public_key)
        except Exception:
            return False

    # 检查根证书的公钥是否可信
    root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
    root_public_key = root_certificate.public_key()
    # 加载预置的公钥
    google_public_key = load_public_key_from_file(PUBLIC_KEYS["google"])
    aosp_ec_public_key = load_public_key_from_file(PUBLIC_KEYS["aosp_ec"])
    aosp_rsa_public_key = load_public_key_from_file(PUBLIC_KEYS["aosp_rsa"])
    knox_public_key = load_public_key_from_file(PUBLIC_KEYS["knox"])

    # 根公钥验证逻辑
    trusted_keys = {
        "google": google_public_key,
        "aosp_ec": aosp_ec_public_key,
        "aosp_rsa": aosp_rsa_public_key,
        "knox": knox_public_key,
    }

    for key_name, public_key in trusted_keys.items():
        if compare_keys(root_public_key, public_key):
            if key_name == "knox":
                print("Found a knox key !?")
            elif key_name in ["aosp_ec", "aosp_rsa"]:
                return False
            break
    else:
        return False

    # 验证证书撤销状态
    serial_number_string = hex(certificate.serial_number)[2:].lower()
    if status_json.get("entries", {}).get(serial_number_string):
        return False

    # 如果所有检查通过，则返回 True
    return True
