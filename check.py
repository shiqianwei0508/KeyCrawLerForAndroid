# 导入必要的模块
import requests
import lxml.etree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

# 加载环境变量，用于获取代理设置
load_dotenv()

# 定义 HTTP 和 HTTPS 代理
HTTP_PROXY = os.getenv("HTTP_PROXY")
HTTPS_PROXY = os.getenv("HTTPS_PROXY")
proxies = {
    "http": HTTP_PROXY,
    "https": HTTPS_PROXY,
}

# 定义 URL 和请求头信息，用于确保数据未被缓存
url = "https://android.googleapis.com/attestation/status"
headers = {
    "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}
# 发送 HTTP GET 请求
response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
if response.status_code != 200:
    # 如果响应失败，抛出异常
    raise Exception(f"Error fetching data: {response.reason}")
# 将响应转换为 JSON 格式
status_json = response.json()


# 定义函数以解析 XML 文件中的证书数量
def parse_number_of_certificates(xml_file):
    # 如果传入的是字符串，先将其转换为字节形式
    if isinstance(xml_file, str):
        xml_file = xml_file.encode("utf-8")

    # 使用 lxml 从字符串中解析 XML
    root = ET.fromstring(xml_file)
    # 查找 XML 中表示证书数量的节点
    number_of_certificates = root.find(".//NumberOfCertificates")

    # 如果找到证书数量，提取并返回
    if number_of_certificates is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        # 如果未找到，抛出异常
        raise Exception("No NumberOfCertificates found.")


# 定义函数以解析 XML 文件中的证书内容
def parse_certificates(xml_file, pem_number):
    # 如果传入的是字符串，先将其转换为字节形式
    if isinstance(xml_file, str):
        xml_file = xml_file.encode("utf-8")

    # 使用 lxml 从字符串中解析 XML
    root = ET.fromstring(xml_file)

    # 查找 XML 中格式为 PEM 的证书内容
    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    # 提取并返回指定数量的证书内容
    if pem_certificates is not None:
        pem_contents = [cert.text.strip() for cert in pem_certificates[:pem_number]]
        return pem_contents
    else:
        # 如果未找到证书，抛出异常
        raise Exception("No Certificate found.")


# 定义函数以从文件中加载公钥
def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        # 使用加密库加载 PEM 公钥
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    return public_key


# 定义函数以比较两个公钥是否一致
def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# 定义 Keybox 检查函数以验证证书链及其有效性
def keybox_check(certificate_text):
    try:
        # 解析证书数量
        pem_number = parse_number_of_certificates(certificate_text)
        # 获取指定数量的证书内容
        pem_certificates = parse_certificates(certificate_text, pem_number)
    except Exception as e:
        # 捕获并打印解析过程中的错误
        print(f"[Keybox Check Error]: {e}")
        return False

    try:
        # 尝试加载根证书
        certificate = x509.load_pem_x509_certificate(pem_certificates[0].encode(), default_backend())
    except Exception as e:
        # 捕获并打印加载过程中的错误
        print(f"[Keybox Check Error]: {e}")
        return False

    # 验证证书有效性
    not_valid_before = certificate.not_valid_before
    not_valid_after = certificate.not_valid_after
    current_time = datetime.now(timezone.utc)
    # 检查当前时间是否在证书有效期内
    is_valid = not_valid_before <= current_time <= not_valid_after
    if not is_valid:
        return False

    # 验证证书链的签名完整性
    for i in range(pem_number - 1):
        # 加载子证书和父证书
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        # 检查签发者和主题是否匹配
        if son_certificate.issuer != father_certificate.subject:
            return False

        # 提取签名信息和公钥
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()

        try:
            # 根据签名算法验证证书
            if signature_algorithm in [
                "sha256WithRSAEncryption",
                "sha1WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
            ]:
                # 定义哈希算法和填充方式
                hash_algorithm = {
                    "sha256WithRSAEncryption": hashes.SHA256(),
                    "sha1WithRSAEncryption": hashes.SHA1(),
                    "sha384WithRSAEncryption": hashes.SHA384(),
                    "sha512WithRSAEncryption": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                # 验证签名
                public_key.verify(signature, tbs_certificate, padding_algorithm, hash_algorithm)
            elif signature_algorithm in [
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA1",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ]:
                # 定义哈希算法和填充方式
                hash_algorithm = {
                    "ecdsa-with-SHA256": hashes.SHA256(),
                    "ecdsa-with-SHA1": hashes.SHA1(),
                    "ecdsa-with-SHA384": hashes.SHA384(),
                    "ecdsa-with-SHA512": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                # 验证签名
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception:
            return False

    # 验证根证书的公钥
    root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
    root_public_key = root_certificate.public_key()
    # 加载可能匹配的公钥
    google_public_key = load_public_key_from_file("pem/google.pem")
    aosp_ec_public_key = load_public_key_from_file("pem/aosp_ec.pem")
    aosp_rsa_public_key = load_public_key_from_file("pem/aosp_rsa.pem")
    knox_public_key = load_public_key_from_file("pem/knox.pem")

    # 比较公钥是否匹配
    if compare_keys(root_public_key, google_public_key):
        pass
    elif compare_keys(root_public_key, aosp_ec_public_key):
        return False
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        return False
    elif compare_keys(root_public_key, knox_public_key):
        print("Found a knox key !?")
    else:
        return False

    # 验证证书的撤销状态
    serial_number_string = hex(certificate.serial_number)[2:].lower()
    status = status_json["entries"].get(serial_number_string, None)
    if status is not None:
        return False

    # 如果所有验证都通过，则返回 True
    return True