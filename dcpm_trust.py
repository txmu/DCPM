# dcpm_trust.py

import hashlib
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from dcpm_core import (
    get_software_id,
    get_package_id,
    get_version_id,
    Domain,
    TrustDomain,
)

# 目前（2024年5月2日，星期四，UTC+8，15:02:10），这里所有的功能都已经在dcpm_core.py中实现。
# 它们最初被单独实现在该文件中，但是后来出于增强安全性与避免循环依赖的考虑将这些代码加入到core中。
# 现在该文件中与core相同的代码旨在保持兼容性与轻便，
# 同时这里未来会加入更多与信任源、域和信任网络有关的代码。

# 目前（2024年5月2日，星期四，UTC+8，19:51:58），这里所有的功能并非都已经在dcpm_core.py中实现。


def sign_data(data, private_key_pem):
    """使用私钥对数据进行数字签名"""
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=None
    )
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(data, signature, public_key_pem):
    """使用公钥验证数字签名"""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=None)
    try:
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# 生成RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=None
)
public_key = private_key.public_key()

# 将公钥和私钥序列化为PEM格式
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)


class TrustSource:
    def __init__(self, name, domain, pubkey):
        self.name = name
        self.domain = domain
        self.pubkey = pubkey
        self.fingerprint = hashlib.sha256(pubkey.encode()).hexdigest()
        self.packages = []

    def add_package(self, package):
        self.packages.append(package)

    def sign_data(self, data):
        """使用私钥对数据进行数字签名"""
        private_key = serialization.load_pem_private_key(
            self.domain.private_key_pem, password=None, backend=None
        )
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return signature

    def verify_data(self, data, signature):
        """使用公钥验证数字签名"""
        public_key = serialization.load_pem_public_key(self.pubkey, backend=None)
        try:
            public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def __str__(self):
        return f"{self.name}@{self.domain.name} ({self.fingerprint})"

    def __repr__(self):
        return f"TrustSource('{self.name}', '{self.domain}', '{self.pubkey}')"


class TrustProvider:
    def __init__(self, name, domain, pubkey, type):
        self.name = name
        self.domain = domain
        self.pubkey = pubkey
        self.type = type  # "primary" 或 "secondary"
        self.fingerprint = hashlib.sha256(pubkey.encode()).hexdigest()

    def __str__(self):
        return f"{self.name}@{self.domain.name} ({self.fingerprint})"

    def __repr__(self):
        return f"TrustProvider('{self.name}', '{self.domain}', '{self.pubkey}', '{self.type}')"


def is_primary_provider_trusted(domain, provider):
    return provider in domain.primary_providers


def is_secondary_provider_allowed(domain, provider, strict_mode=False):
    if strict_mode:
        return provider in domain.secondary_allowlist
    else:
        return provider not in domain.secondary_blocklist


async def verify_package_providers(package):
    """验证软件包的提供者是否可信"""
    # 验证第一类提供者
    source_domain = get_source_domain(package.source)
    if not is_primary_provider_trusted(source_domain, package.primary_provider):
        return False

    # 验证第二类提供者
    for provider in package.secondary_providers:
        if not is_secondary_provider_allowed(source_domain, provider, strict_mode=True):
            return False

    # 验证软件包签名
    source_trust = get_trust_source(package.source)
    if not source_trust.verify_data(str(package), package.signature):
        return False

    return True


def get_source_domain(source):
    """获取信任源所属的域"""
    parts = source.split("@")
    domain_name = parts[1]
    domain = get_domain(domain_name)
    return domain


def get_trust_source(source):
    """获取指定的信任源"""
    parts = source.split("@")
    source_name = parts[0]
    domain = get_source_domain(source)
    for trust_source in domain.trust_sources:
        if trust_source.name == source_name:
            return trust_source
    return None


def get_domain(name, parent=None):
    """获取指定的域"""
    for network in TRUST_NETWORKS:
        for domain in network.domains:
            if domain.name == name and domain.parent == parent:
                return domain
    return None


class TrustNetwork:
    def __init__(self, name, root_domain):
        self.name = name
        self.root_domain = root_domain
        self.domains = [root_domain]

    def add_domain(self, domain):
        self.domains.append(domain)

    def get_domain(self, name, parent=None):
        """获取指定的域"""
        for domain in self.domains:
            if domain.name == name and domain.parent == parent:
                return domain
        return None


# 创建根域和信任网络
ROOT_DOMAIN = Domain("ROOT")
MAIN_NETWORK = TrustNetwork("main", ROOT_DOMAIN)
TEST_NETWORK = TrustNetwork("test", Domain("test"))

# 添加子域和信任源
DCPM_DOMAIN = Domain("dcpm", ROOT_DOMAIN)
MAIN_NETWORK.add_domain(DCPM_DOMAIN)

DCPM_SOURCE = TrustSource("dcpm", DCPM_DOMAIN, "dcpm_pubkey_pem")
DCPM_DOMAIN.add_trust_source(DCPM_SOURCE)

THIRD_PARTY_DOMAIN = Domain("third-party", DCPM_DOMAIN)
DCPM_DOMAIN.add_subdomain(THIRD_PARTY_DOMAIN)

COMPANY_A_SOURCE = TrustSource("company-a", THIRD_PARTY_DOMAIN, "company_a_pubkey_pem")
THIRD_PARTY_DOMAIN.add_trust_source(COMPANY_A_SOURCE)

# 添加主要和次要提供者
DCPM_DOMAIN.add_primary_provider(DCPM_SOURCE)
DCPM_DOMAIN.add_secondary_to_allowlist(COMPANY_A_SOURCE)

# 其他信任网络操作示例
CUSTOM_NETWORK = TrustNetwork("custom", Domain("custom"))
CUSTOM_DOMAIN = Domain("my-domain", ROOT_DOMAIN)
CUSTOM_NETWORK.add_domain(CUSTOM_DOMAIN)

CUSTOM_SOURCE = TrustSource("my-source", CUSTOM_DOMAIN, "my_source_pubkey_pem")
CUSTOM_DOMAIN.add_trust_source(CUSTOM_SOURCE)
CUSTOM_DOMAIN.add_primary_provider(CUSTOM_SOURCE)

TRUST_NETWORKS = [MAIN_NETWORK, TEST_NETWORK, CUSTOM_NETWORK]


# 实现其他函数
async def verify_package_signature(package):
    """验证软件包签名"""
    source_trust = get_trust_source(package.source)
    if source_trust:
        return source_trust.verify_data(str(package), package.signature)
    return False


async def verify_package(package):
    """验证软件包的完整性"""
    if not await verify_package_providers(package):
        return False
    if not await verify_package_signature(package):
        return False

    # 验证软件包文件的校验和
    for file_path, file_data in package.files.items():
        md5 = hashlib.md5(file_data).hexdigest()
        sha1 = hashlib.sha1(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()
        crc32 = binascii.crc32(file_data).hexdigest()

        if (md5, sha1, sha256, crc32) != package.checksums[file_path]:
            print(f"文件 {file_path} 校验和不匹配")
            return False

    # 其他验证逻辑...
    return True


# 使用示例
package = Package(...)
if await verify_package(package):
    print("软件包验证通过，可以安全安装")
else:
    print("软件包验证失败，安装被拒绝")
