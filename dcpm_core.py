# dcpm_core.py

import hashlib
import time
import os
import aiofiles
import asyncio
import aiohttp
from collections import namedtuple
import btporrent
import ipfshttpclient
import struct


def get_software_id(name):
    """根据软件名称计算软件 ID"""
    return hashlib.sha256(name.encode()).hexdigest()


def get_package_id(name, source):
    """根据软件名称和信任源计算包 ID"""
    return hashlib.sha256(f"{name}@{source}".encode()).hexdigest()


def get_version_id(name, source, version, parent_version=None):
    """根据软件名称、信任源、版本号和上游版本计算版本 ID"""
    if parent_version:
        content = f"{name}@{source}:{version}<=>{parent_version}"
    else:
        content = f"{name}@{source}:{version}"
    return hashlib.sha256(content.encode()).hexdigest()


# DHT 节点的列表
DHT_NODES = ["http://node1.example.com", "http://node2.example.com"]


class DHTNode:
    def __init__(self, node_url, protocol="http"):
        self.node_url = node_url
        self.protocol = protocol
        self.data = {}

    async def put(self, key, value):
        if self.protocol == "http" or self.protocol == "https":
            url = f"{self.node_url}/put?key={key}&value={value}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return await response.text()
        elif self.protocol == "udp":
            reader, writer = await asyncio.open_connection(
                self.node_url.split("://")[1], 8001
            )
            message = struct.pack("!16s%ds" % len(value), key.encode(), value.encode())
            writer.write(message)
            await writer.drain()
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return data.decode()
        elif self.protocol == "tcp":
            reader, writer = await asyncio.open_connection(
                self.node_url.split("://")[1], 8002
            )
            message = struct.pack("!16s%ds" % len(value), key.encode(), value.encode())
            writer.write(message)
            await writer.drain()
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return data.decode()
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

    async def get(self, key):
        if self.protocol == "http" or self.protocol == "https":
            url = f"{self.node_url}/get?key={key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return await response.text()
        elif self.protocol == "udp":
            reader, writer = await asyncio.open_connection(
                self.node_url.split("://")[1], 8001
            )
            message = struct.pack("!16s", key.encode())
            writer.write(message)
            await writer.drain()
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return data.decode()
        elif self.protocol == "tcp":
            reader, writer = await asyncio.open_connection(
                self.node_url.split("://")[1], 8002
            )
            message = struct.pack("!16s", key.encode())
            writer.write(message)
            await writer.drain()
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return data.decode()
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

    async def put_file(self, file_id, file_data):
        """分块存储文件到DHT"""
        blocks = [
            file_data[i : i + BLOCK_SIZE] for i in range(0, len(file_data), BLOCK_SIZE)
        ]
        block_hashes = []
        for i, block in enumerate(blocks):
            block_hash = hashlib.sha256(block).hexdigest()
            block_key = f"{file_id}:{i}"
            await self.put(block_key, block)
            block_hashes.append(block_hash)
        return block_hashes

    async def get_file(self, file_id, block_hashes):
        """从DHT获取文件"""
        file_data = b""
        for i, block_hash in enumerate(block_hashes):
            block_key = f"{file_id}:{i}"
            block_data = await self.get(block_key)
            if block_data:
                file_data += block_data.encode()
            else:
                return None
        return file_data


async def put_metadata(key, value):
    tasks = []
    for node_url in DHT_NODES:
        node = DHTNode(node_url)
        tasks.append(asyncio.create_task(node.put(key, value)))
    await asyncio.gather(*tasks)


async def get_metadata(key):
    for node_url in DHT_NODES:
        node = DHTNode(node_url)
        value = await node.get(key)
        if value:
            return value
    return None


BLOCK_SIZE = 1024 * 1024  # 1MB

FileChecksum = namedtuple("FileChecksum", ["md5", "sha1", "sha256", "crc32"])


class Package:
    def __init__(self, name, version, files, package_manager, dependencies=None):
        self.software_id = get_software_id(name)
        self.package_id = get_package_id(name, "SELF")
        self.version_id = get_version_id(name, "SELF", version)
        self.name = name
        self.version = version
        self.files = files
        self.package_manager = package_manager
        self.dependencies = dependencies or []
        self.block_hashes = []
        self.calculate_checksums()

    def calculate_checksums(self):
        """计算软件包文件的校验和"""
        self.checksums = {}
        for file_path, file_data in self.files.items():
            md5 = hashlib.md5(file_data).hexdigest()
            sha1 = hashlib.sha1(file_data).hexdigest()
            sha256 = hashlib.sha256(file_data).hexdigest()
            crc32 = binascii.crc32(file_data).hexdigest()
            self.checksums[file_path] = FileChecksum(md5, sha1, sha256, crc32)

    async def publish(self):
        """发布软件包到网络"""
        package_data = {
            "name": self.name,
            "version": self.version,
            "package_manager": self.package_manager,
            "dependencies": self.dependencies,
            "files": {},
            "checksums": self.checksums,
            "signature": sign_data(str(self), private_key_pem),
        }

        for file_path, file_data in self.files.items():
            file_id = hashlib.sha256(
                f"{self.package_id}:{file_path}".encode()
            ).hexdigest()
            block_hashes = await DHTNode(DHT_NODES[0]).put_file(file_id, file_data)
            package_data["files"][file_path] = {
                "id": file_id,
                "size": len(file_data),
                "block_hashes": block_hashes,
            }

        # 将软件包元数据添加到区块链
        blockchain.add_data(str(package_data))
        await blockchain.mine_block()

        # 将软件包元数据存储到DHT
        await put_metadata(self.package_id, str(package_data))

    async def download(self):
        """从网络下载软件包"""
        package_data_str = await get_metadata(self.package_id)
        if package_data_str:
            package_data = eval(package_data_str)

            # 验证软件包签名
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not verify_signature(
                str(package_data), package_data["signature"], public_key
            ):
                print("软件包签名验证失败")
                return

            # 下载软件包文件
            self.files = {}
            for file_path, file_meta in package_data["files"].items():
                file_id = file_meta["id"]
                block_hashes = file_meta["block_hashes"]
                file_data = await DHTNode(DHT_NODES[0]).get_file(file_id, block_hashes)
                if file_data:
                    self.files[file_path] = file_data
                else:
                    print(f"无法下载文件 {file_path}")
                    return

            # 验证文件校验和
            for file_path, checksum in package_data["checksums"].items():
                if checksum != self.checksums[file_path]:
                    print(f"文件 {file_path} 校验和不匹配")
                    return

            # 验证区块链上的软件包元数据
            if not await validate_package_metadata(self):
                print("软件包元数据验证失败")
                return

            return self
        else:
            print(f"无法找到软件包 {self.package_id}")
            return None

    async def install(self):
        """安装软件包"""
        for file_path, file_data in self.files.items():
            file_name = os.path.basename(file_path)
            install_path = os.path.join("/tmp", file_name)
            async with aiofiles.open(install_path, "wb") as f:
                await f.write(file_data)

            if self.package_manager == "dpkg":
                print(f"使用 dpkg 安装 {file_name}")
                os.system(f"dpkg -i {install_path}")
            elif self.package_manager == "rpm":
                print(f"使用 rpm 安装 {file_name}")
                os.system(f"rpm -i {install_path}")

            os.remove(install_path)

        for dep_id in self.dependencies:
            dep_package_id = get_package_id(dep_id, "SELF")
            dep_package = await Package.download(dep_package_id)
            if dep_package:
                await dep_package.install()
            else:
                print(f"无法安装依赖软件包 {dep_id}")

    @staticmethod
    async def uninstall(package_name):
        """卸载软件包"""
        software_id = get_software_id(package_name)
        package_id = get_package_id(package_name, "SELF")
        package_data_str = await get_metadata(package_id)
        if package_data_str:
            package_data = eval(package_data_str)
            package_manager = package_data["package_manager"]
            for file_path in package_data["files"]:
                file_name = os.path.basename(file_path)
                if package_manager == "dpkg":
                    print(f"使用 dpkg 卸载 {file_name}")
                    os.system(f"dpkg -r {file_name}")
                elif package_manager == "rpm":
                    print(f"使用 rpm 卸载 {file_name}")
                    os.system(f"rpm -e {file_name}")
        else:
            print(f"无法找到软件包 {package_name}")


class TrustSource:
    def __init__(self, name, domain, pubkey):
        self.name = name
        self.domain = domain
        self.pubkey = pubkey
        self.fingerprint = hashlib.sha256(pubkey.encode()).hexdigest()
        self.packages = []

    def add_package(self, package):
        self.packages.append(package)

    def __str__(self):
        return f"{self.name}@{self.domain} ({self.fingerprint})"

    def __repr__(self):
        return f"TrustSource('{self.name}', '{self.domain}', '{self.pubkey}')"


class TrustDomain:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.subtrustdomains = []
        self.trust_sources = []
        self.primary_providers = []
        self.secondary_allowlist = []
        self.secondary_blocklist = []

        # 生成RSA密钥对
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=None
        )
        public_key = private_key.public_key()

        # 将公钥和私钥序列化为PEM格式
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def add_primary_provider(self, provider):
        self.primary_providers.append(provider)

    def add_secondary_to_allowlist(self, provider):
        self.secondary_allowlist.append(provider)

    def add_secondary_to_blocklist(self, provider):
        self.secondary_blocklist.append(provider)

    def add_subtrustdomain(self, subtrustdomain):
        self.subtrustdomains.append(subtrustdomain)

    def add_trust_source(self, trust_source):
        self.trust_sources.append(trust_source)

    def sign_data(self, data):
        """使用私钥对数据进行数字签名"""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=None
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
        public_key = serialization.load_pem_public_key(
            self.public_key_pem, backend=None
        )
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
        if self.parent:
            return f"{self.parent}.{self.name}"
        else:
            return self.name

    def __repr__(self):
        return f"TrustDomain('{self.name}', parent={self.parent})"


class Domain:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.subdomains = []
        self.trust_sources = []
        self.primary_providers = []
        self.secondary_allowlist = []
        self.secondary_blocklist = []
        # 创建对应的 TrustDomain 对象
        self.trust_domain = TrustDomain(name, parent)

    def add_primary_provider(self, provider):
        self.primary_providers.append(provider)

    def add_secondary_to_allowlist(self, provider):
        self.secondary_allowlist.append(provider)

    def add_secondary_to_blocklist(self, provider):
        self.secondary_blocklist.append(provider)

    def add_subdomain(self, subdomain):
        self.subdomains.append(subdomain)

    def add_trust_source(self, trust_source):
        self.trust_sources.append(trust_source)

    def __str__(self):
        if self.parent:
            return f"{self.parent}.{self.name}"
        else:
            return self.name

    def __repr__(self):
        return f"Domain('{self.name}', parent={self.parent})"


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
    # 验证第一类提供者
    if not is_primary_provider_trusted(package.source_domain, package.primary_provider):
        return False

    # 验证第二类提供者
    for provider in package.secondary_providers:
        if not is_secondary_provider_allowed(
            package.source_domain, provider, strict_mode=True
        ):
            return False

    return True


# 创建域
self_domain = Domain("SELF")
other_domain = Domain("EG_OTHER")
sub_domain = Domain("SUB", other_domain)
other_domain.add_subdomain(sub_domain)

# 创建信任源
self_source = TrustSource("SELF", self_domain, "")
self_domain.add_trust_source(self_source)

"""
anthropic_source = TrustSource("Anthropic", other_domain, "abc123...")
other_domain.add_trust_source(anthropic_source)

sub_source = TrustSource("SubSource", sub_domain, "def456...")
sub_domain.add_trust_source(sub_source)
"""

# 创建软件包
package1_files = {
    "dcpm": b"Content of dcpm",
    "dcpm.deb": b"Binary content of dcpm.deb",
}
package1 = Package("dcpm", "1.0.0", package1_files, "dpkg")

package2_files = {
    "dcpm": b"Content of dcpm 1.1.0",
    "dcpm-1.1.0.rpm": b"Binary content of dcpm-1.1.0.rpm",
}
package2 = Package("dcpm", "1.1.0", package2_files, "rpm", dependencies=["dcpm:1.0.0"])

# 将软件包添加到信任源
self_source.add_package(package1)
self_source.add_package(package2)


class BlockHeader:
    def __init__(self, index, timestamp, data_hash, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data_hash = data_hash
        self.prev_hash = prev_hash

    def calculate_hash(self):
        """计算区块头的哈希值"""
        header_data = f"{self.index}{self.timestamp}{self.data_hash}{self.prev_hash}"
        return hashlib.sha256(header_data.encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = []  # 区块链
        self.pending_data = []  # 待打包的数据
        self.create_genesis_block()

    def create_genesis_block(self):
        """创建创世区块"""
        genesis_block = BlockHeader(0, 0, "0" * 64, "0" * 64)
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)

    def add_data(self, data):
        """添加待打包的数据"""
        self.pending_data.append(data)

    async def mine_block(self):
        """打包并添加新的区块"""
        # 计算待打包数据的哈希
        data_hash = hashlib.sha256("".join(self.pending_data).encode()).hexdigest()

        # 创建新的区块头
        index = len(self.chain)
        timestamp = int(time.time())
        prev_hash = self.chain[-1].hash
        new_header = BlockHeader(index, timestamp, data_hash, prev_hash)
        new_header.hash = new_header.calculate_hash()

        # 将新区块添加到区块链
        self.chain.append(new_header)
        self.pending_data = []  # 清空待打包数据

    async def validate_chain(self):
        """验证区块链的完整性"""
        for i in range(1, len(self.chain)):
            current_header = self.chain[i]
            prev_header = self.chain[i - 1]

            # 验证区块头的哈希值
            if current_header.calculate_hash() != current_header.hash:
                return False

            # 验证前一个区块头的哈希值
            if current_header.prev_hash != prev_header.hash:
                return False

        return True


async def validate_package_metadata(package):
    """验证软件包元数据是否存在于区块链上"""
    package_data = {
        "name": package.name,
        "version": package.version,
        "package_manager": package.package_manager,
        "dependencies": package.dependencies,
        "files": {
            file_path: {
                "id": file_meta["id"],
                "size": file_meta["size"],
                "block_hashes": file_meta["block_hashes"],
            }
            for file_path, file_meta in package.files.items()
        },
        "checksums": package.checksums,
    }
    package_data_str = str(package_data)
    package_signature = sign_data(package_data_str, private_key_pem)

    for block in blockchain.chain:
        if block.data_hash == hashlib.sha256(package_data_str.encode()).hexdigest():
            if block.index == 0:
                return False  # 创世区块不应该包含软件包元数据
            prev_block = blockchain.chain[block.index - 1]
            if prev_block.hash == block.prev_hash:
                # 验证软件包签名
                public_key = serialization.load_pem_public_key(public_key_pem)
                if verify_signature(package_data_str, package_signature, public_key):
                    return True
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


class Network:
    def __init__(self, name, dht_nodes, blockchain=None):
        self.name = name
        self.dht_nodes = dht_nodes
        self.blockchain = blockchain or Blockchain()

    def set_dht_nodes(self, dht_nodes):
        self.dht_nodes = dht_nodes

    def set_blockchain(self, blockchain):
        self.blockchain = blockchain


MAIN_NETWORK = Network("main", ["http://node1.example.com", "http://node2.example.com"])

TEST_NETWORK = Network(
    "test",
    ["http://testnode1.example.com", "http://testnode2.example.com"],
    Blockchain(),
)

CURRENT_NETWORK = MAIN_NETWORK


def get_dht_nodes():
    return CURRENT_NETWORK.dht_nodes


def get_blockchain():
    return CURRENT_NETWORK.blockchain


def switch_network(network_name):
    global CURRENT_NETWORK
    if network_name == "main":
        CURRENT_NETWORK = MAIN_NETWORK
    elif network_name == "test":
        CURRENT_NETWORK = TEST_NETWORK
    else:
        raise ValueError(f"Invalid network name: {network_name}")


def create_network(name, dht_nodes, blockchain=None):
    new_network = Network(name, dht_nodes, blockchain)
    setattr(sys.modules[__name__], name.upper() + "_NETWORK", new_network)
    print(f"New network '{name}' created.")


async def put_metadata(key, value):
    tasks = []
    for node_url in get_dht_nodes():
        node = DHTNode(node_url)
        tasks.append(asyncio.create_task(node.put(key, value)))
    await asyncio.gather(*tasks)


async def get_metadata(key):
    for node_url in get_dht_nodes():
        node = DHTNode(node_url)
        value = await node.get(key)
        if value:
            return value
    return None


async def put_metadata_ipfs(key, value):
    ipfs_client = ipfshttpclient.connect()
    res = ipfs_client.add_str(value)
    ipfs_hash = res[-1]["Hash"]
    await put_metadata(key, ipfs_hash)


async def get_metadata_ipfs(key):
    ipfs_hash = await get_metadata(key)
    if ipfs_hash:
        ipfs_client = ipfshttpclient.connect()
        value = ipfs_client.cat(ipfs_hash)
        return value
    return None


async def start_bt_seeding(torrent_hash, value):
    torrent = btporrent.get_torrent(torrent_hash)
    torrent.start_seeding(value)


async def put_metadata_bt(key, value):
    torrent = btporrent.create_torrent(value)
    torrent_hash = torrent.info_hash
    await put_metadata(key, torrent_hash)
    await start_bt_seeding(torrent_hash, value)


async def get_metadata_bt(key):
    torrent_hash = await get_metadata(key)
    if torrent_hash:
        torrent = btporrent.get_torrent(torrent_hash)
        value = await torrent.download()
        return value
    return None


blockchain = Blockchain()
