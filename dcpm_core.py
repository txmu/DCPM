import hashlib
import time
import os

def get_software_id(name):
    """
    根据软件名称计算软件 ID
    """
    return hashlib.sha256(name.encode()).hexdigest()

def get_package_id(name, source):
    """
    根据软件名称和信任源计算包 ID
    """
    return hashlib.sha256(f"{name}@{source}".encode()).hexdigest()

def get_version_id(name, source, version, parent_version=None):
    """
    根据软件名称、信任源、版本号和上游版本计算细 ID
    """
    if parent_version:
        content = f"{name}@{source}:{version}<=>{parent_version}"
    else:
        content = f"{name}@{source}:{version}"
    return hashlib.sha256(content.encode()).hexdigest()


# DHT 节点的列表
DHT_NODES = ["http://node1.example.com",/ "http://node2.example.com"]

class DHTNode:
    def __init__(self, node_url):
        self.node_url = node_url
        self.data = {}

    async def put(self, key, value):
        url = f"{self.node_url}/put?key={key}&value={value}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.text()

    async def get(self, key):
        url = f"{self.node_url}/get?key={key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.text()

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

def calculate_key(package):
    return hashlib.sha256(str(package).encode()).hexdigest()


class Package:
    def __init__(self, name, version, content, package_manager, dependencies=None):
        self.software_id = get_software_id(name)
        self.name = name
        self.version = version
        self.content = content
        self.package_manager = package_manager
        self.dependencies = dependencies or []

    def __str__(self):
        return f"{self.name}-{self.version} ({self.software_id})"

    def __repr__(self):
        return f"Package('{self.name}', '{self.version}', '{self.content}', '{self.package_manager}', dependencies={self.dependencies})"

    async def install(self):
        key = calculate_key(self)
        metadata = await get_metadata(key)
        if metadata:
            print(f"从元数据获取到 {self} 的信息")
            dependencies = metadata.split(",")
            for dep in dependencies:
                dep_key = calculate_key(dep)
                dep_metadata = await get_metadata(dep_key)
                if dep_metadata:
                    dep_package = eval(dep_metadata)
                    await dep_package.install()
            if self.package_manager == "dpkg":
                print(f"使用 dpkg 安装 {self}")
                os.system(f"dpkg -i {self.content}")
            elif self.package_manager == "rpm":
                print(f"使用 rpm 安装 {self}")
                os.system(f"rpm -i {self.content}")
        else:
            print(f"元数据中没有 {self} 的信息")

    async def uninstall(self):
        if self.package_manager == "dpkg":
            print(f"使用 dpkg 卸载 {self}")
            os.system(f"dpkg -r {self.name}")
        elif self.package_manager == "rpm":
            print(f"使用 rpm 卸载 {self}")
            os.system(f"rpm -e {self.name}")


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

class Domain:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.subdomains = []
        self.trust_sources = []

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

# 创建软件包
package1 = Package("dcpm", "1.0.0", "Content of dcpm 1.0.0", "dpkg")
package2 = Package("dcpm", "1.1.0", "Content of dcpm 1.1.0", "rpm")

# 将软件包添加到信任源
self_source.add_package(package1)
anthropic_source.add_package(package2)
sub_source.add_package(package1)
"""

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
        genesis_block = BlockHeader(0, 0, "0"*64, "0"*64)
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
            prev_header = self.chain[i-1]
            
            # 验证区块头的哈希值
            if current_header.calculate_hash() != current_header.hash:
                return False
            
            # 验证前一个区块头的哈希值
            if current_header.prev_hash != prev_header.hash:
                return False
        
        return True