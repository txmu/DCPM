import asyncio
import aiohttp
import libp2p
from libp2p.crypto.rsa import KeyPair
from libp2p.peer.peerinfo import PeerInfo
from libp2p.transport.tcp.tcp import TCP
from libp2p.stream_muxer.mplex import Mplex
from libp2p.security.secio import SecIO
from libp2p.host.basic_host import BasicHost
from libp2p.routing.kademlia_dht import KademliaDHT
from libp2p.discovery.mdns import MulticastDNSService
from dcpm_core import Package

class P2PNode:
    def __init__(self, host, port, public_key_pem, private_key_pem):
        self.host = host
        self.port = port
        self.public_key_pem = public_key_pem
        self.private_key_pem = private_key_pem
        self.packages = {}  # 本地软件包存储
        self.blockchain = Blockchain()  # 区块链实例
        self.node = None  # libp2p节点实例
        self.dht = None  # 分布式哈希表实例

    async def start(self):
        # 创建libp2p节点实例
        rsa_key_pair = KeyPair.from_bytes(self.private_key_pem, self.public_key_pem)
        peer_info = PeerInfo(rsa_key_pair.public_key)
        transports = [TCP(self.host, self.port)]
        muxer = Mplex()
        security = SecIO(rsa_key_pair)
        self.node = BasicHost(peer_info, transports, muxer, security)

        # 启动P2P网络节点
        await self.node.start()

        # 创建分布式哈希表实例
        self.dht = KademliaDHT(self.node)
        await self.dht.start()

        # 启动节点发现服务
        service = MulticastDNSService(self.node)
        await service.start()

    async def publish_package(self, package):
        """发布软件包到网络"""
        package_id = get_package_id(package.name, package.source)
        package_data = {
            "name": package.name,
            "version": package.version,
            "content": package.content,
            "package_manager": package.package_manager,
            "dependencies": package.dependencies,
            "signature": sign_data(str(package), self.private_key_pem)
        }

        # 将软件包元数据添加到区块链
        self.blockchain.add_data(str(package_data))
        await self.blockchain.mine_block()

        # 将软件包元数据存储到DHT
        await self.dht.set(package_id, str(package_data))

        # 将软件包内容分块并存储到DHT
        package_content = package.content.encode()
        block_size = 1024 * 1024  # 1MB
        for i in range(0, len(package_content), block_size):
            block = package_content[i:i+block_size]
            block_id = hashlib.sha256(block).hexdigest()
            await self.dht.set(block_id, block)

    async def download_package(self, package_id):
        """从网络下载软件包"""
        package_data_str = await self.dht.get(package_id)
        if package_data_str:
            package_data = eval(package_data_str)

            # 验证软件包签名
            public_key = serialization.load_pem_public_key(self.public_key_pem)
            if not verify_signature(str(package_data), package_data["signature"], public_key):
                print("软件包签名验证失败")
                return

            # 下载软件包内容
            package_content = b""
            for dep_id in package_data["dependencies"]:
                dep_package_id = get_package_id(dep_id, package_data["source"])
                dep_package_data_str = await self.dht.get(dep_package_id)
                if dep_package_data_str:
                    dep_package_data = eval(dep_package_data_str)
                    dep_package_content = await self.download_package_content(dep_package_data)
                    package_content += dep_package_content
                else:
                    print(f"无法找到依赖软件包 {dep_id}")
                    return

            package_content += await self.download_package_content(package_data)

            # 创建软件包对象
            package = Package(
                package_data["name"],
                package_data["version"],
                package_content.decode(),
                package_data["package_manager"],
                package_data["dependencies"]
            )

            # 验证区块链上的软件包元数据
            if not await self.validate_package_metadata(package):
                print("软件包元数据验证失败")
                return

            return package
        else:
            print(f"无法找到软件包 {package_id}")
            return None

    async def download_package_content(self, package_data):
        """下载软件包内容"""
        package_content = b""
        block_ids = []
        package_content_str = package_data["content"]
        block_size = 1024 * 1024  # 1MB
        for i in range(0, len(package_content_str), block_size):
            block = package_content_str[i:i+block_size].encode()
            block_id = hashlib.sha256(block).hexdigest()
            block_ids.append(block_id)

        for block_id in block_ids:
            block_data = await self.dht.get(block_id)
            if block_data:
                package_content += block_data
            else:
                print(f"无法找到数据块 {block_id}")
                return b""

        return package_content

    async def validate_package_metadata(self, package):
        """验证软件包元数据是否存在于区块链上"""
        package_data = {
            "name": package.name,
            "version": package.version,
            "content": package.content,
            "package_manager": package.package_manager,
            "dependencies": package.dependencies,
        }
        package_data_str = str(package_data)
        package_signature = sign_data(package_data_str, self.private_key_pem)

        for block in self.blockchain.chain:
            if block.data_hash == hashlib.sha256(package_data_str.encode()).hexdigest():
                if block.index == 0:
                    return False  # 创世区块不应该包含软件包元数据
                prev_block = self.blockchain.chain[block.index - 1]
                if prev_block.hash == block.prev_hash:
                    # 验证软件包签名
                    public_key = serialization.load_pem_public_key(self.public_key_pem)
                    if verify_signature(package_data_str, package_signature, public_key):
                        return True
        return False