# dcpm_p2p.py

import asyncio
import aiohttp
import hashlib
import libp2p
from libp2p.crypto.rsa import KeyPair
from libp2p.peer.peerinfo import PeerInfo
from libp2p.transport.tcp.tcp import TCP
from libp2p.stream_muxer.mplex import Mplex
from libp2p.security.secio import SecIO
from libp2p.host.basic_host import BasicHost
from libp2p.routing.kademlia_dht import KademliaDHT
from libp2p.discovery.mdns import MulticastDNSService
from dcpm_core import Package, get_package_id, calculate_checksums
import dnscrypt_python


# TLS支持
import ssl
from OpenSSL import SSL, crypto
import libtls
import wolfcrypt.tls

# 流量统计和限制
from collections import defaultdict
import time


class P2PNode:
    def __init__(
        self, host, port, public_key_pem, private_key_pem, tls_cert=None, tls_key=None
    ):
        self.host = host
        self.port = port
        self.public_key_pem = public_key_pem
        self.private_key_pem = private_key_pem
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.packages = {}
        self.blockchain = Blockchain()
        self.node = None
        self.dht = None
        self.traffic_stats = defaultdict(int)  # 流量统计
        self.traffic_threshold = 1024 * 1024 * 1024  # 流量阈值 1GB
        self.traffic_reset_time = time.time() + 1800  # 每半小时重置流量统计
        self.download_progress = defaultdict(lambda: defaultdict(int))  # 下载进度

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

        # 启用OpenTLS支持
        if self.tls_cert and self.tls_key:
            ssl_context = self.create_opentls_context()
            self.node.set_stream_handler("/tls/1.0.0", self.handle_tls_stream)

        # 启用DNSCrypt支持
        dnscrypt_client = dnscrypt_python.init_client_with_system_resolver()
        self.node.set_stream_handler("/dnscrypt/1.0.0", self.handle_dnscrypt_stream)

    def create_opentls_context(self):
        # OpenTLS
        openssl_context = SSL.Context(SSL.TLSv1_2_METHOD)
        openssl_context.use_certificate_file(self.tls_cert)
        openssl_context.use_privatekey_file(self.tls_key)

        return openssl_context

    def create_libretls_context(self):
        # LibreTLS
        libtls_context = libtls.create_context(libtls.client_mode)
        libtls_context.load_client_ca_file(cert_file)
        libtls_context.load_client_keypair(cert_file, key_file)
        return libtls_context

    def create_wolftls_context(self):
        # WolfTLS
        wolfcrypt_context = wolfcrypt.tls.create_context()
        wolfcrypt_context.load_cert_chain(cert_file)
        wolfcrypt_context.load_private_key(key_file)
        return wolfcrypt_context

    # 根据需要返回不同的TLS上下文

    # 支持LibreTLS和WolfTLS，但默认不启用。
    # 默认使用OpenTLS，如需要使用LibreTLS或WolfTLS，请自行修改该文件，并测试。
    # DCPM社区将欢迎相关技术问题的交流。

    async def handle_tls_stream(self, stream):
        # 处理TLS加密流
        peer_id = stream.remotePeer().prettyPeerID()
        if self.check_traffic_limit(peer_id):
            ssl_context = self.create_opentls_context()
            tls_stream = await stream.newTLSStream(ssl_context)
            self.node.addStreamHandler(tls_stream, self.handle_tls_stream_data)
        else:
            stream.reset()

    async def handle_tls_stream_data(self, stream):
        peer_id = stream.remotePeer().prettyPeerID()
        try:
            data = await stream.read()
            self.update_traffic_stats(peer_id, len(data))
            # 处理接收到的数据
            response = process_data(data)
            await stream.write(response)
        except Exception as e:
            print(f"Error handling TLS stream data from {peer_id}: {e}")

    async def handle_dnscrypt_stream(self, stream):
        # 处理DNSCrypt流
        peer_id = stream.remotePeer().prettyPeerID()
        if self.check_traffic_limit(peer_id):
            dnscrypt_client = dnscrypt_python.init_client_with_system_resolver()
            dnscrypt_stream = await stream.newDNSCryptStream(dnscrypt_client)
            self.node.addStreamHandler(
                dnscrypt_stream, self.handle_dnscrypt_stream_data
            )
        else:
            stream.reset()

    async def handle_dnscrypt_stream_data(self, stream):
        peer_id = stream.remotePeer().prettyPeerID()
        try:
            data = await stream.read()
            self.update_traffic_stats(peer_id, len(data))
            # 处理接收到的数据
            response = process_data(data)
            await stream.write(response)
        except Exception as e:
            print(f"Error handling DNSCrypt stream data from {peer_id}: {e}")

    def check_traffic_limit(self, peer_id):
        if time.time() > self.traffic_reset_time:
            self.traffic_stats.clear()
            self.traffic_reset_time = time.time() + 1800
        if self.traffic_stats[peer_id] > self.traffic_threshold:
            return False
        return True

    def update_traffic_stats(self, peer_id, data_len):
        self.traffic_stats[peer_id] += data_len

    async def publish_package(self, package):
        """发布软件包到网络"""
        package_id = get_package_id(package.name, package.source)
        package_data = {
            "name": package.name,
            "version": package.version,
            "package_manager": package.package_manager,
            "dependencies": package.dependencies,
            "files": {},
            "checksums": {},
            "signature": sign_data(str(package), self.private_key_pem),
        }

        for file_path, file_data in package.files.items():
            file_id = hashlib.sha256(f"{package_id}:{file_path}".encode()).hexdigest()
            block_hashes = await self.dht.put_file(file_id, file_data)
            checksums = calculate_checksums(file_data)
            package_data["files"][file_path] = {
                "id": file_id,
                "size": len(file_data),
                "block_hashes": block_hashes,
                "checksums": checksums,
            }
            package_data["checksums"][file_path] = checksums

        # 将软件包元数据添加到区块链
        self.blockchain.add_data(str(package_data))
        await self.blockchain.mine_block()

        # 将软件包元数据存储到DHT
        await self.dht.put(package_id, str(package_data))

        # 将软件包内容分块并存储到DHT
        package_content = package.content.encode()
        block_size = 1024 * 1024  # 1MB
        for i in range(0, len(package_content), block_size):
            block = package_content[i : i + block_size]
            block_id = hashlib.sha256(block).hexdigest()
            await self.dht.set(block_id, block)

    async def download_file(self, file_id, block_hashes):
        """从DHT下载文件,支持断点续传"""
        file_data = b""
        downloaded_blocks = set()
        for block_hash in block_hashes:
            if block_hash not in self.download_progress[file_id]:
                block_data = await self.dht.get_block(block_hash)
                if block_data:
                    file_data += block_data
                    self.download_progress[file_id][block_hash] = len(block_data)
                    downloaded_blocks.add(block_hash)
                else:
                    print(f"无法下载数据块 {block_hash}")
                    break
            else:
                file_data += self.download_progress[file_id][block_hash]
                downloaded_blocks.add(block_hash)

        if len(downloaded_blocks) == len(block_hashes):
            return file_data
        else:
            # 重新下载未完成的块
            for block_hash in set(block_hashes) - downloaded_blocks:
                block_data = await self.dht.get_block(block_hash)
                if block_data:
                    file_data += block_data
                    self.download_progress[file_id][block_hash] = len(block_data)
                else:
                    print(f"无法下载数据块 {block_hash}")
                    return None

            return file_data

    async def download_package_content(self, package_data):
        """下载软件包内容,支持断点续传"""
        package_content = b""
        downloaded_blocks = set()
        block_size = 1024 * 1024  # 1MB
        package_content_str = package_data["content"]
        block_hashes = [
            hashlib.sha256(package_content_str[i : i + block_size].encode()).hexdigest()
            for i in range(0, len(package_content_str), block_size)
        ]

        for block_hash in block_hashes:
            if block_hash not in self.download_progress[package_data["id"]]:
                block_data = await self.dht.get_block(block_hash)
                if block_data:
                    package_content += block_data
                    self.download_progress[package_data["id"]][block_hash] = len(
                        block_data
                    )
                    downloaded_blocks.add(block_hash)
                else:
                    print(f"无法下载数据块 {block_hash}")
                    break
            else:
                package_content += self.download_progress[package_data["id"]][
                    block_hash
                ]
                downloaded_blocks.add(block_hash)

        if len(downloaded_blocks) == len(block_hashes):
            return package_content
        else:
            # 重新下载未完成的块
            for block_hash in set(block_hashes) - downloaded_blocks:
                block_data = await self.dht.get_block(block_hash)
                if block_data:
                    package_content += block_data
                    self.download_progress[package_data["id"]][block_hash] = len(
                        block_data
                    )
                else:
                    print(f"无法下载数据块 {block_hash}")
                    return None

            return package_content

    async def download_package(self, package_id):
        """从网络下载软件包,支持分块与断点续传"""
        package_data_str = await self.dht.get(package_id)
        if package_data_str:
            package_data = eval(package_data_str)

            # 验证软件包签名
            public_key = serialization.load_pem_public_key(self.public_key_pem)
            if not verify_signature(
                str(package_data), package_data["signature"], public_key
            ):
                print("软件包签名验证失败")
                return

            # 下载软件包内容
            package_content = await self.download_package_content(package_data)
            if not package_content:
                print("无法下载软件包内容")
                return

            # 下载软件包文件
            self.packages[package_id] = {}
            for file_path, file_meta in package_data["files"].items():
                file_id = file_meta["id"]
                block_hashes = file_meta["block_hashes"]
                file_data = await self.download_file(file_id, block_hashes)
                if file_data:
                    self.packages[package_id][file_path] = file_data
                else:
                    print(f"无法下载文件 {file_path}")
                    return

            # 验证文件校验和
            for file_path, checksums in package_data["checksums"].items():
                if checksums != calculate_checksums(
                    self.packages[package_id][file_path]
                ):
                    print(f"文件 {file_path} 校验和不匹配")
                    return

            # 验证区块链上的软件包元数据
            if not await self.validate_package_metadata(package_data):
                print("软件包元数据验证失败")
                return

            # 创建软件包对象
            package = Package(
                package_data["name"],
                package_data["version"],
                package_content.decode(),
                self.packages[package_id],
                package_data["package_manager"],
                package_data["dependencies"],
            )

            return package
        else:
            print(f"无法找到软件包 {package_id}")
            return None

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
                    if verify_signature(
                        package_data_str, package_signature, public_key
                    ):
                        return True
        return False
