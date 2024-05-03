# dcpm_p2p.py

import random
import struct
from collections import defaultdict
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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


class EncryptedConnection:
    def __init__(self, reader, writer, session_key):
        self.reader = reader
        self.writer = writer
        self.cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce=b"\x00" * 16))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    async def read(self, n=-1):
        # 读取并解密数据
        data = await self.reader.read(n)
        return self.decryptor.update(data) + self.decryptor.finalize()

    async def write(self, data):
        # 加密并发送数据
        encrypted_data = self.encryptor.update(data) + self.encryptor.finalize()
        self.writer.write(encrypted_data)
        await self.writer.drain()

    async def open_connection(self, host, port):
        # 打开与目标节点的连接
        conn = await asyncio.open_connection(host, port)
        return EncryptedConnection(conn.reader, conn.writer, self.session_key)

    async def open_tunnel(self, host, port):
        # 打开与目标节点的隧道连接
        conn = await self.writer.open_tunnel(host, port)
        return EncryptedConnection(conn.reader, conn.writer, self.session_key)

    async def create_encrypted_connection(host, port, public_key):
        # 建立 TLS/SSL 加密连接
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile="path/to/cert.pem", keyfile="path/to/key.pem")
        conn = await asyncio.open_connection(host, port, ssl=context)
        reader, writer = conn

        # 协商会话密钥
        session_key = await negotiate_session_key(reader, writer, public_key)

        return EncryptedConnection(reader, writer, session_key)

    async def negotiate_session_key(reader, writer, public_key):
        # 生成会话密钥
        session_key = os.urandom(32)

        # 加密会话密钥
        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 发送加密的会话密钥
        writer.write(struct.pack(">H", len(encrypted_key)) + encrypted_key)
        await writer.drain()

        # 等待确认
        response = await reader.read(2)
        if response != b"\x00\x00":
            raise Exception("Session key negotiation failed")

        return session_key


class ProxyNode:
    def __init__(self, node_id, host, port, public_key):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.public_key = public_key
        self.load = 0  # 节点负载
        self.last_used = 0  # 上次使用时间


class TunnelNode:
    def __init__(self, node_id, host, port, public_key):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.public_key = public_key
        self.load = 0  # 节点负载
        self.last_used = 0  # 上次使用时间


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
        self.proxy_nodes = {}
        self.proxy_stream_handlers = {}
        self.tunnel_nodes = {}
        self.tunnel_stream_handlers = {}
        self.proxy_threshold = 0.8
        self.tunnel_threshold = 0.8
        self.private_key_pem = private_key_pem
        self.use_proxy = False  # 默认不启用代理
        self.use_tunnel = False  # 默认不启用隧道
        self.connection_attempts = 0  # 连接尝试次数
        self.max_connection_attempts = 3  # 最大连接尝试次数

    # 代理和隧道节点负载均衡算法
    def select_proxy_node(self):
        # 根据负载、距离和随机性选择代理节点
        available_nodes = [
            node
            for node in self.proxy_nodes.values()
            if node.load < self.proxy_threshold
        ]
        if not available_nodes:
            return None
        return random.choice(available_nodes)

    def select_tunnel_node(self, target_node):
        # 根据负载、距离和随机性选择隧道节点
        available_nodes = [
            node
            for node in self.tunnel_nodes.values()
            if node.load < self.tunnel_threshold
        ]
        if not available_nodes:
            return None
        return min(
            available_nodes, key=lambda node: calculate_distance(node, target_node)
        )

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

    async def handle_stream(self, stream):
        peer_id = stream.remotePeer().prettyPeerID()
        try:
            if self.use_proxy and peer_id in self.proxy_nodes:
                await self.handle_proxy_stream(stream, peer_id)
            elif self.use_tunnel and peer_id in self.tunnel_nodes:
                await self.handle_tunnel_stream(stream, peer_id)
            else:
                await self.handle_direct_stream(stream)
        except Exception as e:
            print(f"Error handling stream from {peer_id}: {e}")
            stream.reset()

    # 代理和隧道连接函数
    async def connect_via_proxy(self, proxy_node):
        # 通过代理节点连接到 DCPM 网络
        conn = await create_encrypted_connection(
            proxy_node.host, proxy_node.port, proxy_node.public_key
        )
        stream_handler = self.handle_proxy_stream(conn)
        self.proxy_stream_handlers[proxy_node.node_id] = stream_handler

    async def connect_via_tunnel(self, tunnel_node, target_node):
        # 通过隧道节点连接到目标节点
        conn = await create_encrypted_connection(
            tunnel_node.host, tunnel_node.port, tunnel_node.public_key
        )
        stream_handler = self.handle_tunnel_stream(conn, target_node)
        self.tunnel_stream_handlers[tunnel_node.node_id] = stream_handler

    async def handle_proxy_stream(self, stream, peer_id):
        proxy_node = self.proxy_nodes[peer_id]
        conn = await create_encrypted_connection(
            proxy_node.host, proxy_node.port, proxy_node.public_key
        )
        while True:
            try:
                data = await stream.read()
                await conn.write(data)
                response = await conn.read()
                await stream.write(response)
            except Exception as e:
                print(f"Error handling proxy stream from {peer_id}: {e}")
                break

    async def handle_tunnel_stream(self, stream, peer_id):
        tunnel_node = self.tunnel_nodes[peer_id]
        target_node_id = await stream.read(32)
        target_node = self.dht.routing_table.get_node(target_node_id)
        if target_node:
            conn = await create_encrypted_connection(
                tunnel_node.host, tunnel_node.port, tunnel_node.public_key
            )
            await conn.open_tunnel(target_node.host, target_node.port)
            while True:
                try:
                    data = await stream.read()
                    await conn.write(data)
                    response = await conn.read()
                    await stream.write(response)
                except Exception as e:
                    print(f"Error handling tunnel stream from {peer_id}: {e}")
                    break
        else:
            print(f"Target node {target_node_id} not found")
            stream.reset()

    async def handle_direct_stream(self, stream):
        peer_id = stream.remotePeer().prettyPeerID()
        while True:
            try:
                # 读取请求数据
                request_data = await stream.read()
                request_type = request_data[0]

                if request_type == 0:  # 发布软件包
                    package_data = request_data[1:]
                    package = Package.from_bytes(package_data)
                    await package.publish()
                    response = b"\x00"  # 发布成功

                elif request_type == 1:  # 下载软件包
                    package_id = request_data[1:].decode()
                    package = await Package.download(package_id)
                    if package:
                        response = b"\x01" + package.to_bytes()
                    else:
                        response = b"\x00"  # 下载失败

                elif request_type == 2:  # 安装软件包
                    package_data = request_data[1:]
                    package = Package.from_bytes(package_data)
                    await package.install()
                    response = b"\x02"  # 安装成功

                elif request_type == 3:  # 卸载软件包
                    package_name = request_data[1:].decode()
                    await Package.uninstall(package_name)
                    response = b"\x03"  # 卸载成功

                else:
                    response = b"\x00"  # 未知请求类型

                # 发送响应数据
                await stream.write(response)

            except Exception as e:
                print(f"Error handling direct stream from {peer_id}: {e}")
                break

        stream.reset()

    async def discover_proxy_nodes(self):
        # 通过 DHT 查找代理节点
        proxy_nodes = await self.dht.get_providers("proxy")
        for node_id, addrs in proxy_nodes.items():
            host, port = addrs[0]
            public_key = await self.dht.get_public_key(node_id)
            self.proxy_nodes[node_id] = ProxyNode(node_id, host, port, public_key)

    async def discover_tunnel_nodes(self):
        # 通过 DHT 查找隧道节点
        tunnel_nodes = await self.dht.get_providers("tunnel")
        for node_id, addrs in tunnel_nodes.items():
            host, port = addrs[0]
            public_key = await self.dht.get_public_key(node_id)
            self.tunnel_nodes[node_id] = TunnelNode(node_id, host, port, public_key)

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

    async def publish_package_via_proxy_or_tunnel(self, package):
        try:
            await super().publish_package(package)
        except Exception as e:
            self.connection_attempts += 1
            if self.connection_attempts >= self.max_connection_attempts:
                if self.use_proxy:
                    print("Failed to publish package via proxy, trying tunnel")
                    self.use_proxy = False
                    self.use_tunnel = True
                    self.connection_attempts = 0
                else:
                    print("Failed to publish package via tunnel, enabling proxy")
                    self.use_proxy = True
                    self.use_tunnel = False
                    self.connection_attempts = 0
            await self.publish_package(package)

    async def download_package_via_proxy_or_tunnel(self, package_id):
        try:
            package = await super().download_package(package_id)
        except Exception as e:
            self.connection_attempts += 1
            if self.connection_attempts >= self.max_connection_attempts:
                if self.use_proxy:
                    print("Failed to download package via proxy, trying tunnel")
                    self.use_proxy = False
                    self.use_tunnel = True
                    self.connection_attempts = 0
                else:
                    print("Failed to download package via tunnel, enabling proxy")
                    self.use_proxy = True
                    self.use_tunnel = False
                    self.connection_attempts = 0
            package = await self.download_package(package_id)

        return package

    # 其他方法保持不变

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

    async def send_request(self, request_data):
        """发送请求并等待响应"""
        # 连接到随机节点
        target_node = random.choice(list(self.dht.routing_table.get_nodes()))
        reader, writer = await asyncio.open_connection(
            target_node.host, target_node.port
        )

        # 发送请求数据
        writer.write(request_data)
        await writer.drain()

        # 等待响应数据
        response_data = await reader.read()

        # 关闭连接
        writer.close()
        await writer.wait_closed()

        return response_data

    async def send_publish_request(self, package):
        """发送发布软件包请求"""
        request_data = b"\x00" + package.to_bytes()
        await self.send_request(request_data)

    async def send_download_request(self, package_id):
        """发送下载软件包请求"""
        request_data = b"\x01" + package_id.encode()
        response = await self.send_request(request_data)
        if response[0] == 1:
            package_data = response[1:]
            package = Package.from_bytes(package_data)
            return package
        else:
            return None

    async def send_install_request(self, package):
        """发送安装软件包请求"""
        request_data = b"\x02" + package.to_bytes()
        response = await self.send_request(request_data)
        return response[0] == 2

    async def send_uninstall_request(self, package_name):
        """发送卸载软件包请求"""
        request_data = b"\x03" + package_name.encode()
        response = await self.send_request(request_data)
        return response[0] == 3
