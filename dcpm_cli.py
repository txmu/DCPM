import argparse
import asyncio
from dcpm_core import Package
from dcpm_p2p import P2PNode
from dcpm_trust import public_key_pem, private_key_pem

def parse_args():
    parser = argparse.ArgumentParser(description="DCPM - 去中心化的 Linux 包管理器")
    parser.add_argument("-p", "--publish", metavar="PACKAGE", help="发布软件包到网络")
    parser.add_argument("-d", "--download", metavar="PACKAGE_ID", help="从网络下载软件包")
    parser.add_argument("-i", "--install", metavar="PACKAGE", help="安装本地软件包")
    parser.add_argument("-r", "--remove", metavar="PACKAGE", help="卸载本地软件包")
    return parser.parse_args()

async def main():
    args = parse_args()
    node = P2PNode("0.0.0.0", 9000, public_key_pem, private_key_pem)
    await node.start()

    if args.publish:
        package_path = args.publish
        package = Package.from_file(package_path)
        await node.publish_package(package)

    elif args.download:
        package_id = args.download
        package = await node.download_package(package_id)
        if package:
            package.save_to_file()

    elif args.install:
        package_path = args.install
        package = Package.from_file(package_path)
        await package.install()

    elif args.remove:
        package_name = args.remove
        await Package.uninstall(package_name)

if __name__ == "__main__":
    asyncio.run(main())