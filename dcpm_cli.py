# dcpm_cli.py


import argparse
import asyncio
from dcpm_core import Package
from dcpm_p2p import P2PNode
from dcpm_trust import public_key_pem, private_key_pem
from dcpm_utils import PackageVersionManager, DependencyResolver


def parse_args():
    parser = argparse.ArgumentParser(description="DCPM - 去中心化的 Linux 包管理器")
    parser.add_argument("-p", "--publish", metavar="PACKAGE", help="发布软件包到网络")
    parser.add_argument("-d", "--download", metavar="PACKAGE_ID", help="从网络下载软件包")
    parser.add_argument("-i", "--install", metavar="PACKAGE", help="安装本地软件包")
    parser.add_argument("-r", "--remove", metavar="PACKAGE", help="卸载本地软件包")
    parser.add_argument("--tls-cert", help="TLS证书文件路径")
    parser.add_argument("--tls-key", help="TLS密钥文件路径")
    parser.add_argument(
        "--dep-mode",
        choices=["none", "suggest", "auto"],
        default="none",
        help="依赖解决模式: none - 不解决依赖; suggest - 输出依赖解决建议; auto - 自动解决依赖",
    )
    parser.add_argument("--fork", metavar="PACKAGE_ID", help="为指定软件包创建新的分支或版本")
    parser.add_argument("--branch", metavar="PACKAGE_ID", help="为指定软件包创建新的分支")
    parser.add_argument("--revert", metavar="PACKAGE_ID", help="恢复指定软件包到上一个版本")
    return parser.parse_args()


async def main():
    # ... 其他代码保持不变 ...
    args = parse_args()
    tls_cert = args.tls_cert
    tls_key = args.tls_key
    node = P2PNode("0.0.0.0", 9000, public_key_pem, private_key_pem, tls_cert, tls_key)
    await node.start()

    package_version_manager = PackageVersionManager()
    
    
    if args.publish:
        package_path = args.publish
        package = Package.from_file(package_path)
        await node.send_publish_request(package)

    elif args.download:
        package_id = args.download
        package = await node.send_download_request(package_id)
        if package:
            package_version_manager.add_package(package)
            package.save_to_file()

    elif args.install:
        package_path = args.install
        package = Package.from_file(package_path)
        package_version_manager.add_package(package)

        if args.dep_mode == "suggest":
            # ... 依赖解决建议代码保持不变 ...
            resolver = DependencyResolver([package])
            resolved = await resolver.resolve()
            for software_id, package_versions in resolved.items():
                for package_version in package_versions:
                    print(
                        f"{package_version.name} ({package_version.version_id}) - [{package_version.software_id}, {package_version.package_id}, {package_version.version_id}]"
                    )
        elif args.dep_mode == "auto":
            await package_version_manager.resolve_dependencies([package])
            await node.send_install_request(package)
        else:
            await node.send_install_request(package)

    elif args.remove:
        package_name = args.remove
        software_id = get_software_id(package_name)
        package = package_version_manager.get_package(software_id)

        if package:
            if args.dep_mode == "suggest":
                # ... 依赖解决建议代码保持不变 ...
                resolver = DependencyResolver(package.versions)
                resolved = await resolver.resolve()
                for software_id, package_versions in resolved.items():
                    for package_version in package_versions:
                        print(
                            f"{package_version.name} ({package_version.version_id}) - [{package_version.software_id}, {package_version.package_id}, {package_version.version_id}]"
                        )
            elif args.dep_mode == "auto":
                await package_version_manager.resolve_dependencies(package.versions)
                await node.send_uninstall_request(package_name)
            else:
                await node.send_uninstall_request(package_name)
        else:
            print(f"无法找到软件包 {package_name}")

    # ... 其他代码保持不变 ...
    elif args.fork:
        package_id = args.fork
        package = package_version_manager.get_package(package_id)
        if package:
            latest_version = max(package.versions, key=lambda v: v.version)
            forked_version = await latest_version.fork("NEW_SOURCE", "1.0.0")
            package_version_manager.add_package(forked_version)
            print(f"已创建新分支: {forked_version}")
        else:
            print(f"无法找到软件包 {package_id}")

    elif args.branch:
        package_id = args.branch
        package = package_version_manager.get_package(package_id)
        if package:
            latest_version = max(package.versions, key=lambda v: v.version)
            branched_version = await latest_version.branch("1.1.0")
            package_version_manager.add_package(branched_version)
            print(f"已创建新分支: {branched_version}")
        else:
            print(f"无法找到软件包 {package_id}")

    elif args.revert:
        package_id = args.revert
        package = package_version_manager.get_package(package_id)
        if package:
            latest_version = max(package.versions, key=lambda v: v.version)
            reverted_version = await latest_version.revert()
            if reverted_version:
                print(f"已恢复到上一个版本: {reverted_version}")
            else:
                print(f"无法恢复软件包 {package_id}")
        else:
            print(f"无法找到软件包 {package_id}")


if __name__ == "__main__":
    asyncio.run(main())
