# dcpm_utils.py

import asyncio
from collections import defaultdict
from dcpm_core import get_software_id, get_package_id, get_version_id, Package


class DependencyResolver:
    def __init__(self, packages):
        self.packages = packages
        self.dependencies = defaultdict(list)
        self.resolved = defaultdict(list)

        for package in packages:
            self.dependencies[package.software_id].append(package)

    async def resolve(self):
        tasks = [self.resolve_package(package) for package in self.packages]
        await asyncio.gather(*tasks)
        return self.resolved

    async def resolve_package(self, package):
        if package.software_id in self.resolved:
            return

        for dep_id in package.dependencies:
            for dep_package in self.dependencies[dep_id]:
                await self.resolve_package(dep_package)

        self.resolved[package.software_id].append(package)


class PackageVersion:
    def __init__(
        self, name, source, version, content, package_manager, parent_version=None
    ):
        self.software_id = get_software_id(name)
        self.package_id = get_package_id(name, source)
        self.version_id = get_version_id(name, source, version, parent_version)
        self.name = name
        self.version = version
        self.content = content
        self.package_manager = package_manager
        self.parent_version = parent_version
        self.children = []
        self.forks = []

    def __str__(self):
        return f"{self.name}-{self.version} ({self.version_id})"

    def __repr__(self):
        return f"PackageVersion('{self.name}', '{self.source}', '{self.version}', '{self.content}', '{self.package_manager}', parent_version={self.parent_version})"

    async def fork(self, new_source, new_version, new_content=None):
        forked_version = PackageVersion(
            self.name,
            new_source,
            new_version,
            new_content or self.content,
            self.package_manager,
            parent_version=self,
        )
        self.forks.append(forked_version)
        return forked_version

    async def branch(self, new_version, new_content=None):
        branched_version = PackageVersion(
            self.name,
            self.source,
            new_version,
            new_content or self.content,
            self.package_manager,
            parent_version=self,
        )
        self.children.append(branched_version)
        return branched_version

    async def revert(self):
        if self.parent_version:
            return self.parent_version
        else:
            print(
                f"Cannot revert {self.name}-{self.version} as it has no parent version."
            )
            return None


class PackageVersionManager:
    def __init__(self):
        self.packages = {}

    def add_package(self, package):
        self.packages[package.software_id] = package

    def get_package(self, software_id):
        return self.packages.get(software_id)

    def get_version(self, software_id, version_id):
        package = self.get_package(software_id)
        if package:
            for version in package.versions:
                if version.version_id == version_id:
                    return version
        return None

    async def resolve_dependencies(self, packages):
        resolver = DependencyResolver(packages)
        resolved = await resolver.resolve()
        for software_id, package_versions in resolved.items():
            self.packages[software_id] = package_versions

    async def install(self, software_id, version_id=None):
        package = self.get_package(software_id)
        if package:
            if version_id:
                version = self.get_version(software_id, version_id)
                if version:
                    await version.install()
                else:
                    print(f"Version {version_id} not found for package {software_id}")
            else:
                latest_version = max(package.versions, key=lambda v: v.version)
                await latest_version.install()
        else:
            print(f"Package {software_id} not found")

    async def uninstall(self, software_id, version_id=None):
        package = self.get_package(software_id)
        if package:
            if version_id:
                version = self.get_version(software_id, version_id)
                if version:
                    await version.uninstall()
                else:
                    print(f"Version {version_id} not found for package {software_id}")
            else:
                for version in package.versions:
                    await version.uninstall()
        else:
            print(f"Package {software_id} not found")
