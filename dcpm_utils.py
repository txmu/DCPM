import asyncio
from collections import defaultdict
from dcpm_core import get_software_id, Package

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
    def __init__(self, name, source, version, content, package_manager, parent_version=None):
        self.software_id = get_software_id(name)
        self.package_id = get_package_id(name, source)
        self.version_id = get_version_id(name, source, version, parent_version)
        self.name = name
        self.version = version
        self.content = content
        self.package_manager = package_manager
        self.parent_version = parent_version

    def __str__(self):
        return f"{self.name}-{self.version} ({self.version_id})"

    def __repr__(self):
        return f"PackageVersion('{self.name}', '{self.source}', '{self.version}', '{self.content}', '{self.package_manager}', parent_version={self.parent_version})"