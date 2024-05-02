# dcpm_poolmemory.py

# 第三代内存的第二代内存（非官方称呼：第五代内存）。代号：L

import zlib
import pickle
from cryptography.fernet import Fernet
import threading

# 共享内存池。该版本极旧，是从P内存（第二代内存）传下来的，仅作兼容考虑。更推荐手动使用SharedMemoryPool类或者修改get_memory，使其支持SharedMemoryPool类。下一个版本中，旧的共享内存池将不再被支持。此外，相比于手动通过get_memory来获取内存，更推荐使用SharedMemoryPool类，因为它附带完整的权限系统和更多功能
shared_memory_pool = []

PERMISSIONS_MAP = {
    "r": "读权限",
    "w": "写权限",
    "x": "执行权限",
    "s": "共享权限",
    "u": "取消共享权限",
    "e": "清空权限",
    "p": "页面所有权",
}

"""
文字说明：
PERMISSIONS_MAP = {
  'r': '允许读取segment的数据，但只能手动',
  'w': '允许修改segment的数据，但只能手动',
  'x': '允许调用会操作这个segment的函数，权限范围为该user的权限',
  's': '允许共享这个segment给其他用户,且只可共享自己对该segment的真子集权限',
  'u': '允许取消共享这个segment',
  'e': '允许清空这个segment的数据',
  'p': '允许取代None，成为这个segment所有页面的owner' 
}
"""


def parse_permissions(perm_str):
    # 校验格式
    if not re.match(r"^[rwxsuep-]{7}$", perm_str):
        raise ValueError("Invalid permission string")

    permissions = {}

    # 解析读权限
    if perm_str[0] == "r":
        permissions["can_read_data"] = True
        permissions["can_read_meta"] = True
        permissions["can_read_stats"] = True
        permissions["can_read_config"] = True
    else:
        permissions["can_read_data"] = False
        permissions["can_read_meta"] = False
        permissions["can_read_stats"] = False
        permissions["can_read_config"] = False

    # 解析写权限
    if perm_str[1] == "w":
        permissions["can_write_data"] = True
        permissions["can_write_meta"] = True
        permissions["can_resize"] = True
    else:
        permissions["can_write_data"] = False
        permissions["can_write_meta"] = False
        permissions["can_resize"] = False

    # 执行权限
    if perm_str[2] == "x":
        permissions["can_call_rw_api"] = True
        permissions["can_call_stats_api"] = True
        permissions["can_call_config_api"] = True
        permissions["can_access_memory"] = True
    else:
        permissions["can_call_rw_api"] = False
        permissions["can_call_stats_api"] = False
        permissions["can_call_config_api"] = False
        permissions["can_access_memory"] = False

    # 共享权限
    if perm_str[3] == "s":
        permissions["can_share"] = True
        permissions["shared_perm_subset"] = True
    else:
        permissions["can_share"] = False
        permissions["shared_perm_subset"] = False

    # 取消共享权限
    if perm_str[4] == "u":
        permissions["can_unshare_full"] = True
        permissions["can_unshare_partial"] = True
    else:
        permissions["can_unshare_full"] = False
        permissions["can_unshare_partial"] = False

    # 清空权限
    if perm_str[5] == "e":
        permissions["can_erase_data"] = True
        permissions["can_erase_meta"] = True
    else:
        permissions["can_erase_data"] = False
        permissions["can_erase_meta"] = False

    # 页面所有权
    if perm_str[6] == "p":
        permissions["can_own_pages"] = True
        permissions["can_direct_rw"] = True
    else:
        permissions["can_own_pages"] = False
        permissions["can_direct_rw"] = False

    return permissions


class User:
    def __init__(self, name):
        self.name = name


class Domain:
    def __init__(self, name):
        self.name = name
        self.users = []

    def add_user(self, user):
        if user not in self.users:
            self.users.append(user)

    def remove_user(self, user):
        if user in self.users:
            self.users.remove(user)


class Segment:
    def __init__(self, start, length, memory):
        self.start = start
        self.length = length
        self.memory = memory
        self.owner = None
        self.domain = None
        self.permissions = {}


class Page:
    def __init__(self, index, memory):
        self.index = index
        self.memory = memory
        self.owner = None


# 目前的Page类与PageTable类没有任何的关系。PageTable不依赖Page类，而是自己简易模拟了Page，功能被严重压缩，比如不存在Page owner这一概念。


class SegmentTable:
    def __init__(self):
        self.segments = []

    def allocate(self, length):
        # 找到合适的段进行分配
        for segment in self.segments:
            if segment.length >= length:
                allocated = Segment(segment.start, length, segment.memory)
                segment.start += length
                segment.length -= length
                return allocated
        # 没找到就新增一个段
        segment = Segment(0, length, Memory(length))
        self.segments.append(segment)
        return segment

    def free(self, segment):
        # 释放内存段时,合并相邻的空闲段
        index = self.segments.index(segment)
        if index > 0 and self.segments[index - 1].length == 0:
            prev = self.segments[index - 1]
            self.segments.remove(prev)
            segment.start = prev.start
            segment.length += prev.length
        if index < len(self.segments) - 1 and self.segments[index + 1].length == 0:
            next = self.segments[index + 1]
            self.segments.remove(next)
            segment.length += next.length


class PageTable:
    def __init__(self, memory):
        self.page_size = 256
        self.table = {}
        self.memory = memory

    def map(self, logical, physical):
        self.table[logical] = physical

    def unmap(self, logical):
        self.table.pop(logical)

    def translate(self, logical):
        return self.table.get(logical)


class Cache:
    def __init__(self, size):
        self.size = size
        self.cache = [None] * size

    def read(self, address):
        return self.cache[address % self.size]

    def write(self, address, value):
        self.cache[address % self.size] = value


class Memory:
    def __init__(self, size):
        self.memory = [None] * size
        self.page_table = None
        self.cacheL1 = Cache(128)
        self.cacheL2 = Cache(512)
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.length = size

    def read(self, logical_address):
        physical = self.page_table.translate(logical_address)
        if not physical:
            # 触发缺页中断
            physical = self.allocate_page()
            self.page_table.map(logical_address, physical)
        return self.memory[physical]

    def write(self, logical_address, data):
        physical = self.page_table.translate(logical_address)
        if not physical:
            # 触发缺页中断
            physical = self.allocate_page()
            self.page_table.map(logical_address, physical)
        self.memory[physical] = data

    def allocate_page(self):
        for i in range(len(self.memory)):
            if not self.memory[i]:
                return i
        raise MemoryError("Out of memory")

    def compress(self, data):
        return zlib.compress(pickle.dumps(data))

    def decompress(self, data):
        return pickle.loads(zlib.decompress(data))

    def encrypt(self, data):
        return self.fernet.encrypt(data)

    def decrypt(self, data):
        return self.fernet.decrypt(data)

    def checksum(self, data):
        return sum(data) % 256


class SharedMemoryPool:
    def __init__(self, capacity, is_multithread=False):
        self.segments = []
        self.capacity = capacity
        if is_multithread:
            self._lock = threading.Lock()
        else:
            self._lock = None

    def allocate(self, size, owner=None, domain=None, priority=0):
        if self._lock:
            self._lock.acquire()
        try:
            # 先查看是否有合适的空闲Segment
            for seg in self.segments:
                if seg.priority < priority and seg.length >= size:
                    alloc_seg = Segment(seg.start, size, seg.memory)
                    seg.start += size
                    seg.length -= size
                    alloc_seg.priority = priority
                    seg.owner = owner
                    seg.domain = domain
                    alloc_seg.owner = owner
                    alloc_seg.domain = domain
                    return alloc_seg

            # 没有可用Segment,创建新的Memory
            memory = Memory(size)
            seg = Segment(0, size, memory)
            seg.owner = owner
            seg.domain = domain
            seg.priority = priority
            if len(self.segments) < self.capacity:
                self.segments.append(seg)
                pages = []
                for i in range(0, size, 1024):
                    page = Page(i, seg.memory)
                    page.owner = self
                    pages.append(page)
                seg.pages = pages
            return seg
        finally:
            if self._lock:
                self._lock.release()

    def add_user(self, segment, user, perm_str):
        # 校验权限格式
        if not re.match(r"^[rwxsuep-]{7}$", perm_str):
            raise ValueError("Invalid permission string")

        if user not in segment.users:
            segment.users.append(user)
            segment.permissions[user] = perm_str

    def remove_user(self, segment, user):
        if user in segment.users:
            segment.users.remove(user)
            segment.permissions.pop(user)

    def set_permissions(self, segment, user, perms):
        # 校验权限变量格式
        if not re.match(r"^[rwxsuep-]{7}$", perm_str):
            raise ValueError("Invalid permissions")

        segment.permissions[user] = perms

    def check_permission(self, segment, user, access):
        perms = parse_permissions(segment.permissions.get(user, ""))
        if access in perms:
            return True
        return False

    def free(self, segment):
        if self._lock:
            self._lock.acquire()
        try:
            # 找到segment在segments中的index
            idx = self.segments.index(segment)
            if idx > 0:
                prev = self.segments[idx - 1]
                # 如果前一个segment是空闲的,合并
                if prev.length == 0:
                    prev.length += segment.length
                    prev.memory = segment.memory
                    segment = prev
            if idx < len(self.segments) - 1:
                # 同理,如果后一个segment空闲,合并
                next = self.segments[idx + 1]
                if next.length == 0:
                    segment.length += next.length
                    segment.memory = next.memory
                    self.segments.remove(next)
            # 插入新的segment
            self.segments.insert(idx, segment)
        finally:
            if self._lock:
                self._lock.release()

    def reserve(self, size):
        if self._lock:
            self._lock.acquire()
        try:
            memory = Memory(size)
            seg = Segment(0, size, memory)
            self.segments.append(seg)
        finally:
            if self._lock:
                self._lock.release()

    # 新增功能:获取内存池使用状况
    def get_usage(self):
        total = sum([seg.length for seg in self.segments])
        return total / self.capacity

    def on_alloc(size, segment):
        print("Allocated", size)


# 获取内存对象
def get_memory(size):
    #    if shared_memory_pool:
    #        segment = shared_memory_pool.pop()
    #        return segment.memory
    #    else:
    memory = Memory(size)
    segment_table = SegmentTable()
    page_table = PageTable(memory)
    segment = segment_table.allocate(memory.length)
    segment.memory = memory
    memory.page_table = page_table
    return memory


# 使用示例
memory = get_memory(1024)
memory.read(100)  # 触发缺页中断并映射
memory.write(200, b"abc")  # 触发缺页中断并映射

# 初始化池对象
pool = SharedMemoryPool(100, is_multithread=True)

# 使用示例
seg1 = pool.allocate(1024)
...
pool.free(seg1)
print(pool.get_usage())
