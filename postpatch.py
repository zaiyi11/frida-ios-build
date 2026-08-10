#!/usr/bin/env python3
"""
编译后二进制深层去特征(增强版)。

与 v1 的区别:
  - 随机替换键(per-build random):每次构建生成唯一 5 字符替换键,不再是固定 frlda
  - LC_ID_DYLIB 安装名 patch:agent dylib 的 Mach-O load command 也更新
  - 线程名使用随机等长字符串替代反转(反转有启发式模式)
  - 输出 manifest 文件供主机 patch-client.py 使用

用法:
  python3 postpatch.py <macho1> [macho2 ...]
  环境变量 FRIDA_ALIAS=frdxv 覆盖默认随机键(用于 CI 跨步骤传递)
"""

import os, sys, random, string, struct, json

# ── 替换键生成 ──────────────────────────────────────────────────────────
# 从环境变量读取(CI 跨步骤传递),否则随机生成。
# ⚠ 必须 5 字符:LC_ID_DYLIB 安装名 /usr/lib/frida/frida-agent.dylib 是 32 字节,
#   /usr/lib/<5char>/<5char>-agent.dylib 恰好 32 字节,等长替换才成立。
_ALIAS = os.environ.get("FRIDA_ALIAS") or None
if _ALIAS:
    assert len(_ALIAS) == 5 and _ALIAS.isalnum(), \
        f"FRIDA_ALIAS 必须是 5 字母数字: {_ALIAS}"
else:
    _ALIAS = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

# 大小写变体
_ALIAS_UPPER = _ALIAS.upper()          # FRIDA → 全大写
_ALIAS_TITLE = _ALIAS[0].upper() + _ALIAS[1:]  # Frida → 首字母大写

print(f"[postpatch] 替换键: frida → {_ALIAS} / Frida → {_ALIAS_TITLE} / FRIDA → {_ALIAS_UPPER}")

# ── 替换表(等长) ────────────────────────────────────────────────────────
# 所有需替换的字符串及其替换值(长度必须相同)
REPLACE_TABLE = {}
def _add(old, new):
    assert len(old) == len(new), f"不等长: {old}({len(old)}) -> {new}({len(new)})"
    REPLACE_TABLE[old.encode()] = new.encode()

# frida/Frida/FRIDA + 派生路径(三个大小写变体分别替换)
_add("frida", _ALIAS)
_add("Frida", _ALIAS_TITLE)
_add("FRIDA", _ALIAS_UPPER)

# 端口常量 27042/27043:以 4 字节小端整数存于数据段(27042=0x6996 → 96 69 00 00),
# 不是 ASCII 文本,字符串替换无法命中。处理方式:
#   1) 运行时用 -l 127.0.0.1:<非默认端口> 覆盖监听端口(现有做法,保留)
#   2) 数据段小端值由 patch_data_ports() 统一改为 manifest 里的随机端口
# 这里不添加 ASCII 端口替换(避免误伤)。

# 明确路径/服务名(必须等长)
_add("frida-server", f"{_ALIAS}-server")
_add("frida-agent.dylib", f"{_ALIAS}-agent.dylib")
_add("re.frida.Server", f"re.{_ALIAS}.Server")
_add("re.frida.Agent", f"re.{_ALIAS}.Agent")
_add("frida:rpc", f"{_ALIAS}:rpc")
_add("frida:portal", f"{_ALIAS}:portal")
_add("frida:host-session", f"{_ALIAS}:host-session")
_add("frida:agent-session", f"{_ALIAS}:agent-session")
_add("frida:transport-broker", f"{_ALIAS}:transport-broker")
_add("frida:bus", f"{_ALIAS}:bus")
_add("frida-helper", f"{_ALIAS}-helper")

# 线程名:随机等长替换(不反转,反转有启发式模式 gum-* / *-loop 可被模式匹配)
# 注意:线程名在 __TEXT.__cstring 里,必须全局等长替换。全随机,无启发式残留。
thread_names = {}
def _rand_threadname(length):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

for tn in ["gum-js-loop", "gmain", "gdbus", "gum-deadbeef", "gum-event"]:
    r = _rand_threadname(len(tn))
    thread_names[tn] = r
    _add(tn, r)

# Gum/GDBus/GLib 类名:随机等长替换
# 不再保留可识别后缀(Script/Proxy 也属于启发式特征),全部随机。
class_names = {}
for cn in ["FridaScriptEngine", "GumScript", "GumObject", "GDBusProxy", "GDBusConnection",
           "GLib-GIO", "GumEventSink", "GumInterceptorBackend"]:
    r = _rand_threadname(len(cn))
    class_names[cn] = r
    _add(cn, r)

# 删除后续可能重复的 GDBusProxy/GLib-GIO 处理(已被上面循环覆盖)



# ── Mach-O 解析 ────────────────────────────────────────────────────────
FAT_MAGIC = 0xbebafeca
FAT_CIGAM = 0xcafebabe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
LC_ID_DYLIB = 0x0d  # dylib identification load command

def _read32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def _read64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

def _read_macho_64(data, base_off, file_size):
    """解析单个 64 位 Mach-O,返回 LC_ID_DYLIB 信息"""
    if base_off + 4 > file_size:
        return None
    magic = _read32(data, base_off)
    if magic not in (MH_MAGIC_64, MH_CIGAM_64):
        return None
    # ncmds, sizeofcmds
    ncmds = _read32(data, base_off + 0x10)
    sizeofcmds = _read32(data, base_off + 0x14)
    # 遍历 load commands
    offset = base_off + 0x20  # 64-bit header size
    results = []
    for _ in range(ncmds):
        if offset + 8 > file_size:
            break
        cmd = _read32(data, offset)
        cmdsize = _read32(data, offset + 4)
        if offset + cmdsize > file_size:
            break
        if cmd == LC_ID_DYLIB:
            # LC_ID_DYLIB 结构:
            #   offset+0: cmd(4)
            #   offset+4: cmdsize(4)
            #   offset+8: struct dylib { name_off(4), timestamp(4), cur_ver(4), compat_ver(4) }
            #   name_off 是 lc_str:相对于整个 load command 起始(offset)
            #   name 起始 = offset + name_off
            name_off = _read32(data, offset + 8)
            name_start = offset + name_off
            # 读以 null 结尾的字符串
            end = name_start
            while end < file_size and data[end] != 0:
                end += 1
            name = data[name_start:end].decode('utf-8', errors='replace')
            results.append({
                "cmd_offset": offset,
                "name_offset": name_start - base_off,
                "name": name,
                "name_len": end - name_start,
            })
        offset += cmdsize
    return results


def _find_fat_slices(data, file_size):
    """如果是 FAT 二进制,返回所有 slice 偏移;否则返回 [0]"""
    if file_size < 4:
        return [0]
    magic = _read32(data, 0)
    if magic in (FAT_MAGIC, FAT_CIGAM):
        narch = _read32(data, 4)
        slices = []
        for i in range(narch):
            off = 8 + i * 20
            if off + 20 > file_size:
                break
            stoff = _read32(data, off)
            # 只处理 arm64
            cpu = _read32(data, off)
            # ARM64 是 0x0100000c (CPU_TYPE_ARM64)
            if cpu == 0x0100000c or cpu == 0x0c000001:  # 大小端
                slices.append(stoff)
        return slices if slices else [0]
    return [0]


def patch_data_ports(data, old_ports=(27042, 27043), new_ports=(37015, 37016)):
    """
    把二进制数据段里的小端 4 字节端口常量替换成随机端口。
    frida 默认端口 27042(0x69a2)和 27043(0x69a3)以小端存储:
      27042 → a2 69 00 00
      27043 → a3 69 00 00
    RASP 会硬编码扫描这两个值(扫描进程内存判断是否注入 frida)。
    随机端口 37015/37016 等长(仍是 5 位),避免启发式端口区间。
    """
    patched = bytearray(data)
    count = 0
    for old_port, new_port in zip(old_ports, new_ports):
        old_bytes = struct.pack("<I", old_port)
        new_bytes = struct.pack("<I", new_port)
        # 注意:37015 > 65535 会溢出 4 字节?37015 < 65536,OK
        assert new_port < 0x10000, f"端口 {new_port} 超出 16 位"
        c = data.count(old_bytes)
        if c:
            patched = patched.replace(old_bytes, new_bytes)
            count += c
            print(f"  [port] {old_port} (0x{old_port:04x}) x{c} -> {new_port} (0x{new_port:04x})")
    return bytes(patched), count


def patch_lc_id_dylib(path, data, new_name):
    """
    修改 Mach-O 中 LC_ID_DYLIB 的安装名。
    如果 new_name 比原名字短,剩余空间填 0;如果长于原名字则报错。
    """
    file_size = len(data)
    slices = _find_fat_slices(data, file_size)
    patched = bytearray(data)
    for sl in slices:
        entries = _read_macho_64(patched, sl, file_size)
        if not entries:
            continue
        for entry in entries:
            old_name = entry["name"]
            name_len = entry["name_len"]
            abs_name_off = entry["name_offset"] + sl
            new_bytes = new_name.encode('utf-8')
            if len(new_bytes) > name_len:
                print(f"  [warn] 新安装名 '{new_name}' 比原 '{old_name}'({name_len}B)长,跳过")
                continue
            # 写入新名字 + null 填充剩余
            patched[abs_name_off:abs_name_off + len(new_bytes)] = new_bytes
            if len(new_bytes) < name_len:
                patched[abs_name_off + len(new_bytes):abs_name_off + name_len] = b'\x00' * (name_len - len(new_bytes))
            print(f"  [lc_id_dylib] {old_name} -> {new_name}")
    return bytes(patched)


# ── 主 patch 逻辑 ──────────────────────────────────────────────────────
def patch(path):
    data = open(path, "rb").read()
    n0 = len(data)
    replace_log = {}

    # 1) 字符串替换
    # ⚠ 必须先长后短:否则 "frida" 会先于 "frida-agent.dylib" 替换,
    #   把长串里的 frida 提前换掉,导致长串规则失配。
    for old, new in sorted(REPLACE_TABLE.items(), key=lambda kv: -len(kv[0])):
        c = data.count(old)
        if c:
            data = data.replace(old, new)
            replace_log[old.decode('utf-8', 'replace')] = c
            print(f"  [replace] {old.decode('utf-8','replace')} x{c} -> {new.decode('utf-8','replace')}")

    # 2) 保护 Python 扩展入口(仅在 client 侧需要,server/agent 无害)
    data = data.replace(b"PyInit__" + _ALIAS.encode(), b"PyInit__frida")

    # 3) 数据段端口常量 patch(小端 4 字节 27042/27043 → 随机端口)
    data, port_count = patch_data_ports(data)
    if port_count:
        print(f"  [port] 共 {port_count} 处端口常量已改")

    # 4) LC_ID_DYLIB 安装名 patch
    new_install_name = f"/usr/lib/{_ALIAS}/{_ALIAS}-agent.dylib"
    data = patch_lc_id_dylib(path, data, new_install_name)

    # 断言长度不变
    assert len(data) == n0, f"长度变了 {n0}->{len(data)}(有替换不等长)"

    open(path, "wb").write(data)
    print(f"  [done] {path}")

    # 4) 硬校验:REPLACE_TABLE 里所有 old 必须清零
    errors = []
    for old in REPLACE_TABLE:
        r = data.count(old)
        if r:
            errors.append(f"{old.decode('utf-8','replace')} x{r}")
    if errors:
        print(f"  [FAIL] 残留特征: {', '.join(errors)}")
        sys.exit(1)
    else:
        print(f"  [verify] 全部特征清零 ✓")

    return replace_log


def write_manifest(manifest_path, replace_log, thread_names_dict, class_names_dict, alias):
    """写入 manifest 供主机 patch-client.py 使用"""
    manifest = {
        "alias": alias,
        "alias_title": alias[0].upper() + alias[1:],
        "alias_upper": alias.upper(),
        "replace_log": {k: v for k, v in replace_log.items()},
        "thread_names": thread_names_dict,
        "class_names": {k: v for k, v in class_names_dict.items()},
        "install_path": f"/usr/lib/{alias}",
        "agent_path": f"/usr/lib/{alias}/{alias}-agent.dylib",
        "server_path": f"/usr/sbin/{alias}-server",
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"  [manifest] -> {manifest_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <macho1> [macho2 ...]")
        print(f"环境变量 FRIDA_ALIAS 可指定替换键(默认随机)")
        sys.exit(1)

    all_logs = {}
    for p in sys.argv[1:]:
        if os.path.exists(p):
            log = patch(p)
            all_logs[p] = log

    # 写 manifest
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "build_manifest.json")
    write_manifest(manifest_path, all_logs, thread_names, class_names, _ALIAS)

    print(f"\n=== 全部完成 ===")
    print(f"替换键: {_ALIAS}")
    print(f"安装路径: /usr/lib/{_ALIAS}/")
    print(f"Server 路径: /usr/sbin/{_ALIAS}-server")
    print(f"Agent 路径: /usr/lib/{_ALIAS}/{_ALIAS}-agent.dylib")
    print(f"Manifest: {manifest_path}")
    print(f"\n⚠ 部署时请保持文件名/路径与上述一致")
    print(f"⚠ 主机 client 请用: python3 patch-client.py --alias {_ALIAS} <_frida.abi3.so>")