#!/usr/bin/env python3
"""
主机 client 去特征:与 workflow 编出的 server/agent 协议对齐。
client 只需改协议串(re.frida.* / frida:rpc),不需反转检测串(那是 agent 内部、不影响协议)。

用法:
  python3 patch-client.py /path/to/_frida.abi3.so
  python3 patch-client.py --alias <alias> /path/to/_frida.abi3.so   # 显式指定别名
  python3 patch-client.py --manifest build_manifest.json /path/to/_frida.abi3.so  # 从 manifest 读别名

会自动备份 <so>.bak。等价:FRIDA_ALIAS 环境变量指定别名。
"""
import sys, shutil, os, json

def load_alias_from_args(argv):
    """从命令行参数或环境变量解析别名。返回 (alias, remaining_args)"""
    alias = os.environ.get("FRIDA_ALIAS")
    rest = argv
    i = 0
    while i < len(rest):
        if rest[i] == "--alias" and i + 1 < len(rest):
            alias = rest[i + 1]
            rest = rest[:i] + rest[i+2:]
        elif rest[i] == "--manifest" and i + 1 < len(rest):
            with open(rest[i + 1]) as f:
                alias = json.load(f)["alias"]
            rest = rest[:i] + rest[i+2:]
        else:
            i += 1
    return alias, rest

def patch(path, alias):
    # 从别名生成大小写变体
    alias_upper = alias.upper()
    alias_title = alias[0].upper() + alias[1:]

    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy(path, bak)
        print(f"备份 -> {bak}")
    data = open(path, "rb").read()
    n0 = len(data)

    # 协议串替换(与 postpatch.py 的 REPLACE_TABLE 完全一致)
    # ⚠ 必须先长后短:否则 "frida" 会先于 "frida-agent.dylib" 替换,
    #   导致长串规则失配
    table = sorted([
        (b"frida", alias.encode()),
        (b"Frida", alias_title.encode()),
        (b"FRIDA", alias_upper.encode()),
        (b"frida-server", f"{alias}-server".encode()),
        (b"frida-agent.dylib", f"{alias}-agent.dylib".encode()),
        (b"re.frida.Server", f"re.{alias}.Server".encode()),
        (b"re.frida.Agent", f"re.{alias}.Agent".encode()),
        (b"frida:rpc", f"{alias}:rpc".encode()),
        (b"frida:portal", f"{alias}:portal".encode()),
        (b"frida:host-session", f"{alias}:host-session".encode()),
        (b"frida:agent-session", f"{alias}:agent-session".encode()),
        (b"frida:transport-broker", f"{alias}:transport-broker".encode()),
        (b"frida:bus", f"{alias}:bus".encode()),
        (b"frida-helper", f"{alias}-helper".encode()),
    ], key=lambda kv: -len(kv[0]))
    # 先校验长度
    for old, new in table:
        assert len(old) == len(new), f"不等长: {old} -> {new}"
        c = data.count(old)
        if c:
            data = data.replace(old, new)
            print(f"  [client] {old.decode()} x{c} -> {new.decode()}")

    # 保护 Python 扩展入口:PyInit__<alias> 改回 PyInit__frida
    # (Python 扩展必须保持原始入口名,否则 import 失败)
    data = data.replace(b"PyInit__" + alias.encode(), b"PyInit__frida")

    assert len(data) == n0, f"长度变了 {n0}->{len(data)}"
    # 残留校验:除 PyInit__frida 外不能有 frida/Frida/FRIDA
    # 注意:PyInit__frida 里含 frida,允许存在
    # 因此检查:去掉 PyInit__frida 后,其余 frida 必须为 0
    without_pyinit = data.replace(b"PyInit__frida", b"")
    assert b"frida" not in without_pyinit, "残留 frida"
    assert b"Frida" not in without_pyinit, "残留 Frida"
    assert b"FRIDA" not in without_pyinit, "残留 FRIDA"
    open(path, "wb").write(data)
    print(f"[client] {path}: 协议串已按 alias={alias} 替换,PyInit__frida 已保留")

    # Python implements Script RPC framing outside the native extension.
    # Updating only _frida leaves exports_sync waiting on the original marker.
    from pathlib import Path
    native_dir = Path(path).resolve().parent
    core_path = native_dir / "core.py" if native_dir.name == "frida" else native_dir / "frida" / "core.py"
    if not core_path.is_file():
        raise RuntimeError(f"Cannot find Python RPC implementation: {core_path}")
    source = core_path.read_text()
    marker = f"{alias}:rpc"
    if "frida:rpc" in source:
        core_backup = core_path.with_name(core_path.name + ".frida-original.bak")
        if not core_backup.exists():
            shutil.copy2(core_path, core_backup)
        source = source.replace("frida:rpc", marker)
        core_path.write_text(source)
    if source.count(marker) != 2:
        raise RuntimeError("Python RPC markers do not match this build; restore the original core.py before patching")
    print(f"[client] {core_path}: Python RPC send/receive markers matched to {marker}")

if __name__ == "__main__":
    alias, args = load_alias_from_args(sys.argv[1:])
    if not alias:
        print("用法: patch-client.py [--alias <alias>] [--manifest build_manifest.json] <_frida.abi3.so>")
        print("     或设置环境变量 FRIDA_ALIAS=<alias>")
        sys.exit(1)
    if len(args) != 1:
        print("用法: patch-client.py [--alias <alias>] <_frida.abi3.so>")
        sys.exit(1)
    patch(args[0], alias)
