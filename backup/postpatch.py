#!/usr/bin/env python3
"""Equal-width static backup profile. Validate all Mach-O slices before commit.

Port selection stays in server -l; this does not establish runtime invisibility.
FRIDA_ALIAS is fixed for bootstrap/server/agent/client consistency.
"""

import os, sys, secrets, string, struct, json
random = secrets.SystemRandom()

# ── 替换键生成 ──────────────────────────────────────────────────────────
# 从环境变量读取(CI 跨步骤传递),否则随机生成。
# ⚠ 必须 5 字符:LC_ID_DYLIB 安装名 /usr/lib/frida/frida-agent.dylib 是 32 字节,
#   /usr/lib/<5char>/<5char>-agent.dylib 恰好 32 字节,等长替换才成立。
_ALIAS = os.environ.get("FRIDA_ALIAS") or None
if _ALIAS:
    assert len(_ALIAS) == 5 and _ALIAS.isascii() and _ALIAS.isalnum() and _ALIAS[0].isalpha(), \
        f"FRIDA_ALIAS 必须是 5 字母数字: {_ALIAS}"
else:
    _ALIAS = random.choice(string.ascii_lowercase) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))

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

# No whole-binary integer port replacement. Use an explicit listen address.

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
    # GType identifiers must start with a letter or underscore.
    r = random.choice(string.ascii_lowercase) + _rand_threadname(len(cn) - 1)
    class_names[cn] = r
    if cn.startswith(('Gum', 'GDBus')):
        REPLACE_TABLE[cn.encode() + b'\0'] = r.encode() + b'\0'
    else:
        _add(cn, r)

# 删除后续可能重复的 GDBusProxy/GLib-GIO 处理(已被上面循环覆盖)



# Strict parser handles FAT32/FAT64 and both byte orders.
from macho import commands, dylib_ids
from patterns import replace_aliases, alias_hits

catalog_path = os.path.join(os.path.dirname(__file__), 'runtime_catalog.json')
if os.path.isfile(catalog_path):
    catalog = json.load(open(catalog_path))
    for name in catalog['gobject_names']:
        if name not in class_names:
            value = random.choice(string.ascii_lowercase) + _rand_threadname(len(name) - 1)
            class_names[name] = value
            # Exact C-string only: do not rename CModule type declarations.
            REPLACE_TABLE[name.encode() + b'\0'] = value.encode() + b'\0'
    for name in catalog['extra_thread_names']:
        value = _rand_threadname(len(name))
        if '%d' in name:
            value = value[:-2] + '%d'
        thread_names[name] = value
        _add(name, value)

def patch_lc_id_dylib(path, data, new_name):
    patched = bytearray(data)
    for base, start, stop, old in dylib_ids(data):
        # Preserve the original install-name layout: never expand a load command.
        replacement = old.replace("frida", _ALIAS).replace("Frida", _ALIAS_TITLE)
        encoded = replacement.encode()
        if len(encoded) != stop - start:
            raise ValueError("install-name replacement changes layout")
        patched[start:stop] = encoded
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
    data, encoded_counts = replace_aliases(data, _ALIAS)
    replace_log['case_encoding_alias_counts'] = encoded_counts
    data = data.replace(b"PyInit__" + _ALIAS.encode(), b"PyInit__frida")

    # Port selection belongs to server -l; arbitrary instruction/data rewrites
    # are unsafe and provide no protocol authentication.
    list(commands(data))  # Validate every slice before any file is committed.

    # 4) LC_ID_DYLIB 安装名 patch
    new_install_name = f"/usr/lib/{_ALIAS}/{_ALIAS}-agent.dylib"
    data = patch_lc_id_dylib(path, data, new_install_name)

    # 断言长度不变
    assert len(data) == n0, f"长度变了 {n0}->{len(data)}(有替换不等长)"


    # 4) 硬校验:REPLACE_TABLE 里所有 old 必须清零
    errors = []
    if alias_hits(data):
        errors.append('project name remains in a supported encoding/case')
    for old in REPLACE_TABLE:
        r = data.count(old)
        if r:
            errors.append(f"{old.decode('utf-8','replace')} x{r}")
    if errors:
        print(f"  [FAIL] 残留特征: {', '.join(errors)}")
        sys.exit(1)
    else:
        print(f"  [verify] configured byte patterns absent (static check only)")

    # Atomic replacement only after all structural and byte checks pass.
    list(commands(data))
    temporary = path + ".pending"
    with open(temporary, "wb") as handle:
        handle.write(data)
    os.chmod(temporary, os.stat(path).st_mode)
    os.replace(temporary, path)
    print(f"  [done] {path}")
    return replace_log


def write_manifest(manifest_path, replace_log, thread_names_dict, class_names_dict, alias):
    """写入 manifest 供主机 patch-client.py 使用"""
    manifest = {
        "profile": "enhanced-backup-v1",
        "default_port": "unchanged; explicitly use -l 127.0.0.1:52000",
        "runtime_guard": "embedded in Runner before transport connection",
        "upstream_arm64e_interceptor": True,
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
        if not os.path.isfile(p):
            raise FileNotFoundError(p)
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
