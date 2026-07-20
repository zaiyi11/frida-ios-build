#!/usr/bin/env python3
# 主机 client 去特征:与 workflow 编出的 server/agent 协议对齐(同一 frida->frlda 规则)。
# client 只需改协议串(re.frida.*/frida:rpc),不需反转检测串(那是 agent 内部、不影响协议)。
# 会自动备份 <so>.bak。用法: python3 patch-client.py /path/to/_frida.abi3.so
import sys, shutil, os

def patch(path):
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy(path, bak)
        print(f"备份 -> {bak}")
    data = open(path, "rb").read()
    n0 = len(data)
    fc = data.count(b"frida") + data.count(b"Frida")
    data = data.replace(b"frida", b"frlda").replace(b"Frida", b"Frlda")
    # 关键:保留 Python 扩展入口 PyInit__frida,否则 import 失败
    data = data.replace(b"PyInit__frlda", b"PyInit__frida")
    assert len(data) == n0
    open(path, "wb").write(data)
    print(f"[client] {path}: frida/Frida 改名 {fc} 处,PyInit 已保留")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: patch-client.py <_frida.abi3.so>"); sys.exit(1)
    patch(sys.argv[1])
