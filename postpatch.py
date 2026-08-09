#!/usr/bin/env python3
# 编译后二进制去特征(undetected-frida 的 anti-anti-frida.py 思路)
# 版本无关:直接改已编好的 Mach-O,不碰源码,不会有 hunk/编译 bug。
# 对 frida-server + frida-agent.dylib 各跑一次。
# 用法: python3 postpatch.py <macho1> [macho2 ...]
import sys

# 反转这些检测目标串(同字节长度;含不带 "frida" 的 —— 内存扫描的真目标)
REVERSE = [
    b"FridaScriptEngine",
    b"GLib-GIO",
    b"GDBusProxy",
    b"GumScript",
    b"gum-js-loop",
    b"gmain",
    b"gdbus",
]

# 这些都是 RASP 常扫的直接落地/进程/服务名特征。它们会被下面的
# frida->frlda 全局等长替换覆盖;这里单独列出来做硬校验,防止旧产物
# 或未来版本改动导致 artifact 里仍残留明显字符串。
MUST_CLEAR = [
    b"frida-agent.dylib",
    b"frida-server",
    b"re.frida.Server",
    b"re.frida.Agent",
    b"frida:rpc",
    b"frida:portal",
    b"frida:host-session",
    b"frida:agent-session",
    b"frida:transport-broker",
    b"frida:bus",
    b"frida",
    b"Frida",
    b"FRIDA",
]

def patch(path):
    data = open(path, "rb").read()
    n0 = len(data)
    done = {}
    # 1) 先反转检测串(必须在 frida->frlda 之前,免得半替换)
    for s in REVERSE:
        c = data.count(s)
        if c:
            data = data.replace(s, s[::-1])
            done[s.decode()] = c
    # 2) frida -> frlda(确定性,主机 client 用同一规则,协议才对得上)
    fc = data.count(b"frida") + data.count(b"Frida") + data.count(b"FRIDA")
    data = data.replace(b"frida", b"frlda").replace(b"Frida", b"Frlda").replace(b"FRIDA", b"FRLDA")
    # 保护 Python 扩展入口(server/agent 无此符号,无害;client 复用本逻辑时关键)
    data = data.replace(b"PyInit__frlda", b"PyInit__frida")

    assert len(data) == n0, f"长度变了 {n0}->{len(data)}(有替换不等长)"
    open(path, "wb").write(data)

    # 硬校验:反转的检测串必须清零(否则构建失败,防止漏改)
    for s in REVERSE:
        r = data.count(s)
        assert r == 0, f"残留检测串 {s.decode()} x{r}"
    for s in MUST_CLEAR:
        r = data.count(s)
        assert r == 0, f"残留 Frida 特征 {s.decode(errors='replace')} x{r}"
    print(f"[postpatch] {path}")
    print(f"  反转检测串: {done}")
    print(f"  frida/Frida 改名: {fc} 处")
    print("  明显 Frida 特征残留: 0")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: postpatch.py <macho> [...]"); sys.exit(1)
    for p in sys.argv[1:]:
        patch(p)
