#!/bin/bash
# verify.sh — 从"恶意样本视角"验证去特征是否彻底
# 在设备上检查:进程名 / 端口 / 文件路径 / 镜像 / 内存字符串
# 用法: ./verify.sh <alias> [device] [ssh_port]
#
# 这是"攻击者自检":用 RASP 常见的检测手段反查我们自己的部署,
# 任何一项暴露都说明还有遗漏。

set -uo pipefail

ALIAS="${1:-}"
DEVICE="${2:-localhost}"
SSH_PORT="${3:-2222}"
SSH="ssh -p ${SSH_PORT} -q -o StrictHostKeyChecking=no"

if [ -z "$ALIAS" ]; then
    echo "用法: $0 <alias> [device] [ssh_port]"
    echo "别名可从 build_manifest.json 读:"
    echo "  python3 -c \"import json; print(json.load(open('build_manifest.json'))['alias'])\""
    exit 1
fi

echo "=========================================="
echo "  去特征验证(样本视角): alias=$ALIAS"
echo "=========================================="

FAIL=0

check() {
    local desc="$1"; shift
    local output
    output=$("$@" 2>&1) || true
    if [ -n "$output" ]; then
        echo "  [✗] $desc"
        echo "      $output" | sed 's/^/      /'
        FAIL=1
    else
        echo "  [✓] $desc"
    fi
}

echo ""
echo "── 1. 进程名 ──────────────────────────────"
check "进程列表里出现 frida" \
    $SSH "root@${DEVICE}" "ps aux | grep -i frida | grep -v grep"
check "进程名含原始特征" \
    $SSH "root@${DEVICE}" "ps aux | grep -E 'frida|gum|gadget' | grep -v grep"

echo ""
echo "── 2. 默认端口 ────────────────────────────"
check "27042 被监听" \
    $SSH "root@${DEVICE}" "netstat -an 2>/dev/null | grep -E '27042|27043'"

echo ""
echo "── 3. 文件路径 ────────────────────────────"
check "原版 frida 路径存在" \
    $SSH "root@${DEVICE}" "ls /usr/lib/frida/ /usr/sbin/frida-server 2>&1"
check "进程读取的原版路径" \
    $SSH "root@${DEVICE}" "ls -la /usr/lib/frida 2>&1"

echo ""
echo "── 4. 镜像枚举(需目标进程内检测,这里用静态方式) ──"
echo "     运行时镜像检测由 agent/stealth_agent.js 处理(见 README)"

echo ""
echo "── 5. 磁盘上的字符串残留 ──────────────────"
# 在设备上扫 server 二进制
echo "     设备端 $ALIAS-server 字符串扫描(应全 0):"
for s in frida Frida FRIDA gum-js-loop gmain gdbus GumScript GDBusProxy; do
    c=$($SSH "root@${DEVICE}" "strings /usr/sbin/${ALIAS}-server 2>/dev/null | grep -F -c '$s'" || true)
    if [ "$c" != "0" ] && [ -n "$c" ]; then
        echo "      [✗] '$s' 残留 $c 处"
        FAIL=1
    else
        echo "      [✓] '$s' = 0"
    fi
done

echo ""
echo "── 6. agent 安装名 ────────────────────────"
check "agent LC_ID_DYLIB 含 frida" \
    $SSH "root@${DEVICE}" "otool -D /usr/lib/${ALIAS}/${ALIAS}-agent.dylib 2>/dev/null | grep -i frida"

echo ""
if [ "$FAIL" = "0" ]; then
    echo "=========================================="
    echo "  全部通过!部署在样本视角下无特征。"
    echo "=========================================="
else
    echo "=========================================="
    echo "  ⚠ 有 $FAIL 项未通过,见上方 [✗]"
    echo "=========================================="
    exit 1
fi