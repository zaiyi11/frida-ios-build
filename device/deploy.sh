#!/bin/bash
# deploy.sh — 把去特征后的 frida 推送到越狱设备并启动
# 用法: ./deploy.sh <alias> [device_ip] [ssh_port]
#
# 步骤:
#   1) 从 build_manifest.json 读别名(或通过参数指定)
#   2) scp 推送 server + agent 到设备
#   3) 清理旧进程
#   4) 启动新 server(随机端口,只绑回环)
#   5) 验证启动
#
# 前提:设备已越狱(roothide/unc0ver/checkra1n),SSH 可达,有 scp/ssh

set -euo pipefail

# ── 参数 ────────────────────────────────────────────────────
ALIAS="${1:-}"
DEVICE="${2:-localhost}"
SSH_PORT="${3:-2222}"
SCP="scp -P ${SSH_PORT} -q"
SSH="ssh -p ${SSH_PORT} -q -o StrictHostKeyChecking=no"
LISTEN_PORT="${4:-51000}"  # 随机高位端口,不要用 27042/27043

# ── 读取 manifest ───────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${SCRIPT_DIR}/build_manifest.json"

if [ -z "$ALIAS" ]; then
    if [ -f "$MANIFEST" ]; then
        ALIAS=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['alias'])")
        echo "[deploy] 从 manifest 读取别名: $ALIAS"
    else
        echo "[deploy] 错误: 未指定别名且找不到 build_manifest.json"
        echo "用法: $0 <alias> [device] [port] [listen_port]"
        exit 1
    fi
fi

# 构造路径
SERVER_FILE="${SCRIPT_DIR}/${ALIAS}-server-ios-arm64"
AGENT_FILE="${SCRIPT_DIR}/${ALIAS}-agent.dylib"
DEVICE_SERVER="/usr/sbin/${ALIAS}-server"
DEVICE_AGENT_DIR="/usr/lib/${ALIAS}"
DEVICE_AGENT="${DEVICE_AGENT_DIR}/${ALIAS}-agent.dylib"

echo "=========================================="
echo "  frida-stealth 部署工具"
echo "  别名:       $ALIAS"
echo "  设备:       ${DEVICE}:${SSH_PORT}"
echo "  监听端口:   ${LISTEN_PORT}"
echo "  本地 server: $SERVER_FILE"
echo "  本地 agent:  $AGENT_FILE"
echo "=========================================="

# ── 检查本地文件 ────────────────────────────────────────────
for f in "$SERVER_FILE" "$AGENT_FILE"; do
    if [ ! -f "$f" ]; then
        echo "[deploy] 错误: 找不到 $f"
        echo "        请先下载 artifact 或检查当前目录"
        exit 1
    fi
done

# ── 推送文件 ────────────────────────────────────────────────
echo "[deploy] 推送 server -> ${DEVICE}:${DEVICE_SERVER}"
$SCP "$SERVER_FILE" "root@${DEVICE}:${DEVICE_SERVER}"
echo "[deploy] 推送 agent -> ${DEVICE}:${DEVICE_AGENT}"
$SSH "root@${DEVICE}" "mkdir -p ${DEVICE_AGENT_DIR}"
$SCP "$AGENT_FILE" "root@${DEVICE}:${DEVICE_AGENT}"

# ── 设置权限 ────────────────────────────────────────────────
echo "[deploy] 设置权限(0755)"
$SSH "root@${DEVICE}" "chmod 0755 ${DEVICE_SERVER} && chmod 0755 ${DEVICE_AGENT}"

# ── 清理旧进程 ──────────────────────────────────────────────
echo "[deploy] 清理旧 ${ALIAS}-server 进程"
$SSH "root@${DEVICE}" "killall ${ALIAS}-server 2>/dev/null || true"
sleep 1

# ── 启动新 server ───────────────────────────────────────────
echo "[deploy] 启动 ${ALIAS}-server -l 127.0.0.1:${LISTEN_PORT}"
$SSH "root@${DEVICE}" "nohup ${DEVICE_SERVER} -l 127.0.0.1:${LISTEN_PORT} >/dev/null 2>&1 &"
sleep 2

# ── 验证启动 ────────────────────────────────────────────────
echo "[deploy] 验证进程是否运行..."
PID=$($SSH "root@${DEVICE}" "pgrep -x ${ALIAS}-server" || true)
if [ -n "$PID" ]; then
    echo "[deploy] ✓ ${ALIAS}-server 运行中, PID=$PID, 端口=${LISTEN_PORT}"
    echo ""
    echo "主机端连接:"
    echo "  iproxy ${LISTEN_PORT} ${LISTEN_PORT} ${DEVICE_PORT:-2222} ${DEVICE}"
    echo "  frida -H 127.0.0.1:${LISTEN_PORT} <target>"
    echo ""
    echo "⚠ 别忘了用 patch-client.py 同步改主机 _frida.abi3.so:"
    echo "  python3 patch-client.py --alias ${ALIAS} \$(python3 -c \"import frida; print(frida.__file__)\")"
else
    echo "[deploy] ✗ 启动失败,检查设备日志:"
    echo "        $SSH root@${DEVICE} '${DEVICE_SERVER} -l 127.0.0.1:${LISTEN_PORT}'"
    exit 1
fi