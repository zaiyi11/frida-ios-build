# Current Status

Date: 2026-08-10

## 改动概要

实现了完整的"静态清洗 + 运行时兜底"双层隐身架构:

### 新增/修改

| 文件 | 改动 |
|---|---|
| `postpatch.py` | 重写:随机别名替换(原 frlda 固定替换)、数据段端口常量 patch(27042/27043)、线程名随机化(非反转)、LC_ID_DYLIB 安装名同步更新、输出 manifest |
| `patch-client.py` | 支持随机别名(从 manifest 或 --alias 参数读取),不再硬编码 |
| `agent/stealth_agent.js` | 新增:运行时 hook dyld 镜像枚举、dladdr、文件路径、strstr/memmem、线程名、getenv 等系统 API 兜底 |
| `.github/workflows/build-ios.yml` | 集成随机别名流程、manifest 输出、artifact 名改用别名 |
| `device/deploy.sh` | 新增:设备端推送/启动脚本,自动读取 manifest |
| `device/verify.sh` | 新增:从样本视角自检进程/端口/路径/字符串残留 |
| `README.md` | 重写:覆盖矩阵、架构说明、用法更新 |

### 反检测覆盖对比

| 检测向量 | 原版 | v1(frlda) | 当前(增强) |
|---|---|---|---|
| 进程/文件名 | frida-server | frlda-server | 随机别名(每次构建不同) |
| 字符串 `frida` | 暴露 | frlda | 随机 alias |
| 27042/27043 端口 | 暴露 | 运行时 -l 覆盖 | 运行时 + 数据段常量 patch |
| 线程名 | gum-js-loop 等 | 反转(pooL-js-mug) | 全随机(每次构建不同) |
| GumScript/GDBusProxy 等类名 | 暴露 | 反转 | 全随机 |
| LC_ID_DYLIB 安装名 | frida-agent.dylib | frlda-agent.dylib | 随机 alias-agent.dylib |
| 镜像枚举 `_dyld_get_image_name` | 暴露 | 暴露 | stealth_agent.js 隐藏 |
| 文件路径探测 | 暴露 | 暴露 | stealth_agent.js 返回 ENOENT |
| 内存扫描 strstr/memmem | 暴露 | 暴露 | stealth_agent.js 过滤 |
| dladdr 查询 | 暴露 | 暴露 | stealth_agent.js 返回失败 |
| gum interceptor prologue 特征 | 暴露 | movz/ret 补丁 | 同左(不变) |

## 待解决的问题

1. **stealth_agent.js 目前是"附加脚本"加载方式**——如果目标进程在 RASP 初始化后才启动 frida 注入,stealth_agent.js 可能来不及生效。理想方案是**编译进 frida-agent 的默认 payload**,在 agent 初始化时自动加载,但需要修改 frida 源码(编译前 patch frida-core 的 agent 加载逻辑)。

2. **编译时未 strip**——`make core-ios` 默认编译没有 strip 符号,产物中仍有 `_frida_*` / `gum_*` 等符号,虽然 `frida` 字样的字符串被替换了,但符号名本身是编译生成的,不会被 __cstring 替换覆盖。RASP 读 Mach-O 符号表仍可能发现异常。

3. **arm64e 未覆盖**——`patch_antidetect.py` 只改 arm64 的 interceptor,A12+ 设备如果跑 arm64e 需要增加 arm64e 分支的补丁。

4. **sysctl 反调试未完全实现**——hook 框架已设但未完善,对抗 ptrace 检测需要额外工作。

## 下一次实验建议

在 GCash 上测试当前 artifact:
1. 触发一次构建,拿到随机别名 artifact
2. 部署到设备
3. 用 `-l` 参数注入 stealth_agent.js:
   `frida -H 127.0.0.1:<port> -l agent/stealth_agent.js com.globetel.gcash`
4. 观察 GCash 是否仍退出
5. 如果仍退出,需要进一步排查:在 RASP 初始化前就注入 stealth agent(编译进 payload 的方式)