# frida-ios-build

在 GitHub Actions 的 **macOS runner**(自带 Xcode + iOS SDK)上原生编译 iOS 版 frida-server,
编译时/后做深层去特征,产出"天生隐身"的 frida 二进制,用于对抗恶意 App 的 RASP 检测。

## 用法

1. Actions 页 → `build-frida-ios` → **Run workflow**,填 `frida_version`(默认 16.1.4)、`arch`(6s=arm64)。
2. 跑完在该次 run 的 Artifacts 里下 `frida-stealth-<arch>`(含 server + agent + manifest)。
3. 解压 artifact,从 manifest 读取本次构建的**随机别名**:
   ```bash
   python3 -c "import json; print(json.load(open('build_manifest.json'))['alias'])"
   ```
4. 用 `device/deploy.sh` 推送到设备:
   ```bash
   ./device/deploy.sh <alias> <device_ip> <ssh_port> <listen_port>
   ```
5. 主机端同步改 `_frida.abi3.so`:
   ```bash
   python3 patch-client.py --manifest build_manifest.json $(python3 -c "import frida; print(frida.__file__)")
   ```
6. 连接:
   ```bash
   iproxy <listen_port> <listen_port> <device_ssh_port> <device_ip>
   frida -H 127.0.0.1:<listen_port> <target>
   ```

## 反检测覆盖

### 二进制层(编译后 postpatch.py)

| 信号 | 处理 |
|---|---|
| `frida-server` / `frida-agent.dylib` 进程/文件名 | 随机别名替代,每次构建不同 |
| `/usr/lib/frida/` 路径 | 同步改为 `/usr/lib/<alias>/` |
| `re.frida.Server` / `frida:rpc` 等协议串 | 随机别名+路径全量替换并硬校验清零 |
| `GumScript` / `GDBusProxy` / `GLib-GIO` 等类名 | 随机等长替换(不保留可识别后缀) |
| `gum-js-loop` / `gmain` / `gdbus` 线程名 | 随机等长替换(反转是弱特征,已被取代) |
| 27042/27043 默认端口常量 | 数据段小端字节替换为随机高位端口 |
| `LC_ID_DYLIB` 安装名 | 同步更新为新路径(等长别名约束) |
| `FridaScriptEngine` 等引擎名 | 随机等长替换 |
| 裸 `frida`/`Frida`/`FRIDA` 字符串 | 全局等长替换为随机变体,硬校验清零 |

### 运行时 hook 层(stealth_agent.js)

| 检测向量 | 对策 |
|---|---|
| `_dyld_get_image_count` / `_dyld_get_image_name` 枚举镜像 | 从计数/列表中隐藏 alias-agent 镜像 |
| `dladdr` / `dladdr1` 地址→所属模块查询 | 对 agent 范围内地址返回失败 |
| `open` / `openat` / `stat` / `lstat` / `fopen` / `access` 探测路径 | 隐藏路径返回 ENOENT/NULL |
| `strstr` / `memmem` 内存扫描找特征字符串 | 返回 NULL(未找到) |
| `pthread_getname_np` 获取线程名 | 覆盖含特征的线程名为空 |
| `getenv("FRIDA_*")` 环境变量 | 返回 NULL |
| `sysctl(KERN_PROC)` 进程信息 | 扩展点,部分实现 |

### 源码层(patch_antidetect.py)

| 信号 | 处理 |
|---|---|
| gum interceptor 16B/8B prologue 特征 | 首字节 0x58→0xd2(ldr→movz),byte6 0x1f→0x5f(br→ret) |
| RASP 对被 hook 函数入口的完整性扫描 | 规避 byte[3] 判定 + br 分支检查 |

## 架构

```
frida-ios-build/
├── .github/workflows/build-ios.yml  # CI 构建流水线
├── patch_antidetect.py               # 编译前源码补丁(gum interceptor prologue)
├── postpatch.py                      # 编译后二进制去特征(随机别名 + 端口 + 安装名)
├── patch-client.py                   # 主机端 _frida.abi3.so 协议对齐
├── agent/
│   └── stealth_agent.js              # 运行时 stealth agent(镜像/文件/内存过滤)
├── device/
│   ├── deploy.sh                     # 设备端部署脚本
│   └── verify.sh                     # 样本视角去特征验证
├── ent.plist                         # 越狱调试 entitlements
└── build_manifest.json               # 构建产物(每次构建自动生成,含别名信息)
```

## 注意事项

- **6s(A9) = arm64**,别编 arm64e
- **用公开仓库**跑:macOS runner 分钟数公开仓库免费,私有仓库按 10 倍计费
- client(主机)与 server(设备)版本要一致,manifest 请保留
- **第一次连接后**记得用 `patch-client.py` 同步主机侧的 `_frida.abi3.so`
- 每次构建的**随机别名不同**,不要混用不同构建的 server/client
- 如果主机 `_frida.abi3.so` 因为版本不一致报错,用 `pip install frida==<version>` 装对应版本