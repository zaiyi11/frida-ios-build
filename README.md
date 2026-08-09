# frida-ios-build

在 GitHub Actions 的 **macOS runner**(自带 Xcode + iOS SDK)上原生编译 iOS 版 frida-server,
无需在 Linux 上凑 Apple 交叉工具链。构建后会把设备端产物去特征并导出为 `frlda-*` 命名。

## 用法

1. Actions 页 → `build-frida-ios` → **Run workflow**,填 `frida_version`(默认 16.1.4)、`arch`(6s=arm64)。
2. 跑完在该次 run 的 Artifacts 里下 `frlda-server-ios-arm64` 和 `frlda-agent.dylib`。
3. 推到设备的越狱根(roothide 随机 jbroot),保持进程名为 `frlda-server`,启动:
   `./frlda-server -l 127.0.0.1:<非27042端口> &`
4. 把 `frlda-agent.dylib` 放到 server 内部引用的 agent 路径,通常是:
   `/usr/lib/frlda/frlda-agent.dylib`。

## 反检测覆盖

| 信号 | 处理 |
|---|---|
| `gum-js-loop`/`gmain`/`gdbus` 线程名 | 编译后等长反转并硬校验 |
| 27042 端口 | 运行时 `-l` 指定非默认端口 |
| `/usr/sbin/frida-server` 文件/进程名 | artifact 导出为 `frlda-server-*`,部署时不要改回 `frida-server` |
| `frida-agent.dylib`/`frida-server`/`re.frida.Server`/`frida:rpc` 串 | `postpatch.py` 全局 `frida->frlda` 并作为构建失败条件校验 |
| `GumScript`/`GDBusProxy`/`GLib-GIO`/`FridaScriptEngine` 串 | 编译后等长反转并硬校验 |

## 注意

- 6s(A9)= **arm64**,别编 arm64e。
- **用公开仓库**跑:macOS runner 分钟数公开仓库免费,私有仓库按 10 倍计费。
- client(主机)与 server(设备)版本要一致(都 16.1.4)。
- 主机 `_frida.abi3.so` 也要用 `patch-client.py` 做同样的 `frida->frlda` 协议改名,否则会连不上去特征后的 server。
