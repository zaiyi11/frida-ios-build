# frida-ios-build

在 GitHub Actions 的 **macOS runner**(自带 Xcode + iOS SDK)上原生编译 iOS 版 frida-server,
无需在 Linux 上凑 Apple 交叉工具链。含基础反检测改名(gum-js-loop 线程重命名)。

## 用法

1. Actions 页 → `build-frida-ios` → **Run workflow**,填 `frida_version`(默认 16.1.4)、`arch`(6s=arm64)。
2. 跑完在该次 run 的 Artifacts 里下 `frida-server-ios-arm64`。
3. 推到设备的越狱根(roothide 随机 jbroot),`chmod +x`,启动:
   `frida-server -l 127.0.0.1:<非27042端口> &`

## 反检测覆盖

| 信号 | 处理 |
|---|---|
| `gum-js-loop` 线程名 | 源码改名(本 workflow 已做) |
| 27042 端口 | 运行时 `-l` 指定非默认端口 |
| `/usr/sbin/frida-server` 文件 | 装在随机 jbroot、不落默认路径 |
| `re.frida.server`/`frida:rpc`/`frida-agent` 串 | 可选,workflow 里放开对应 sed(注意别破坏协议一致性) |

## 注意

- 6s(A9)= **arm64**,别编 arm64e。
- **用公开仓库**跑:macOS runner 分钟数公开仓库免费,私有仓库按 10 倍计费。
- client(主机)与 server(设备)版本要一致(都 16.1.4)。
