# Frida 16.1.4 增强备用版

本目录是独立备用构建。当前手机的 aq2ih 服务、51000 端口和电脑 pyenv 3.8.13 原环境不由本构建修改。

## 已实现

- 在 Runner 建立传输连接前，创建一次独立的 QuickJS 引导脚本；随 agent 卸载关闭，并参与退出/exec 生命周期。普通 `-f` 注入在完成这一步后才交还客户端。它不保证覆盖注入前已经执行的代码。
- `_dyld_image_count`、name、header、vmaddr_slide 四个接口共用可见索引。每次 count 查询重建映射，镜像数量变化时也刷新；越界索引交给系统返回空值。
- `dladdr` 查询命中 agent 时清空完整 Dl_info 并返回失败。
- 对明确安装路径的绝对路径查询，在原调用之前改用空路径，返回失败并设置当前调用的 ENOENT，避免泄漏已打开的描述符/FILE。
- 路径按分隔符边界匹配并处理 `.` / `..`，不会把同前缀的正常文件当成目标；有界读取，异常指针不修改。
- 随机构建别名、线程名和已登记的 Gum GObject 类型名；仅按完整 C 字符串替换新增类型，保留 CModule 的公共声明。
- 项目名扫描覆盖 ASCII、UTF-16 LE/BE、UTF-32 LE/BE 和混合大小写；端口通过启动参数设置，不再全文件替换整数。
- 严格解析 FAT32/FAT64、两种字节序及每个 Mach-O load command；签名后逐架构验证 CodeDirectory 代码页哈希。
- arm64 / arm64e 均保留上游 Interceptor 跳板，不使用截断指针高位的旧补丁。

## 明确未覆盖的检测

直接 syscalls、Mach 内存/任务接口、`TASK_DYLD_INFO`、dyld 私有信息、镜像通知回调、dlsym、内联扫描、代码页完整性、跳板/调用栈、异常端口/调试寄存器、线程数量与入口、端口协议指纹、时间/内存开销、目录列表、已打开 FD、符号链接及 `openat` 的相对路径等，仍可能暴露注入。

镜像加载/卸载并发时，dyld 公共接口本身不提供跨多次调用的原子快照。本映射也不能保证这种原子性；同数量替换通过下次 count 查询刷新。

保留的 `gum_*` CModule 公共符号、Gum 声明以及 GLib/GDBus/V8 等依赖文本会记录在 verification.json。它们不是“已清零”的项目。文件名、路径、二进制布局和运行行为仍可作为检测依据。脚本自身的 Hook 也可以被完整性检测发现。

不对 `strstr/memmem` 做全局隐藏，不伪造未实现的 sysctl/异常端口结果。**静态扫描通过 ≠ 无法检测；编译通过 ≠ 真机兼容通过。**

## 产物

- `build_manifest.json`：本次随机别名、部署路径、线程/类型映射。
- `*-server-ios-arm64e`：手机 server。
- `*-agent.dylib`：arm64 + arm64e 通用 agent。
- `verification.json`：最终签名文件摘要、架构、代码页哈希检查、残留统计。
- `bootstrap.js` / `embedded-bootstrap.patch`：实际编入的脚本及源码补丁，仅作审阅，**不要重复手动加载 bootstrap.js**。
- `source/`、提交号、子模块记录、工具链记录、`SHA256SUMS.txt`：复现与核对材料。

## 备用测试方法

先在电脑解压目录中读取别名：

```sh
ALIAS=$(python3 -c 'import json; print(json.load(open("build_manifest.json"))["alias"])')
```

将 server 上传到手机 `/usr/sbin/${ALIAS}-server`，agent 上传到 `/usr/lib/${ALIAS}/${ALIAS}-agent.dylib`。目录和文件名要与 manifest 一致，server 设为可执行。RootHide 采用当前可用部署相同的权限/签名处理。

手机 SSH 中临时启动备用服务，使用独立端口：

```sh
export CRYPTEX_MOUNT_PATH="$(jbroot)"
/usr/sbin/<manifest中的alias>-server -l 127.0.0.1:52000
```

这是前台临时进程；关闭它不影响原 51000 服务。不要为备用版覆盖现有 launchd 配置。仅完成构建时，不代表已经在手机执行过本命令。

电脑另外打开一个终端建立转发：

```sh
ssh -N -L 52000:127.0.0.1:52000 root@192.168.3.141
```

在解压目录创建独立客户端（可选加 `--objection`）：

```sh
~/.pyenv/versions/3.8.13/bin/python source/create-client.py
./client-env/bin/frida-ps -H 127.0.0.1:52000
./client-env/bin/frida -H 127.0.0.1:52000 -f com.apple.Preferences
```

会新建 `client-env`，不会修改当前 pyenv 的客户端。不同别名的 server 和 client 不能混用。运行时的 `Frida` 全局对象也随别名变化；已有自定义脚本如使用 `Frida.version`，需按 manifest 的 alias_title 调整。

## 建议验证

用同一个自有测试程序比较：无注入 / 当前可用版 / 本备用版。分别记录 attach、spawn、退出、重连、模块增删、各查询 API 的一致性、误拦截和时间开销。保留原始检测输出，避免只以“没弹窗”判定成功。
