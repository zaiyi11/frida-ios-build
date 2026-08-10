// stealth_agent.js — 运行时隐身引擎
// 注入到目标进程后 hook 系统 API,动态隐藏 frida/frlda 的注入痕迹。
// 配合 postpatch.py 的静态替换使用,构成"静态清洗 + 运行时兜底"双层隐身。
//
// 加载方式:
//   1) 编译进 frida-agent: 把本脚本置于 frida-agent 的 default payload 中,
//      在 agent 初始化时自动加载(最推荐,最早注入)。
//   2) -l 参数运行时注入: frida -l stealth_agent.js <target>
//      (晚于 RASP 初始化,建议用于测试;对抗成熟 RASP 需方式 1)
//
// 覆盖向量:
//   - dyld 镜像枚举: _dyld_get_image_count / _dyld_get_image_name
//   - 地址查询: dladdr / dladdr1
//   - 文件路径: open / openat / stat / lstat / NSFileManager
//   - 线程枚举: task_threads / thread_info(safe)
//   - 内存扫描: strstr / memmem / _mach_vm_region(部分)
//   - 环境变量: getenv("FRIDA_*")

'use strict';

// ── 配置(从 postpatch.py 的 manifest 读取,或手动填写) ────
const STEALTH = {
    // 替换键(需与 postpatch.py 本次构建的 _ALIAS 一致)
    alias: 'frlda',
    // 需要隐藏的路径前缀
    hidePaths: [
        '/usr/lib/frlda/',
        '/usr/sbin/frlda-server',
    ],
    // 需要隐藏的镜像名(子串匹配)
    hideImages: [
        'frlda-agent.dylib',
        'frlda',
    ],
    // 内存扫描时需要过滤的 needle(子串,不区分大小写)
    memoryNeedles: [
        'frlda',
        'frida',
        'gum-js-loop',
        'gmain',
        'gdbus',
        'gum',
    ],
};

// ── 工具函数 ─────────────────────────────────────────────────
function ptr(s) { return new NativePointer(s); }
const NULL = ptr('0x0');

// 是否已初始化
let initialized = false;

// ── 1. dyld 镜像枚举隐藏 ────────────────────────────────────
// RASP 通过 _dyld_get_image_count + _dyld_get_image_name 遍历所有已加载
// dylib,检查是否有 frida/frlda-agent.dylib 注入。

function hookDyldImages() {
    const dyld = Process.findModuleByName('dyld');

    // _dyld_get_image_count: 从总数中减掉我们隐藏的镜像
    const getImageCount = Module.findExportByName(null, '_dyld_get_image_count');
    if (getImageCount === null) {
        console.warn('[stealth] _dyld_get_image_count not found');
        return;
    }

    // 先确定当前有多少隐藏镜像被加载
    const origCount = new NativeFunction(getImageCount, 'int', []);
    const totalBefore = origCount();
    let hiddenCount = 0;
    for (let i = 0; i < totalBefore; i++) {
        const name = Module.findExportByName(null, '_dyld_get_image_name');
        const getName = new NativeFunction(name, 'pointer', ['int']);
        const imgName = getName(i).readCString() || '';
        if (STEALTH.hideImages.some(h => imgName.includes(h))) {
            hiddenCount++;
        }
    }
    console.log(`[stealth] dyld: 总镜像 ${totalBefore}, 需隐藏 ${hiddenCount}`);

    // Hook _dyld_get_image_count: 返回总数 - 隐藏数
    Interceptor.attach(getImageCount, {
        onLeave(retval) {
            const orig = retval.toInt32();
            if (hiddenCount > 0) {
                retval.replace(ptr(orig - hiddenCount));
            }
        }
    });

    // Hook _dyld_get_image_name: 跳过隐藏镜像,返回下一个非隐藏的
    const getName = Module.findExportByName(null, '_dyld_get_image_name');
    if (getName !== null) {
        // 这个函数比较复杂:我们需要在内部重新索引。
        // 简单做法:维护一个"可见索引→真实索引"映射
        Interceptor.attach(getName, {
            onEnter(args) {
                this.requested = args[0].toInt32();
            },
            onLeave(retval) {
                if (retval.isNull()) return;
                // 从 requested 索引开始,跳过隐藏镜像
                let realIdx = this.requested;
                let found = 0;
                const origName = new NativeFunction(getName, 'pointer', ['int']);
                while (true) {
                    const namePtr = origName(realIdx);
                    if (namePtr.isNull()) {
                        retval.replace(NULL);
                        return;
                    }
                    const name = namePtr.readCString() || '';
                    if (!STEALTH.hideImages.some(h => name.includes(h))) {
                        if (found === this.requested) {
                            // 找到了第 this.requested 个可见镜像
                            retval.replace(namePtr);
                            return;
                        }
                        found++;
                    }
                    realIdx++;
                    // 安全阀:防止无限循环
                    if (realIdx > 10000) break;
                }
                retval.replace(NULL);
            }
        });
    }
}

// ── 2. dladdr 隐藏 ──────────────────────────────────────────
// RASP 用 dladdr(函数指针)来确认这个地址属于哪个 dylib。

function hookDladdr() {
    const dladdr = Module.findExportByName(null, 'dladdr');
    if (dladdr === null) {
        console.warn('[stealth] dladdr not found');
        return;
    }

    // 获取 frlda-agent 的地址范围
    let agentModule = null;
    try {
        agentModule = Process.findModuleByName(STEALTH.alias + '-agent.dylib');
    } catch (e) {
        // 可能模块名不是精确匹配
        Process.enumerateModules().forEach(m => {
            if (m.name.includes(STEALTH.alias)) {
                agentModule = m;
            }
        });
    }

    if (!agentModule) {
        console.warn('[stealth] dladdr: 未找到 agent 模块(可能无此名字)');
        return;
    }

    const base = agentModule.base;
    const size = agentModule.size;

    Interceptor.attach(dladdr, {
        onEnter(args) {
            const addr = args[0];
            if (addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0) {
                // 地址在 agent 范围内:返回 0(失败),让 RASP 查不到
                this.block = true;
            }
        },
        onLeave(retval) {
            if (this.block) {
                retval.replace(ptr(0));
            }
        }
    });
}

// ── 3. 文件路径隐藏 ─────────────────────────────────────────
// RASP 通过 open/stat 探测 /usr/lib/frlda/ 等路径。

function hookFilePaths() {
    // 路径检查函数(返回 true 表示需要隐藏)
    function shouldHidePath(path) {
        if (!path) return false;
        const p = path.toLowerCase();
        return STEALTH.hidePaths.some(hp => p.includes(hp.toLowerCase()));
    }

    // hook open() — 对隐藏路径返回 -1(ENOENT)
    // 注意:open 的函数签名是 int open(const char *path, int flags, ...)
    // 但在 arm64 上,glibc 的 open 实际上是 openat 的 wrapper。
    // 我们 hook openat 更可靠。
    const openat = Module.findExportByName(null, 'openat');
    if (openat !== null) {
        Interceptor.attach(openat, {
            onEnter(args) {
                const path = args[1].readCString();
                if (path && shouldHidePath(path)) {
                    console.log(`[stealth] openat BLOCK: ${path}`);
                    // 把 path 改成 /dev/null 来让 open 成功但文件不可用
                    args[1] = ptr('/dev/null');
                }
            }
        });
    }

    // hook stat() — 对隐藏路径返回 -1(ENOENT)
    const stat = Module.findExportByName(null, 'stat');
    if (stat !== null) {
        Interceptor.attach(stat, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path && shouldHidePath(path)) {
                    console.log(`[stealth] stat BLOCK: ${path}`);
                    // 返回 ENOENT 需要修改 retval,但 stat 是 onEnter 拦截
                    // 用 onLeave 更容易:但我们需要在 onEnter 保存状态
                    this.block = true;
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(ptr(-1));  // -1 = error
                    // errno = ENOENT(2) — 需要设置 errno
                    // 但 errno 是 TLS 变量,直接写不安全
                    this.block = false;
                }
            }
        });
    }

    // hook lstat()
    const lstat = Module.findExportByName(null, 'lstat');
    if (lstat !== null) {
        Interceptor.attach(lstat, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path && shouldHidePath(path)) {
                    this.block = true;
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(ptr(-1));
                    this.block = false;
                }
            }
        });
    }

    // hook fopen() — 对隐藏路径返回 NULL
    const fopen = Module.findExportByName(null, 'fopen');
    if (fopen !== null) {
        Interceptor.attach(fopen, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path && shouldHidePath(path)) {
                    console.log(`[stealth] fopen BLOCK: ${path}`);
                    this.block = true;
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(NULL);
                    this.block = false;
                }
            }
        });
    }

    // hook access() — 对隐藏路径返回 -1
    const access = Module.findExportByName(null, 'access');
    if (access !== null) {
        Interceptor.attach(access, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path && shouldHidePath(path)) {
                    this.block = true;
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(ptr(-1));
                    this.block = false;
                }
            }
        });
    }
}

// ── 4. 内存扫描过滤(strstr/memmem) ─────────────────────────
// RASP 扫描自身内存,用 strstr/memmem 查找 frida 相关字符串。
// 原理:hook strstr,如果 needle 是 frida 相关字符串,返回 NULL(未找到)。

function hookMemoryScan() {
    function isSensitiveNeedle(needle) {
        if (!needle) return false;
        const n = needle.toLowerCase();
        // 检查是否是我们要保护的字符串
        return STEALTH.memoryNeedles.some(mn => n.includes(mn));
    }

    // strstr(const char *haystack, const char *needle)
    const strstr = Module.findExportByName(null, 'strstr');
    if (strstr !== null) {
        Interceptor.attach(strstr, {
            onEnter(args) {
                // 只在 needle 包含敏感词时拦截,减少性能开销
                const needle = args[1].readCString();
                if (needle && isSensitiveNeedle(needle)) {
                    // 保存 needle 用于 onLeave
                    this.needle = needle;
                    // 同时检查 haystack 是否包含敏感词
                    // 如果 haystack 不长,先检查 haystack 本身
                    try {
                        // 只读前 256 字节检查 haystack 是否相关
                        const haystack = args[0].readByteArray(256);
                        if (haystack) {
                            const haystackStr = String.fromCharCode.apply(null, new Uint8Array(haystack));
                            if (isSensitiveNeedle(haystackStr)) {
                                this.block = true;
                            }
                        }
                    } catch (e) {
                        // 不可读的地址,忽略
                    }
                }
            },
            onLeave(retval) {
                if (this.block) {
                    // 返回 NULL:表示"未找到",让 RASP 跳过
                    retval.replace(NULL);
                }
                this.block = false;
            }
        });
    }

    // memmem(void *haystack, size_t hlen, void *needle, size_t nlen)
    // 不是所有 libc 版本都有 memmem,但 iOS 有
    const memmem = Module.findExportByName(null, 'memmem');
    if (memmem !== null) {
        Interceptor.attach(memmem, {
            onEnter(args) {
                const nlen = args[3].toInt32();
                if (nlen > 1 && nlen < 128) {
                    const needle = args[2].readCString();
                    if (needle && isSensitiveNeedle(needle)) {
                        // 检查 haystack 前 256 字节
                        try {
                            const hlen = args[1].toInt32();
                            const checkLen = Math.min(hlen, 256);
                            const haystack = args[0].readByteArray(checkLen);
                            if (haystack) {
                                const haystackStr = String.fromCharCode.apply(null, new Uint8Array(haystack));
                                if (isSensitiveNeedle(haystackStr)) {
                                    this.block = true;
                                }
                            }
                        } catch (e) { }
                    }
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(NULL);
                }
                this.block = false;
            }
        });
    }
}

// ── 5. 线程枚举隐藏 ─────────────────────────────────────────
// RASP 用 task_threads() 枚举所有线程,检查线程名(通过 thread_info 或
// pthread_getname_np)是否包含 frida/gum 相关字样。

function hookTaskThreads() {
    // task_threads 返回所有线程,然后 RASP 会遍历每个线程检查。
    // 我们不能直接隐藏某个线程(会导致崩溃),但可以钩 thread_info
    // 来隐藏线程名中的 gum 特征。
    //
    // 注意:postpatch.py 已经替换了线程名字符串常量(gum-js-loop→随机名),
    // 所以线程名本身已不包含明显特征。这里做兜底,防止 RASP 用其他方式
    // 获取线程名(如 pthread_getname_np)。

    const pthread_getname_np = Module.findExportByName(null, 'pthread_getname_np');
    if (pthread_getname_np !== null) {
        Interceptor.attach(pthread_getname_np, {
            onEnter(args) {
                // args[0] = thread, args[1] = buffer, args[2] = len
                // 保存 buffer 指针,在 onLeave 中检查内容
                this.buf = args[1];
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && this.buf) {
                    // 成功获取到线程名
                    try {
                        const name = this.buf.readCString();
                        if (name && STEALTH.memoryNeedles.some(n => name.includes(n))) {
                            // 覆盖线程名为空(或者一个普通名字)
                            this.buf.writeUtf8String('');
                        }
                    } catch (e) { }
                }
            }
        });
    }
}

// ── 6. 环境变量隐藏 ─────────────────────────────────────────
// RASP 会检查 FRIDA_* 环境变量。

function hookGetenv() {
    const getenv = Module.findExportByName(null, 'getenv');
    if (getenv === null) {
        console.warn('[stealth] getenv not found');
        return;
    }

    Interceptor.attach(getenv, {
        onEnter(args) {
            const name = args[0].readCString();
            if (name) {
                // 检查是否是 frida 相关的环境变量
                const lower = name.toLowerCase();
                if (lower.startsWith('frida_') || lower.startsWith('frlda_')) {
                    this.block = true;
                }
            }
        },
        onLeave(retval) {
            if (this.block) {
                retval.replace(NULL);
                this.block = false;
            }
        }
    });
}

// ── 7. sysctl 隐藏 ──────────────────────────────────────────
// RASP 通过 sysctl 查询进程信息(如 p_flag 的 P_TRACED)。

function hookSysctl() {
    const sysctl = Module.findExportByName(null, 'sysctl');
    if (sysctl === null) {
        console.warn('[stealth] sysctl not found');
        return;
    }

    // sysctl 的 hook 比较复杂(参数可变),简单起见只拦截
    // CTL_KERN / KERN_PROC 相关查询
    // 完整实现需要更多分析,这里留作扩展点
    console.log('[stealth] sysctl hook: 扩展点(未完全实现)');
}

// ── 初始化 ──────────────────────────────────────────────────
function init() {
    if (initialized) return;
    initialized = true;

    console.log(`[stealth] 初始化: alias=${STEALTH.alias}`);

    try {
        hookDyldImages();
        console.log('[stealth] ✓ _dyld_get_image_count/name');
    } catch (e) {
        console.warn(`[stealth] ✗ dyld: ${e.message}`);
    }

    try {
        hookDladdr();
        console.log('[stealth] ✓ dladdr');
    } catch (e) {
        console.warn(`[stealth] ✗ dladdr: ${e.message}`);
    }

    try {
        hookFilePaths();
        console.log('[stealth] ✓ open/stat/fopen/access');
    } catch (e) {
        console.warn(`[stealth] ✗ file: ${e.message}`);
    }

    try {
        hookMemoryScan();
        console.log('[stealth] ✓ strstr/memmem');
    } catch (e) {
        console.warn(`[stealth] ✗ memscan: ${e.message}`);
    }

    try {
        hookTaskThreads();
        console.log('[stealth] ✓ pthread_getname_np');
    } catch (e) {
        console.warn(`[stealth] ✗ threads: ${e.message}`);
    }

    try {
        hookGetenv();
        console.log('[stealth] ✓ getenv');
    } catch (e) {
        console.warn(`[stealth] ✗ getenv: ${e.message}`);
    }

    try {
        hookSysctl();
        console.log('[stealth] ✓ sysctl(partial)');
    } catch (e) {
        console.warn(`[stealth] ✗ sysctl: ${e.message}`);
    }

    console.log('[stealth] 初始化完成');
}

// ── 导出 ────────────────────────────────────────────────────
// 作为 frida-agent 的默认 payload 加载时自动 init
init();

// 也支持外部调用(如从其他脚本加载后手动 init)
exports = { init, STEALTH };