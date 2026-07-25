#!/usr/bin/env python3
"""
源码级反检测补丁(编译前打,对 frida-gum,已核对 frida 16.1.4 源码)。

治的是:RASP(工行 ICBCBankTest / 邮储 YCReBank 等)对 frida-core 自身 hook 的
libsystem 函数(task_threads / thread_resume / abort / signal / exit ...)做
prologue 完整性扫描。真机逆向(IDA+frida)确认判据:读被 hook 函数入口字节,
  · 首字节 byte[3] 归一(&0x9f)== 0x90(adrp) 或 == 0x58(ldr-literal) 才继续查;
  · 再看第 2 条是不是 `br x16`(byte[6]==0x1f && byte[7]==0xd6)→ 判定被 hook → 投毒。
gum 默认入口 redirect:
  16B: `ldr x16,[pc+8]; br x16`  首字节 0x58 → 命中
   8B: `adrp x16; br x16`        首字节 adrp(&0x9f=0x90)+ br → 命中
本补丁改成(仅改 backend-arm64/guminterceptor-arm64.c 的 activate switch,不动 writer):
  16B → `movz/movk x16, on_enter; br x16` 首字节 0xd2(MOVZ)→ byte[3] 检查即不匹配;
   8B → `adrp x16; ret x16`               adrp 逃不掉,但 RASP 只认 br(byte6=0x1f)
                                          不认 ret(byte6=0x5f)→ 分支检查不匹配。
两者仍是 16/8 字节、语义等价的间接跳转;48 位用户地址够 iOS 用。

用法: python3 patch_antidetect.py <frida根目录(默认 frida)>
"""
import sys, os

def patch(path, old, new, desc):
    with open(path) as f: s = f.read()
    if new in s:
        print("  [skip] 已打过: %s" % desc); return
    n = s.count(old)
    assert n == 1, "锚点命中 %d 次(期望 1): %s @ %s" % (n, desc, path)
    with open(path, 'w') as f: f.write(s.replace(old, new, 1))
    print("  [ok] %s" % desc)

root = sys.argv[1] if len(sys.argv) > 1 else "frida"
# 兼容两种子模块布局:16.1.4 是 <root>/frida-gum,较新版是 <root>/subprojects/frida-gum
cands = [os.path.join(root, "frida-gum"), os.path.join(root, "subprojects", "frida-gum")]
gumroot = next((c for c in cands if os.path.isdir(c)), None)
assert gumroot is not None, "找不到 frida-gum(试过: %s)" % cands
itc = os.path.join(gumroot, "gum", "backend-arm64", "guminterceptor-arm64.c")
assert os.path.exists(itc), "找不到 %s" % itc
print("frida-gum: %s" % gumroot)

print("[1/2] 16 字节 redirect: ldr x16;br x16 -> movz/movk x16;br x16 (首字节 0xd2)")
patch(itc,
"""      case 16:
        gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16, on_enter);
        gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
        break;""",
"""      case 16:
        /* anti-detection: avoid the ldr-literal entry byte (0x58) that RASP
         * prologue scanners fingerprint. movz/movk keeps entry byte 0xd2. */
        gum_arm64_writer_put_instruction (aw,
            0xd2800010 | ((guint32) (on_enter & 0xffff) << 5));
        gum_arm64_writer_put_instruction (aw,
            0xf2a00010 | ((guint32) ((on_enter >> 16) & 0xffff) << 5));
        gum_arm64_writer_put_instruction (aw,
            0xf2c00010 | ((guint32) ((on_enter >> 32) & 0xffff) << 5));
        gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
        break;""",
"case 16 movz/movk/br")

print("[2/2] 8 字节 redirect: adrp x16;br x16 -> adrp x16;ret x16 (byte6 0x1f->0x5f)")
patch(itc,
"""      case 8:
        gum_arm64_writer_put_adrp_reg_address (aw, ARM64_REG_X16, on_enter);
        gum_arm64_writer_put_br_reg_no_auth (aw, ARM64_REG_X16);
        break;""",
"""      case 8:
        /* anti-detection: adrp unavoidable in 8B, but RASP keys on `br x16`
         * (byte6==0x1f); `ret x16` (byte6==0x5f) is an equivalent branch. */
        gum_arm64_writer_put_adrp_reg_address (aw, ARM64_REG_X16, on_enter);
        gum_arm64_writer_put_ret_reg (aw, ARM64_REG_X16);
        break;""",
"case 8 adrp/ret")

print("反检测源码补丁应用完成。")
