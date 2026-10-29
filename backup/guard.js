/* Embedded bootstrap for the isolated backup build. No kernel visibility claim. */
'use strict';
(() => {
    const alias = '__BUILD_ALIAS__';
    const agentName = alias + '-agent.dylib';
    const root = '/usr/lib/' + alias;
    const hiddenFiles = [root, '/usr/sbin/' + alias + '-server'];
    const listeners = [];
    const report = { profile: 'enhanced-backup-v1', installed: [], missing: [], errors: [] };
    const zero = ptr(0);
    const missingPath = Memory.allocUtf8String('');
    const boundedLength = new NativeFunction(Module.getExportByName(null, 'strnlen'),
        'ulong', ['pointer', 'ulong'], { traps: 'none' });

    function read(pointer, limit = 4096) {
        if (pointer.isNull()) return null;
        try {
            const length = Number(boundedLength(pointer, limit));
            return length < limit ? pointer.readUtf8String(length) : null;
        } catch (_) { return null; }
    }
    function normalized(path) {
        if (!path || path[0] !== '/') return null;
        const result = [];
        for (const part of path.split('/')) {
            if (!part || part === '.') continue;
            if (part === '..') result.pop(); else result.push(part);
        }
        return '/' + result.join('/');
    }
    function hiddenPath(path) {
        const value = normalized(path);
        return value !== null && hiddenFiles.some(prefix => value === prefix || value.startsWith(prefix + '/'));
    }
    function hiddenImage(path) {
        if (!path) return false;
        return path.split('/').pop() === agentName || path.startsWith(root + '/');
    }
    function address(name) { return Module.findExportByName(null, name); }
    function attach(name, callbacks) {
        const target = address(name);
        if (target === null) { report.missing.push(name); return; }
        listeners.push(Interceptor.attach(target, callbacks));
        report.installed.push(name);
    }
    function install(label, action) {
        try { action(); } catch (error) { report.errors.push(label + ': ' + error.message); }
    }

    install('dyld', () => {
        const countAddress = address('_dyld_image_count');
        const nameAddress = address('_dyld_get_image_name');
        if (!countAddress || !nameAddress) throw new Error('dyld exports unavailable');
        // These internal reads bypass interception and cannot recurse into this map.
        const rawCount = new NativeFunction(countAddress, 'uint', [], { traps: 'none' });
        const rawName = new NativeFunction(nameAddress, 'pointer', ['uint'], { traps: 'none' });
        let visible = [], lastCount = -1;
        function refresh(force) {
            const total = rawCount();
            if (!force && total === lastCount) return;
            if (total > 65536) throw new Error('unreasonable dyld image count');
            const next = [];
            for (let index = 0; index < total; index++) {
                if (!hiddenImage(read(rawName(index)))) next.push(index);
            }
            visible = next;
            lastCount = total;
        }
        attach('_dyld_image_count', {
            onLeave(result) {
                refresh(true);
                result.replace(ptr(visible.length));
            }
        });
        for (const name of ['_dyld_get_image_name', '_dyld_get_image_header', '_dyld_get_image_vmaddr_slide']) {
            attach(name, {
                onEnter(args) {
                    refresh(false);
                    const requested = args[0].toUInt32();
                    args[0] = ptr(requested < visible.length ? visible[requested] : 0xffffffff);
                }
            });
        }
    });

    install('dladdr', () => attach('dladdr', {
        onEnter(args) { this.info = args[1]; },
        onLeave(result) {
            if (result.toInt32() === 0 || this.info.isNull()) return;
            try {
                if (hiddenImage(read(this.info.readPointer()))) {
                    // Dl_info has four pointer-sized fields on both supported slices.
                    this.info.writeByteArray(new Uint8Array(Process.pointerSize * 4));
                    result.replace(zero);
                }
            } catch (_) { /* Preserve the OS result for unreadable caller buffers. */ }
        }
    }));

    install('filesystem', () => {
        // Redirect BEFORE the syscall: avoid opening/leaking the real file or
        // changing its metadata. Never manufacture a successful descriptor.
        const specs = [
            ['open', 0, false], ['openat', 1, false], ['fopen', 0, true],
            ['stat', 0, false], ['lstat', 0, false], ['access', 0, false],
            ['faccessat', 1, false], ['fstatat', 1, false], ['readlink', 0, false],
            ['readlinkat', 1, false], ['opendir', 0, true], ['realpath', 0, true]
        ];
        for (const [name, pathIndex, pointerResult] of specs) {
            attach(name, {
                onEnter(args) {
                    this.blocked = hiddenPath(read(args[pathIndex]));
                    if (this.blocked) args[pathIndex] = missingPath;
                },
                onLeave(result) {
                    if (this.blocked) {
                        result.replace(pointerResult ? zero : ptr(-1));
                        this.errno = 2; // Darwin ENOENT, per invocation/thread.
                    }
                }
            });
        }
    });

    install('environment', () => attach('getenv', {
        onEnter(args) {
            const name = read(args[0], 128);
            this.blocked = name !== null && name.toUpperCase().startsWith(alias.toUpperCase() + '_');
        },
        onLeave(result) { if (this.blocked) result.replace(zero); }
    }));

    // No hooks on strstr/memmem, thread enumeration, sysctl, or exception ports.
    // Global string suppression changes unrelated app behavior and is itself detectable.
    rpc.exports = { status: () => report };
    send({ type: 'bootstrap-ready', report });
})();
