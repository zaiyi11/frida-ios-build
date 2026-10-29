'use strict';
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const hooks = new Map();
let images = ['/usr/lib/A.dylib', '/usr/lib/q7m2x/q7m2x-agent.dylib', '/usr/lib/B.dylib'];
class Pointer {
    constructor(value) { this.value = value; }
    isNull() { return this.value === 0 || this.value === null; }
    toInt32() { return Number(this.value) | 0; }
    toUInt32() { return Number(this.value) >>> 0; }
    replace(value) { this.value = value.value; }
    readUtf8String(length) {
        if (typeof this.value !== 'string') throw new Error('bad read');
        return this.value.slice(0, length);
    }
    readPointer() { return new Pointer(this.value); }
    writeByteArray(bytes) { this.bytes = Array.from(bytes); }
}
const pointer = value => new Pointer(value);
const globals = {
    ptr: pointer, Uint8Array,
    Memory: { allocUtf8String: pointer },
    Process: { pointerSize: 8 },
    Module: { findExportByName: (_, name) => name, getExportByName: (_, name) => name },
    NativeFunction: function (name) {
        if (name === 'strnlen') return (p, limit) => {
            if (typeof p.value !== 'string') throw new Error('bad pointer');
            return Math.min(p.value.length, limit);
        };
        if (name === '_dyld_image_count') return () => images.length;
        if (name === '_dyld_get_image_name') return index => pointer(images[index] || 0);
        throw new Error('unexpected native call ' + name);
    },
    Interceptor: { attach: (name, callbacks) => { hooks.set(name, callbacks); return {}; } },
    rpc: {}, send: () => {}
};
vm.runInNewContext(fs.readFileSync(__dirname + '/guard.js', 'utf8').replace('__BUILD_ALIAS__', 'q7m2x'), globals);
assert.deepEqual(Array.from(globals.rpc.exports.status().errors), []);
function enter(name, args) {
    const context = { errno: 77 };
    hooks.get(name).onEnter.call(context, args);
    return context;
}
function leave(name, context, value) {
    const result = pointer(value);
    if (hooks.get(name).onLeave) hooks.get(name).onLeave.call(context, result);
    return result;
}
assert.equal(leave('_dyld_image_count', {}, images.length).value, 2);
for (const name of ['_dyld_get_image_name', '_dyld_get_image_header', '_dyld_get_image_vmaddr_slide']) {
    for (const [requested, expected] of [[0, 0], [1, 2], [2, 0xffffffff], [0xffffffff, 0xffffffff]]) {
        const args = [pointer(requested)];
        enter(name, args);
        assert.equal(args[0].value, expected, name);
    }
}
images.push('/usr/lib/C.dylib');
let args = [pointer(2)];
enter('_dyld_get_image_header', args);
assert.equal(args[0].value, 3);
images = ['/usr/lib/A.dylib', '/usr/lib/q7m2x/q7m2x-agent.dylib'];
assert.equal(leave('_dyld_image_count', {}, images.length).value, 1);
for (const [name, index, pointerResult] of [['open', 0, false], ['openat', 1, false], ['fopen', 0, true], ['stat', 0, false], ['lstat', 0, false], ['access', 0, false], ['opendir', 0, true], ['realpath', 0, true]]) {
    args = [pointer('/usr/lib/./q7m2x/../q7m2x/test'), pointer('/usr/lib/q7m2x/test')];
    const context = enter(name, args);
    assert.equal(args[index].value, '', name);
    assert.equal(leave(name, context, pointerResult ? 0 : -1).value, pointerResult ? 0 : -1);
    assert.equal(context.errno, 2, name);
}
for (const path of ['/usr/lib/q7m2x-other/test', '/usr/lib/normal', 'q7m2x/test', 0, 'x'.repeat(4096)]) {
    args = [pointer(path)];
    const context = enter('open', args);
    assert.equal(args[0].value, path);
    assert.equal(leave('open', context, 42).value, 42);
    assert.equal(context.errno, 77);
}
const info = pointer('/usr/lib/q7m2x/q7m2x-agent.dylib');
assert.equal(leave('dladdr', enter('dladdr', [pointer(100), info]), 1).value, 0);
assert.deepEqual(info.bytes, new Array(32).fill(0));
assert.equal(leave('getenv', enter('getenv', [pointer('Q7M2X_FOO')]), 'secret').value, 0);
assert.equal(leave('getenv', enter('getenv', [pointer('HOME')]), '/var/mobile').value, '/var/mobile');
assert.equal(hooks.has('strstr'), false);
assert.equal(hooks.has('memmem'), false);
console.log('PASS: dyld index parity, add/remove, boundaries, errno, dladdr, environment, hot-hook exclusion');
