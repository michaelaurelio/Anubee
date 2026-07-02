// Ground-truth Java stack per libc syscall wrapper, via ART's own StackVisitor.
// Emits one JSONL object per hit: {tid, syscall, path, java_stack:[...]} (outermost-last).
//
// Frida 17 removed the global `Java` bridge and `Module.findExportByName`. This is an ESM
// source that imports frida-java-bridge; build a self-contained bundle before loading:
//
//   npm install frida-java-bridge
//   frida-compile oracle.js -o oracle.bundle.js
//   python3 run_oracle.py <out.jsonl>     # spawns $PKG, loads the bundle, drives UI
//
// (ART opens via open64/__openat, not the public openat export, so all three are hooked
//  and normalized to syscall:"openat" to overlap ares' openat-named frames; faccessat/
//  readlinkat via libcore Os.* reliably carry the app Java caller.)
import Java from 'frida-java-bridge';

function javaStack() {
  const frames = [];
  try {
    Java.perform(() => {
      const els = Java.use('java.lang.Thread').currentThread().getStackTrace();
      for (let i = 0; i < els.length; i++)
        frames.push(els[i].getClassName() + '.' + els[i].getMethodName());
    });
  } catch (e) {}
  return frames;
}

function resolve(name) {
  try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
  try { return Process.getModuleByName('libc.so').getExportByName(name); } catch (e) {}
  return null;
}

function hook(name, pathArgIndex, label) {
  const p = resolve(name);
  if (!p) return;
  const syscall = label || name;   // emitted join-key label (may differ from the export)
  Interceptor.attach(p, {
    onEnter(args) {
      let path = '';
      try { path = args[pathArgIndex].readUtf8String(); } catch (e) {}
      send(JSON.stringify({ tid: Process.getCurrentThreadId(), syscall: syscall,
                            path: path, java_stack: javaStack() }));
    }
  });
}

// pathArgIndex matches the libc wrapper arg positions; label normalizes the open family
// to "openat" so the (syscall, path) join key overlaps ares' openat frames.
hook('openat', 1);              // public export (ART bypasses it, but keep for completeness)
hook('__openat', 1, 'openat');  // bionic's actual openat bottleneck: __openat(dirfd, path, …)
hook('open64', 0, 'openat');    // open()/open64 family: open64(path, oflag, …)
hook('faccessat', 1);
hook('readlinkat', 1);
