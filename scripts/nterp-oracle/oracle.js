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
// (openat is hooked but ART often opens via open64/__openat; faccessat/readlinkat via
//  libcore Os.* reliably carry the app Java caller.)
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

function hook(name, pathArgIndex) {
  const p = resolve(name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      let path = '';
      try { path = args[pathArgIndex].readUtf8String(); } catch (e) {}
      send(JSON.stringify({ tid: Process.getCurrentThreadId(), syscall: name,
                            path: path, java_stack: javaStack() }));
    }
  });
}

// index matches compare.py _PATH_ARG (libc wrapper arg positions)
hook('openat', 1);
hook('faccessat', 1);
hook('readlinkat', 1);
