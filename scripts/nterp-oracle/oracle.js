// Ground-truth Java stack per libc syscall wrapper, via ART.
// Emits one JSONL object per hit. Run: frida -U -f $PKG -l oracle.js --no-pause
'use strict';

function javaStack() {
  // Uses the ART VM's own stack walk — the authoritative managed backtrace.
  var frames = [];
  Java.perform(function () {
    var Thread = Java.use('java.lang.Thread');
    var els = Thread.currentThread().getStackTrace();
    for (var i = 0; i < els.length; i++) {
      var e = els[i];
      frames.push(e.getClassName() + '.' + e.getMethodName());
    }
  });
  return frames;
}

function hook(name, pathArgIndex) {
  var p = Module.findExportByName('libc.so', name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      var path = '';
      try { path = args[pathArgIndex].readUtf8String(); } catch (e) {}
      var rec = { tid: Process.getCurrentThreadId(), syscall: name,
                  path: path, java_stack: javaStack() };
      send(JSON.stringify(rec));
    }
  });
}

// index matches compare.py _PATH_ARG (libc wrapper arg positions)
hook('openat', 1);
hook('faccessat', 1);
hook('readlinkat', 1);
