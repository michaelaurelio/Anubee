import frida, sys, json, time, subprocess, threading, os
PKG=os.environ.get("ARES_TEST_PKG", os.environ.get("PKG","icu.nullptr.applistdetector"))
OUT=open(sys.argv[1],"w")
ADB=os.environ.get("ADB","adb")
n=[0]
def on_msg(m,data):
    if m.get("type")=="send":
        OUT.write(m["payload"]+"\n"); OUT.flush(); n[0]+=1
    elif m.get("type")=="error":
        sys.stderr.write("JS ERR: %s\n"%m.get("description"))
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG])
sess=dev.attach(pid)
js=open("'oracle.bundle.js'").read()
scr=sess.create_script(js)
scr.on("message",on_msg)
scr.load()
dev.resume(pid)
def drive():
    time.sleep(6)
    for _ in range(3):
        for (x,y) in [(360,1114),(360,1258)]:
            subprocess.run([ADB,"shell","input","tap",str(x),str(y)]); time.sleep(1)
        subprocess.run([ADB,"shell","input","swipe","360","1200","360","600","300"]); time.sleep(1)
        subprocess.run([ADB,"shell","input","tap","360","900"]); time.sleep(1)
t=threading.Thread(target=drive); t.start()
time.sleep(26)
try: dev.kill(pid)
except: pass
print("collected %d messages"%n[0])
