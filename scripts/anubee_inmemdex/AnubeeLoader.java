// SPDX-License-Identifier: GPL-2.0
// Stand-in loader for the `mod dexload-detect` memload device test
// (scripts/device-test.sh), run with dalvikvm. After a delay for the tracer:
//   mem <payload.dex> -- read the DEX, delete the file, load it with
//                        InMemoryDexClassLoader (the DEX never exists on disk
//                        while it runs: ART holds it in "dalvik-DEX data")
//   jar <payload.jar> -- load a jar whose classes.dex is compressed, so ART
//                        extracts it into anonymous memory
//   jardel <src.jar> <dst.jar> -- write src to dst (a "drop" by this process),
//                        load dst and delete it at once, the way some
//                        droppers do: only the unpacked DEX in memory remains
// Then calls Payload.hello() and stays alive so the tracer can read it.
// Reflection only, so it compiles against a plain JDK.
import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.file.Files;

public class AnubeeLoader {
    public static void main(String[] args) throws Exception {
        Thread.sleep(3000);
        ClassLoader parent = AnubeeLoader.class.getClassLoader();
        ClassLoader cl;
        if (args[0].equals("mem")) {
            File f = new File(args[1]);
            byte[] dex = Files.readAllBytes(f.toPath());
            f.delete();
            Class<?> k = Class.forName("dalvik.system.InMemoryDexClassLoader");
            Constructor<?> c = k.getConstructor(ByteBuffer.class, ClassLoader.class);
            cl = (ClassLoader) c.newInstance(ByteBuffer.wrap(dex), parent);
        } else if (args[0].equals("jardel")) {
            File dst = new File(args[2]);
            Files.write(dst.toPath(), Files.readAllBytes(new File(args[1]).toPath()));
            Class<?> k = Class.forName("dalvik.system.PathClassLoader");
            Constructor<?> c = k.getConstructor(String.class, ClassLoader.class);
            cl = (ClassLoader) c.newInstance(dst.getPath(), parent);
            cl.loadClass("Payload");
            dst.delete();
        } else {
            Class<?> k = Class.forName("dalvik.system.PathClassLoader");
            Constructor<?> c = k.getConstructor(String.class, ClassLoader.class);
            cl = (ClassLoader) c.newInstance(args[1], parent);
        }
        Object r = cl.loadClass("Payload").getMethod("hello").invoke(null);
        System.out.println(r);
        Thread.sleep(3000);
    }
}
