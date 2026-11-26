// SPDX-License-Identifier: GPL-2.0
// Second stage for the dexload-detect memload device test: loaded by
// AnubeeLoader only ever from memory (or a compressed jar entry).
public class Payload {
    public static String hello() { return "anubee-inmem-payload-ran"; }
}
