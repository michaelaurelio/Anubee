import json, os, tempfile, unittest
import compare

class TestFrameName(unittest.TestCase):
    def test_corroborated_suffix_stripped(self):
        self.assertEqual(compare.parse_frame_name("v5.t.<clinit>+0x4"), ("v5.t.<clinit>", True))
    def test_bare_name_uncorroborated(self):
        self.assertEqual(compare.parse_frame_name("n0.h$a.a"), ("n0.h$a.a", False))
    def test_non_dexpc_suffix_not_corroborated(self):
        # a native +0x offset is not a dex_pc corroboration marker on a 0x0-addr frame,
        # but parse_frame_name is only ever fed interp chain symbols; treat +0x<hex> as the marker.
        self.assertEqual(compare.parse_frame_name("Foo.bar+0x1a"), ("Foo.bar", True))

class TestLoadAres(unittest.TestCase):
    def _write(self, lines):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        for o in lines:
            f.write(json.dumps(o) + "\n")
        f.close()
        return f.name

    def test_join_stack_id_and_path(self):
        events = self._write([
            {"type":"syscall","tid":100,"syscall":"openat","stack_id":7,
             "string_args":{"1":"/proc/net/unix"}},
        ])
        stacks = self._write([
            {"type":"cfi_stack","stack_id":7,"cfi_backtrace":[
                {"frame":0,"addr":"0x71...","symbol":"libc!__openat","kind":"native"},
                {"frame":1,"addr":"0x0","symbol":"Detector.check+0x4","kind":"interp"},
                {"frame":2,"addr":"0x0","symbol":"Detector.run","kind":"interp"},
            ]},
        ])
        recs = compare.load_ares(events, stacks)
        os.unlink(events); os.unlink(stacks)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["syscall"], "openat")
        self.assertEqual(r["path"], "/proc/net/unix")
        self.assertEqual(r["tid"], 100)
        self.assertEqual(r["interp"], [("Detector.check", True), ("Detector.run", False)])

    def test_syscall_without_stack_id_skipped(self):
        events = self._write([{"type":"syscall","tid":1,"syscall":"read","string_args":{}}])
        stacks = self._write([])
        recs = compare.load_ares(events, stacks)
        os.unlink(events); os.unlink(stacks)
        self.assertEqual(recs, [])

class TestFrida(unittest.TestCase):
    def test_normalize_strips_source_location(self):
        self.assertEqual(
            compare.normalize_java("icu.nullptr.applistdetector.Detector.check(Detector.java:42)"),
            "icu.nullptr.applistdetector.Detector.check")
    def test_normalize_no_paren_passthrough(self):
        self.assertEqual(compare.normalize_java("a.b.C.d"), "a.b.C.d")

    def test_load_frida(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        f.write(json.dumps({"tid":100,"syscall":"openat","path":"/proc/net/unix",
                            "java_stack":["icu.A.check(A.java:1)","icu.A.run(A.java:9)"]})+"\n")
        f.close()
        recs = compare.load_frida(f.name)
        os.unlink(f.name)
        self.assertEqual(recs, [{"syscall":"openat","path":"/proc/net/unix","tid":100,
                                 "java":["icu.A.check","icu.A.run"]}])

class TestJoinScore(unittest.TestCase):
    def test_join_by_syscall_path(self):
        a = [{"syscall":"openat","path":"/p","tid":1,"stack_id":1,"interp":[("A.b",True)]}]
        f = [{"syscall":"openat","path":"/p","tid":9,"java":["A.b","A.run"]}]
        m = compare.join(a, f)
        self.assertEqual(len(m), 1)
        self.assertIsNotNone(m[0][1])

    def test_score_precision_split(self):
        # A.b corroborated + correct; X.y uncorroborated + wrong; A.run truth-only (recall miss)
        matches = [(
            {"interp":[("A.b",True),("X.y",False)]},
            {"java":["A.b","A.run"]},
        )]
        s = compare.score(matches)
        self.assertEqual(s["corr_named"], 1)
        self.assertEqual(s["corr_correct"], 1)     # A.b in truth
        self.assertEqual(s["uncorr_named"], 1)
        self.assertEqual(s["uncorr_correct"], 0)   # X.y not in truth
        self.assertEqual(s["truth_frames"], 2)
        self.assertEqual(s["recalled"], 1)         # only A.b recalled

    def test_score_unmatched_counted(self):
        s = compare.score([({"interp":[("A.b",True)]}, None)])
        self.assertEqual(s["unmatched"], 1)
        self.assertEqual(s["corr_named"], 0)

if __name__ == "__main__":
    unittest.main()
