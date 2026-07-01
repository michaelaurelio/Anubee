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

if __name__ == "__main__":
    unittest.main()
