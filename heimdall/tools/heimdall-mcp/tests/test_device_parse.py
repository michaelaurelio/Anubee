"""Unit tests for heimdall output parsing (no device required)."""

import device


LIB_OUTPUT = """\
package com.example -> uid 10234, logging library loads only
[lib] pid 17267  libstagefright.so        [0x7e35cf9000, 0x7e35e66000)  off=0x9c  inode=28284833
[lib] pid 17267  libstagefright.so        [0x7e35e66000, 0x7e35e69000)  off=0x209  inode=28284833
[lib] pid 17267  e_17267                  [0x7b6b877000, 0x7b6b9c7000)  off=0x34  inode=212353
[lib] pid 17369  libc.so                  [0x7d98295000, 0x7d9832d000)  off=0x44  inode=41
something unrelated
^Cno events dropped
"""

DUMP_OUTPUT = """\
[dump] e_22045 (pid 22045) -> ./e_22045.22045.7aea238000.so  (1778456 bytes, 1777664 from memory, rebuilt)
[dump] /data/data/com.x/e_22045 (deleted) @0x7aea3c0000: no ELF64 header in memory (unmapped/encrypted?)
[dump] wrote 1 module image matching 'e_[0-9]*' to .
"""


def test_parse_lib_lines():
    segs = device.parse_lib_lines(LIB_OUTPUT)
    assert len(segs) == 4
    first = segs[0]
    assert first["pid"] == 17267
    assert first["library"] == "libstagefright.so"
    assert first["start"] == 0x7e35cf9000
    assert first["end"] == 0x7e35e66000
    assert first["pgoff"] == 0x9c
    assert first["inode"] == 28284833


def test_aggregate_libraries_merges_segments():
    libs = device.aggregate_libraries(device.parse_lib_lines(LIB_OUTPUT))
    # libstagefright's two segments collapse to one record with a merged range.
    sf = [l for l in libs if l["library"] == "libstagefright.so"]
    assert len(sf) == 1
    assert sf[0]["segments"] == 2
    assert sf[0]["start"] == hex(0x7e35cf9000)
    assert sf[0]["end"] == hex(0x7e35e69000)
    names = {l["library"] for l in libs}
    assert {"libstagefright.so", "e_17267", "libc.so"} <= names


def test_parse_dump_lines():
    dumps = device.parse_dump_lines(DUMP_OUTPUT)
    assert len(dumps) == 1                 # only the real per-module line, not the error/summary
    d = dumps[0]
    assert d["name"] == "e_22045"
    assert d["pid"] == 22045
    assert d["device_path"] == "./e_22045.22045.7aea238000.so"
    assert d["bytes"] == 1778456
    assert d["from_memory"] == 1777664
    assert d["mode"] == "rebuilt"


def test_check_pkg_rejects_injection():
    import pytest
    for bad in ["com.x; rm -rf /", "$(reboot)", "a b", "", "../x"]:
        with pytest.raises(ValueError):
            device._check_pkg(bad)
    device._check_pkg("com.rmldemo.guardsquare.uat")   # valid, no raise


def test_clamp_seconds():
    assert device._clamp_seconds(-3) == 1
    assert device._clamp_seconds(10) == 10
    assert device._clamp_seconds(10_000) == device.MAX_SECONDS
    assert device._clamp_seconds("oops") == 8
