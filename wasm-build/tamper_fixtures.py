#!/usr/bin/env python3
"""Synthesize the container shapes the web stack must handle, so smoke.mjs / xcheck
exercise the findings path and the JS↔Python drift cases found in review (real-world
fixtures are all clean).

    python3 tamper_fixtures.py OUT_DIR        # writes OUT_DIR/*.apk, prints the paths

No apkllm import. Shapes:
  dup.apk      Master-Key duplicate entry names   → duplicate_entry_name, would_open=False
  janus.apk    DEX magic prepended to a ZIP        → janus, would_open=False
  cdforge.apk  CD method forged to 0x00FF, LFH 0   → cd_lfh_method_mismatch + method_forgery
  ctor.apk     entry names whose extension is a JS Object.prototype key (ADV-1)
  shortbad.apk entry names libziparchive accepts but strict UTF-8 rejects — overlong NUL,
               surrogate, 5-byte lead, ≤16 bytes (embind decoder path) — plus BOM-prefixed
               names on both sides of emscripten's 16-byte decoder split (ADV-3)
  tail.apk     >512-byte 'unknown' entries whose 512-byte head is cut inside a UTF-8
               sequence: valid-incomplete (text) vs invalid continuation (binary) (ADV-5)
  readers.apk  every one of the four device readers, STORED / DEFLATED, plus a CD method
               forged to 99 per reader (strict readers reject, AssetManager reads raw)
               and the bundle's path cases: "../", a directory entry, a case-only twin,
               a DOS device stem, a 300-byte segment and tab/newline/CR/quote/formula names (copy), a real MD5
               collision pair and an identical-content pair (md5 naming)
"""
import struct
import sys
import zipfile
from pathlib import Path

DEX_MAGIC = b"dex\n035\x00" + b"\0" * 56
# The classic 128-byte MD5 collision pair (Wang & Yu 2005; the MD5 Wikipedia example): md5
# 79054025255fb1a26e4bc422aef54eb4 for both, 6 bytes apart.
MD5_COLL_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
MD5_COLL_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")


def build(path: Path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data, method in entries:
            z.writestr(zipfile.ZipInfo(name), data, compress_type=method)
    return path


def raw_zip(path: Path, entries):
    """Minimal STORED zip writer taking RAW BYTE names (zipfile insists on str names).
    gpbf bit 11 (UTF-8) set, like zipfile does for non-ASCII — libziparchive ignores it."""
    out = bytearray()
    cd = bytearray()
    for name, data in entries:
        crc = zipfile.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x800, 0, 0, 0, crc, len(data), len(data), len(name), 0)
        out += name + data
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x800, 0, 0, 0, crc, len(data), len(data),
                          len(name), 0, 0, 0, 0, 0, off)
        cd += name
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cd_off, 0)
    path.write_bytes(out)
    return path


def forge_cd_method(path: Path, name: str, method: int):
    raw = bytearray(path.read_bytes())
    i = raw.find(b"PK\x01\x02")
    while i >= 0:
        nlen = struct.unpack_from("<H", raw, i + 28)[0]
        if raw[i + 46 : i + 46 + nlen] == name.encode():
            struct.pack_into("<H", raw, i + 10, method)
            break
        i = raw.find(b"PK\x01\x02", i + 4)
    path.write_bytes(raw)


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    dup = build(out / "dup.apk", [("AndroidManifest.xml", b"REAL", zipfile.ZIP_STORED),
                                  ("AndroidManifest.xml", b"EVIL", zipfile.ZIP_STORED)])
    base = build(out / "base.apk", [("classes.dex", DEX_MAGIC, zipfile.ZIP_STORED)])
    janus = out / "janus.apk"
    janus.write_bytes(b"dex\n035\x00" + base.read_bytes())
    cdforge = build(out / "cdforge.apk", [("AndroidManifest.xml", b"M" * 64, zipfile.ZIP_STORED)])
    forge_cd_method(cdforge, "AndroidManifest.xml", 0x00FF)
    ctor = build(out / "ctor.apk", [("classes.dex", DEX_MAGIC, zipfile.ZIP_STORED),
                                    ("assets/a.constructor", b"hello\n", zipfile.ZIP_STORED),
                                    ("assets/b.__proto__", b"\x89PNG\r\n\x1a\n" + b"\0" * 8, zipfile.ZIP_STORED),
                                    ("assets/c.toString", b"x", zipfile.ZIP_STORED)])
    shortbad = raw_zip(out / "shortbad.apk", [
        (b"lib/\xc0\x80.so", b"\x7fELF" + b"\0" * 20),                 # overlong NUL
        (b"a/\xed\xa0\x80.so", b"\x7fELF" + b"\0" * 20),               # surrogate
        (b"b/\xf8\x88\x80\x80\x80.so", b"not an elf"),                 # 5-byte lead (decoy .so)
        (b"\xef\xbb\xbfa.txt", b"short bom"),                          # BOM, ≤16 bytes
        (b"\xef\xbb\xbfassets/a_long_enough_name.txt", b"long bom"),   # BOM, >16 bytes
        (b"assets/long_prefix_dir/\xc0\x80.so", b"x"),                 # overlong, >16 bytes
    ])
    # #40: names that are not strict UTF-8 — twins that RENDER alike (only name_hex tells them apart),
    # a literal U+FFFD sibling, each lossy shape libziparchive admits; > 20 mismatches for the sample
    elf, gif = b"\x7fELF" + bytes(60), b"GIF89a" + bytes(30)
    raw_zip(out / "lossy.apk", [
        (b"AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20)),
        (b"lib/arm64-v8a/\xc0\x81.so", elf + b"A"), (b"lib/arm64-v8a/\xc1\x81.so", elf + b"B"),  # twins, own bytes
        (b"lib/arm64-v8a/\xef\xbf\xbd\xef\xbf\xbd.so", elf),                        # literal U+FFFD x2
        (b"lib/arm64-v8a/z\xed\xa0\x80.so", elf), (b"lib/arm64-v8a/z\xed\xb0\x80.so", elf),
        (b"res/\xf5\x80\x80\x80.png", gif + b"1"), (b"res/\xf6\x80\x80\x80.png", gif + b"2"),
        (b"res/\xf4\x90\x80\x80.png", gif),
        (b"assets/\xf8\x88\x80\x80\x80.bin", b"x" * 40), (b"assets/\xfc\x84\x80\x80\x80\x80.bin", b"y" * 40),
        (b"res/raw/\xe0\x80\x80.txt", b"hello"), (b"res/raw/\xe0\x81\x80.txt", b"world"),
        *[(b"res/q%d\xc0\x80.jpg" % i, gif + bytes([i])) for i in range(24)],
    ])
    # a tamper finding ON a lossy name (entry_hex non-null): the same lossy name twice — Master Key
    raw_zip(out / "lossydup.apk", [
        (b"AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20)),
        (b"assets/\xc0\x81.bin", b"first"), (b"assets/\xc0\x81.bin", b"second"),
    ])
    tail = build(out / "tail.apk", [
        ("t1.bin", b"A" * 510 + b"\xe2\x41" + b"B" * 100, zipfile.ZIP_STORED),       # invalid continuation → binary
        ("t2.bin", b"A" * 509 + b"\xf0\x9f\x41" + b"B" * 100, zipfile.ZIP_STORED),   # invalid continuation → binary
        ("t3.bin", b"A" * 511 + b"\xe2" + b"B" * 100, zipfile.ZIP_STORED),           # incomplete → text
        ("t4.bin", b"A" * 510 + b"\xe2\x82" + b"B" * 100, zipfile.ZIP_STORED),       # incomplete → text
        ("t5.bin", b"A" * 511 + b"\xff" + b"B" * 100, zipfile.ZIP_STORED),           # invalid start → binary
        ("t6.bin", b"A" * 510 + b"\xe0\x80" + b"B" * 100, zipfile.ZIP_STORED),       # E0 needs A0.. → binary
    ])
    D, S = zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED
    readers = build(out / "readers.apk", [
        ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"m" * 600, D),
        ("classes.dex", DEX_MAGIC, S),
        ("classes2.dex", DEX_MAGIC + b"d" * 2000, D),
        ("classes3.dex", DEX_MAGIC, S),                        # forged → ART strict rejects
        ("lib/arm64-v8a/libz.so", b"\x7fELF" + b"z" * 3000, D),
        ("lib/arm64-v8a/libf.so", b"\x7fELF" + b"f" * 64, S),  # forged → NativeLibraryHelper rejects
        ("resources.arsc", b"\x02\x00\x0c\x00" + b"r" * 900, D),
        ("res/raw/r.bin", b"r" * 4000, D),
        ("res/raw/f.bin", b"FORGED-RES" * 8, S),               # forged → AssetManager lenient raw
        ("assets/a.bin", b"a" * 4000, D),
        ("assets/f.bin", b"FORGED-ASSET" * 8, S),              # forged → assets/ is AssetManager: lenient raw
        ("data.bin", b"FORGED-OTHER" * 8, S),                  # forged → generic libziparchive (other) rejects
        ("META-INF/F.SF", b"Signature-Version: 1.0\r\n", S),   # forged → libziparchive strict rejects
        ("../evil/x.txt", b"traversal name", S),               # output-path sanitization
        ("res/", b"", S),                                      # explicit directory entry
        ("assets/A.bin", b"upper-case twin", S),               # case-only clash with assets/a.bin
        ("assets/con.txt", b"dos device stem", S),
        ("assets/" + "L" * 300 + ".bin", b"long segment", S),  # > 255-byte file name
        ("assets/tab\there\nnewline.txt", b"tsv-hostile name", S),  # copy-as-TSV escaping
        ("assets/cr\rname.txt", b"cr", S),                        # click-copy must stay byte-exact (DOM turns CR → LF)
        ('"lead.txt', b"quote", S),                               # a leading quote must not open a sheet quoted field
        ("=HYPERLINK(1)", b"formula", S),                         # must not paste as a live formula
        ("assets/coll_a.bin", MD5_COLL_A, S),                     # a real MD5 collision pair (Wang–Yu):
        ("assets/coll_b.bin", MD5_COLL_B, S),                     #   same md5, different sha256 → {md5}.{sha256}.bin
        ("assets/twin1.bin", b"identical content" * 4, S),        # identical content → one {md5}.bin, both mapped
        ("assets/twin2.bin", b"identical content" * 4, S),
    ])
    for n in ("classes3.dex", "lib/arm64-v8a/libf.so", "res/raw/f.bin", "assets/f.bin", "META-INF/F.SF", "data.bin"):
        forge_cd_method(readers, n, 99)
    for p in (dup, janus, cdforge, ctor, shortbad, tail, readers):
        print(p)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
