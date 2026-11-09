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
  many.apk     > 20 items in every check detail list, mixed name families, long lossy names (#49)
  bury.apk     a Master-Key duplicate after 21 per-entry findings (#49)
  readers.apk  every one of the four device readers, STORED / DEFLATED, plus a CD method
               forged to 99 per reader (strict readers reject, AssetManager reads raw)
               and the bundle's path cases: "../", a directory entry, a case-only twin,
               a DOS device stem, a 300-byte segment and tab/newline/CR/quote/formula names (copy), a real MD5
               collision pair and an identical-content pair (md5 naming)
  sigpairs.apk APK Signing Block with duplicate v2 / unknown IDs, observed IDs + build traces:
               v1 signer files (nested, wrong-case decoy), a MANIFEST.MF read by apksig's rules
               (blank lead lines, continuation, CRLF / CR, dotless-i "Built-By"), hostile
               app-metadata keys (__proto__, numeric, \x1c / U+FEFF whitespace, control chars)
  sigbad.apk   a malformed pair after a valid one (walk_error) + a forged-method MANIFEST.MF (unreadable)
  sigcut.apk   300 pairs (cap 256) with the only v2 pair at #290 — named counts the whole walk
  sigsplit.apk junk between the CD and the EOCD — cd_contiguous False with the block present
  mfcut.apk    a MANIFEST.MF main section running past the 4 KiB head; app-metadata, no final newline
  v1many.apk   70 v1 signature files — more than the 64 build_traces lists
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


def forge_cd_methods(path: Path, prefixes, method: int):
    """forge_cd_method for every entry whose RAW name starts with one of ``prefixes``."""
    raw = bytearray(path.read_bytes())
    i = raw.find(b"PK\x01\x02")
    while i >= 0:
        nlen = struct.unpack_from("<H", raw, i + 28)[0]
        if bytes(raw[i + 46 : i + 46 + nlen]).startswith(tuple(prefixes)):
            struct.pack_into("<H", raw, i + 10, method)
        i = raw.find(b"PK\x01\x02", i + 4)
    path.write_bytes(raw)


def with_signing_block(path: Path, pairs, junk_before_eocd: bytes = b""):
    """Insert an APK Signing Block (ID→value pairs, each ``(id, value)`` or raw pair bytes) between
    the last entry and the CD and fix the EOCD's CD offset; optional junk between CD and EOCD."""
    raw = bytearray(path.read_bytes())
    e = raw.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<II", raw, e + 12)
    body = b"".join(p if isinstance(p, bytes) else struct.pack("<QI", 4 + len(p[1]), p[0]) + p[1] for p in pairs)
    size = len(body) + 8 + 16
    block = struct.pack("<Q", size) + body + struct.pack("<Q", size) + b"APK Sig Block 42"
    eocd = bytearray(raw[e:])
    struct.pack_into("<I", eocd, 16, cd_off + len(block))
    path.write_bytes(bytes(raw[:cd_off]) + block + bytes(raw[cd_off:e]) + junk_before_eocd + bytes(eocd))
    return path


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
    # #49: > 20 items in every check detail list. Three name families whose raw-byte order
    # (A < C0 < E4) differs from their UTF-16/str order (A < U+4E00 < U+FFFD), so the kept 20
    # (raw-name order on both sides) mix strict and lossy names; STORED unaligned native libs (the
    # extractNativeLibs=false gate) and dex with the CD method forged to 99 (dex_gate /
    # method_forgery / all_deliverable / tamper findings); ELF-in-.png assets (content sample);
    # 300-byte lossy names (> 128 code points: the cut rendering, an astral char at the cut)
    fam = [(b"A", 10), (b"\xc0\xaf", 8), (b"\xe4\xb8\x80", 8)]
    names = lambda pre, suf: [pre + m + b"%02d" % i + suf for m, n in fam for i in range(n)]
    many = raw_zip(out / "many.apk", [
        (b"AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20)),
        *[(nm, elf + bytes([i])) for i, nm in enumerate(names(b"lib/x86/lib", b".so"))],
        # "lib/x86/lib" (11) + 116 U+FFFD puts an astral char at code point 127: the 128-cut keeps it
        # whole (a UTF-16-unit cut would split its surrogate pair)
        *[(b"lib/x86/lib" + b"\xc0\xaf" * 58 + b"\xf0\x9f\x98\x80" * 2 + b"%d.so" % i, elf) for i in range(2)],
        *[(b"classes%d.dex" % (i + 2), DEX_MAGIC + bytes([i])) for i in range(26)],
        *[(nm, elf) for nm in names(b"assets/", b".png")],
    ])
    forge_cd_methods(many, (b"lib/", b"classes"), 99)
    # #49: 21 per-entry findings walked first, then a Master-Key duplicate (file-level, tamper):
    # the check keeps the most severe first, one finding per id before any second
    bury = raw_zip(out / "bury.apk", [
        *[(b"assets/d%02d" % i, b"0123456789") for i in range(21)],
        (b"AndroidManifest.xml", b"REAL"), (b"AndroidManifest.xml", b"EVIL"),
    ])
    forge_cd_methods(bury, (b"assets/",), 99)
    # #49: a kept finding's detail quotes the names (lfh_name_mismatch: both) and is cut to 512 code
    # points, head + "…" + tail. 700-byte names, strict and lossy, the LFH copy's last byte changed;
    # "the local-file-header name ('" (29) + "assets/" (7) + 219 'a' puts an astral char at code
    # point 255, the last one the head keeps (a UTF-16-unit cut would split it)
    lfh = [b"assets/" + b"a" * 219 + b"\xf0\x9f\x98\x80" + b"%02d" % i + b"a" * 470 for i in range(12)]
    lfh += [b"assets/" + b"\xc0\xaf" * 340 + b"%02d" % i for i in range(12)]
    lfhlong = raw_zip(out / "lfhlong.apk", [(nm, b"x") for nm in lfh])
    d = bytearray(lfhlong.read_bytes())
    i = d.find(b"PK\x03\x04")
    while i >= 0:
        ln = struct.unpack_from("<H", d, i + 26)[0]
        d[i + 30 + ln - 1] ^= 1
        i = d.find(b"PK\x03\x04", i + 30 + ln + 1)
    lfhlong.write_bytes(bytes(d))
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
    S = zipfile.ZIP_STORED
    V2, V3, FROST, AGP, UNK = 0x7109871A, 0xF05368C0, 0x2146444E, 0x504B4453, 0x12345678
    mf = (b"\r\n\nManifest-Version: 1.0\r\nCreated-By: Android Gradle 8.1\r\n continued \xff\r"
          b"Bu\xc4\xb1lt-By: signflinger\nX-Odd\n\nName: classes.dex\nCreated-By: not-main\n")
    meta = ("\ufeffappMetadataVersion=1.1\n#comment=1\n!bang=1\nno separator\n__proto__=polluted\n2=two\n1=one\n"
            "\x1c spaced = value \x1f\nkey=a=b\nctl=\x1b[31mred\u202eevil\nandroidGradlePluginVersion=8.1.0\n").encode()
    sigpairs = build(out / "sigpairs.apk", [
        ("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S),
        ("META-INF/MANIFEST.MF", mf, zipfile.ZIP_DEFLATED),
        ("META-INF/BNDLTOOL.SF", b"Signature-Version: 1.0\r\n", S),
        ("META-INF/BNDLTOOL.RSA", b"0" * 8, S),
        ("META-INF/sub/dir/K.EC", b"0", S),
        ("META-INF/lower.sf", b"decoy: suffix match is case-sensitive", S),
        ("META-INF/com/android/build/gradle/app-metadata.properties", meta, S),
    ])
    with_signing_block(sigpairs, [(V2, b"first v2"), (V3, b"v3"), (UNK, b"u1"), (V2, b"second v2"),
                                  (UNK, b"u2"), (FROST, b"frost"), (AGP, b"agp"), (0x42726577, b"\0" * 4)])
    sigbad = build(out / "sigbad.apk", [("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S),
                                        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nCreated-By: x\n\n", S)])
    forge_cd_method(sigbad, "META-INF/MANIFEST.MF", 99)
    with_signing_block(sigbad, [(V2, b"ok"), struct.pack("<QI", 2, V3)])   # pair length < 4: malformed
    sigcut = build(out / "sigcut.apk", [("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S)])
    with_signing_block(sigcut, [(V2 if i == 289 else 0x1000 + i, b"x") for i in range(300)])
    sigsplit = build(out / "sigsplit.apk", [("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S)])
    with_signing_block(sigsplit, [(V2, b"v2")], junk_before_eocd=b"JUNK" * 4)
    long_mf = b"Manifest-Version: 1.0\n" + b"".join(b"X-Pad-%04d: %s\n" % (i, b"p" * 40) for i in range(120)) + b"Created-By: late\n\n"
    mfcut = build(out / "mfcut.apk", [
        ("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S),
        ("META-INF/MANIFEST.MF", long_mf, zipfile.ZIP_DEFLATED),
        ("META-INF/com/android/build/gradle/app-metadata.properties", b"a=1\nb=2", S),
    ])
    v1many = build(out / "v1many.apk", [("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(20), S)] +
                   [(f"META-INF/S{i:02d}.SF", b"Signature-Version: 1.0\n", S) for i in range(70)])
    for p in (dup, janus, cdforge, ctor, shortbad, tail, readers, sigpairs, sigbad, sigcut, sigsplit, mfcut, v1many):
        print(p)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
