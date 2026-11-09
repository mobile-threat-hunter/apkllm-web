#!/usr/bin/env python3
"""Native ground truth for xcheck.mjs: run apkllm's REAL Python layer on APKs and dump
exactly the objects the web demo derives in JS (domain.js over the wasm engine).

    cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
        ~/Project/apkllm-web/wasm-build/xcheck.py OUT.json APK...

Per APK: content_map (magic typing + checks), tamper_report (findings + checks) and
install_gate's native dict + _container_checks for each arsc_scope / extractNativeLibs
combination the UI can select (the Python install_gate wrapper derives arsc_scope from
role facts; the demo takes the scope directly, so the core binding is called the same way
wasm_module.cpp is). Plus extract_report (the four-reader decompression plan) per case and
extract_entry over every entry name — sha256 of the device-faithful bytes or the error.
And the structural signing-side reads: signing_block (the APK Signing Block's pairs) and
build_traces (v1 signer files, MANIFEST.MF main section, AGP app-metadata).
"""
import hashlib
import json
import sys

import apkllm
from apkllm import container

core = container._core()

GATE_CASES = [  # (extract_native_libs, target_sdk, arsc_scope, page_size)
    (None, None, None, 4096),
    (None, None, True, 4096),
    (True, 34, True, 4096),
    (False, 30, True, 4096),
    (None, 29, False, 4096),
    (False, 35, True, 16384),
]


def gate(path, enl, tsdk, scope, page):
    r = core.install_gate(path, enl, tsdk, page, arsc_scope=scope)
    if r.get("ok"):
        r["checks"] = container._container_checks(r)
    return r


def extract_report(path, enl, tsdk, scope, page):
    """The REAL container.extract_report, fed the same core gate the demo uses (arsc_scope
    given directly instead of derived from role facts)."""
    def core_gate(p, **kw):
        r = gate(p, enl, tsdk, scope, page)
        if r.get("ok"):  # role echo is the Python wrapper's; never compared
            r.update({k: r.get(k) for k in container.ROLE_ECHO_KEYS})
        return r

    real = container.install_gate
    container.install_gate = core_gate
    try:
        return container.extract_report(path, extract_native_libs=enl, target_sdk=tsdk, page_size=page)
    finally:
        container.install_gate = real


def extracted(path, names):
    """extract_entry per unique key — "x:<name_hex>" (the raw bytes of a lossy name, #40) or
    "s:<name>": sha256 of the device-faithful bytes, or the error."""
    out = {}
    for n in dict.fromkeys(names):
        key = bytes.fromhex(n[2:]) if n.startswith("x:") else n[2:]
        r = core.extract_entry(path, key, 512 * 1024 * 1024)
        out[n] = (
            {"ok": True, "disposition": r["disposition"], "size": len(r["data"]),
             "sha256": hashlib.sha256(r["data"]).hexdigest()}
            if r.get("ok") else {"ok": False, "error": r.get("error")}
        )
    return out


def main(out, apks):
    res = {}
    for p in apks:
        c = container.content_map(p)
        t = container.tamper_report(p)
        g0 = gate(p, None, None, None, 4096)
        def key(e):
            return "x:" + e["name_hex"] if e.get("name_hex") else "s:" + e["name"]

        names = [key(e) for e in g0["entries"]] if g0.get("ok") else [
            key(e) for e in (t.get("entries") or [])]
        res[p] = {
            "content": c,
            "tamper": t,
            "gate": {
                f"{enl}|{tsdk}|{scope}|{page}": gate(p, enl, tsdk, scope, page)
                for enl, tsdk, scope, page in GATE_CASES
            },
            "extract_report": {
                f"{enl}|{tsdk}|{scope}|{page}": extract_report(p, enl, tsdk, scope, page)
                for enl, tsdk, scope, page in GATE_CASES
            },
            "extracted": extracted(p, names),
            "signing_block": container.signing_block(p),
            "build_traces": container.build_traces(p),
        }
    with open(out, "w") as f:
        json.dump(res, f, default=lambda o: list(o) if isinstance(o, (set, bytes)) else str(o))
    print("wrote", out, "for", len(apks), "apk(s)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
