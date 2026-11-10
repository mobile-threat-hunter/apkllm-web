#!/usr/bin/env python3
"""Native ground truth for xcheck.mjs: run apkllm's REAL Python layer on APKs and dump
exactly the objects the web demo shows (the wasm engine, plus domain.js's signing_block).

    cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
        ~/Project/apkllm-web/wasm-build/xcheck.py OUT.json APK... [--frost-key B64]...

Per APK: content_map, tamper_report, install_gate and extract_report for each manifest /
split-fact combination in GATE_CASES (since apkllm #67 all four are the engine's, passed
through by Python as by the web), extract_entry over every entry name (sha256 of the
device-faithful bytes, or the error), signing_block, build_traces, signing_certs (#58), and the
engine's frosting check (#59) and signing.frosting's view of it under the built-in key — plus under each --frost-key (a test key
crafted fixtures are signed with).
"""
import base64
import hashlib
import json
import sys

from apkllm import container, signing

core = container._core()

# (extract_native_libs, target_sdk, page_size, role facts); "default" = apk_role left out
GATE_CASES = [
    (None, None, 4096, {}),
    (None, 29, 4096, {"apk_role": None}),
    (True, 34, 4096, {"apk_role": "base"}),
    (False, 30, 4096, {}),
    (None, 30, 4096, {"apk_role": "split", "isolated_splits": True, "feature_split": False}),
    (False, 35, 16384, {"apk_role": "split", "config_for_split": True}),
    (None, 35, 4096, {"feature_split": True}),
]


def case_key(enl, tsdk, page, facts):
    return json.dumps([enl, tsdk, page, facts], sort_keys=True)


def extracted(path, names):
    """extract_entry per unique key — "x:<name_hex>" (the raw bytes of a lossy name, #40) or
    "s:<name>": sha256 of the device-faithful bytes, or the error."""
    out = {}
    for n in dict.fromkeys(names):
        key = bytes.fromhex(n[2:]) if n.startswith("x:") else n[2:]
        r = core.extract_entry(container._native_path(path), key, 512 * 1024 * 1024)
        out[n] = (
            {"ok": True, "disposition": r["disposition"], "size": len(r["data"]),
             "sha256": hashlib.sha256(r["data"]).hexdigest()}
            if r.get("ok") else {"ok": False, "error": r.get("error")}
        )
    return out


def exact(o):
    """An int past 2**53 as its decimal string — what the binding hands JS (a double would round it,
    and JSON.parse on the dump would round it the SAME way, hiding the loss)."""
    if isinstance(o, bool):
        return o
    if isinstance(o, int):
        return str(o) if abs(o) > 1 << 53 else o
    if isinstance(o, dict):
        return {k: exact(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [exact(v) for v in o]
    return o


def main(out, apks, frost_keys):
    keysets = [list(signing.FROSTING_KEYS_DEFAULT)] + [[k] for k in frost_keys]
    res = {"_frost_keysets": keysets}
    for p in apks:
        t = container.tamper_report(p)
        gates = {case_key(*c): container.install_gate(p, extract_native_libs=c[0], target_sdk=c[1], page_size=c[2], **c[3])
                 for c in GATE_CASES}
        g0 = gates[case_key(*GATE_CASES[0])]

        def key(e):
            return "x:" + e["name_hex"] if e.get("name_hex") else "s:" + e["name"]

        names = [key(e) for e in g0["entries"]] if g0.get("ok") else [
            key(e) for e in (t.get("entries") or [])]
        res[p] = {
            "content": container.content_map(p),
            "tamper": t,
            "gate": gates,
            "extract_report": {
                case_key(*c): container.extract_report(p, extract_native_libs=c[0], target_sdk=c[1], page_size=c[2], **c[3])
                for c in GATE_CASES
            },
            "extracted": extracted(p, names),
            "signing_block": container.signing_block(p),
            "build_traces": container.build_traces(p),
            "signing_certs": container.signing_certs(p),
            "frosting": [core.frosting(container._native_path(p), [base64.b64decode(k) for k in ks]) for ks in keysets],
            # signing.frosting's view (claim rules + container view) — domain.js frostingView mirrors it
            "frosting_view": [signing.frosting(p, frosting_keys=ks) for ks in keysets],
        }
    with open(out, "w") as f:
        json.dump(exact(res), f, default=lambda o: list(o) if isinstance(o, (set, bytes)) else str(o))
    print("wrote", out, "for", len(apks), "apk(s)")


if __name__ == "__main__":
    args, keys, i = sys.argv[2:], [], 0
    while "--frost-key" in args:
        i = args.index("--frost-key")
        keys.append(args[i + 1])
        del args[i : i + 2]
    main(sys.argv[1], args, keys)
