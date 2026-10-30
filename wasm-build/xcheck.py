#!/usr/bin/env python3
"""Native ground truth for xcheck.mjs: run apkllm's REAL Python layer on APKs and dump
exactly the objects the web demo derives in JS (domain.js over the wasm engine).

    cd ~/Project/apkllm && PYTHONPATH=src .venv/bin/python -P \
        ~/Project/apkllm-web/wasm-build/xcheck.py OUT.json APK...

Per APK: content_map (magic typing + checks), tamper_report (findings + checks) and
install_gate's native dict + _container_checks for each arsc_scope / extractNativeLibs
combination the UI can select (the Python install_gate wrapper derives arsc_scope from
role facts; the demo takes the scope directly, so the core binding is called the same way
wasm_module.cpp is).
"""
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


def main(out, apks):
    res = {}
    for p in apks:
        c = container.content_map(p)
        t = container.tamper_report(p)
        res[p] = {
            "content": c,
            "tamper": t,
            "gate": {
                f"{enl}|{tsdk}|{scope}|{page}": gate(p, enl, tsdk, scope, page)
                for enl, tsdk, scope, page in GATE_CASES
            },
        }
    with open(out, "w") as f:
        json.dump(res, f, default=lambda o: list(o) if isinstance(o, (set, bytes)) else str(o))
    print("wrote", out, "for", len(apks), "apk(s)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
