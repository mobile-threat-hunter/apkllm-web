"""Emit apkllm's ``signing.FROSTING_KEYS_DEFAULT`` as a C++ initializer list (web #17).

The frosting key is apkllm's (Play serves it as a server flag, so it can rotate): the web build
reads it from the checkout it compiles, never from a copy. The constant is read with ``ast`` —
apkllm is not imported — and must be a tuple of 1..16 base64 strings.

    python3 -I gen_frosting_keys.py APKLLM_ROOT/src/apkllm/signing.py OUT.inc
"""

import ast
import base64
import re
import sys

NAME = "FROSTING_KEYS_DEFAULT"


def main(src: str, out: str) -> None:
    with open(src, encoding="utf-8") as f:
        tree = ast.parse(f.read(), src)
    found = [
        n.value
        for n in tree.body
        if (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == NAME for t in n.targets))
        or (isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == NAME)
    ]
    if len(found) != 1:
        sys.exit(f"{src}: {len(found)} top-level assignments to {NAME} (expected 1)")
    keys = ast.literal_eval(found[0])
    if not isinstance(keys, tuple) or not 1 <= len(keys) <= 16:
        sys.exit(f"{src}: {NAME} is not a tuple of 1..16 keys")
    for k in keys:
        # base64 only: the literal goes into C++ source unescaped
        if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", k):
            sys.exit(f"{src}: {NAME} holds a non-base64 entry")
        base64.b64decode(k, validate=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"// generated from apkllm src/apkllm/signing.py {NAME} by gen_frosting_keys.py\n")
        f.writelines(f'"{k}",\n' for k in keys)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
