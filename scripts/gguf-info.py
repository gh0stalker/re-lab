#!/usr/bin/env python3
"""Print a GGUF model's identity, special tokens and embedded chat template.

    scripts/gguf-info.py [models/<file>.gguf]     (default: the file in models/MODEL.lock)

Reads only the metadata header (standard library only, no model loading). Use it to
check whether a model carries its own chat template; if it doesn't, point
LLAMA_CHAT_TEMPLATE in config.env at the right file in templates/.
"""
import re
import struct
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
SKIP = {"tokenizer.ggml.merges", "tokenizer.ggml.token_type", "tokenizer.ggml.scores"}


def read_header(path: Path) -> dict:
    with open(path, "rb") as f:
        def num(fmt):
            return struct.unpack("<" + fmt, f.read(struct.calcsize("<" + fmt)))[0]

        def text():
            return f.read(num("Q")).decode("utf-8", "replace")

        def value(kind):
            if kind == 8:
                return text()
            if kind == 9:
                inner, count = num("I"), num("Q")
                return [value(inner) for _ in range(count)]
            return num(SCALARS[kind])

        if f.read(4) != b"GGUF":
            sys.exit(f"{path} is not a GGUF file")
        version, _tensors, nkv = num("I"), num("Q"), num("Q")
        meta = {"_version": version}
        for _ in range(nkv):
            key = text()
            meta[key] = value(num("I"))
        return meta


def main() -> None:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        lock = (LAB / "models" / "MODEL.lock").read_text()
        path = LAB / "models" / re.search(r'MODEL_FILE="([^"]+)"', lock).group(1)
    meta = read_header(path)
    tokens = meta.get("tokenizer.ggml.tokens", [])
    print(f"file:          {path.name} (GGUF v{meta['_version']})")
    print(f"name:          {meta.get('general.name', '?')}  arch: {meta.get('general.architecture', '?')}")
    arch = meta.get("general.architecture", "")
    if f"{arch}.context_length" in meta:
        print(f"trained ctx:   {meta[f'{arch}.context_length']}")
    for label, key in (("bos", "bos_token_id"), ("eos", "eos_token_id"), ("eot", "eot_token_id")):
        tid = meta.get(f"tokenizer.ggml.{key}")
        if tid is not None:
            print(f"{label} token:     {tid} {tokens[tid]!r}" if tid < len(tokens) else f"{label} token: {tid}")
    for marker in ("<|eot_id|>", "<|im_end|>", "<end_of_turn>", "<|end|>"):
        if marker in tokens:
            print(f"has token:     {marker}")
    tmpl = meta.get("tokenizer.chat_template")
    print("chat template:", "embedded" if tmpl else "NONE embedded (set LLAMA_CHAT_TEMPLATE in config.env)")
    if tmpl:
        print("-" * 60)
        print(tmpl)


if __name__ == "__main__":
    main()
