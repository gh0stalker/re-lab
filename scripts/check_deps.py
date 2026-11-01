#!/usr/bin/env python3
"""Supply-chain checks for the re-lab. Run on every commit (see scripts/security-check.sh).

Goal: a cloned copy of this repo can only install byte-for-byte the dependencies we pinned,
and every large artifact it downloads (Ghidra, llama.cpp, the model) is verified before use.
This catches the usual ways a malicious or swapped package sneaks in: an unhashed requirement,
a dependency pulled from a git/URL source, an install that doesn't enforce the hashes, or a
download whose integrity check was removed.

Standard library only, so it runs anywhere with python3 and needs no network.
Exits non-zero (and prints what failed) if any check fails.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
PROBLEMS: list[str] = []


def fail(msg: str) -> None:
    PROBLEMS.append(msg)


def read(rel: str) -> str:
    p = LAB / rel
    if not p.exists():
        fail(f"{rel}: missing")
        return ""
    return p.read_text(errors="replace")


# --------------------------------------------------------------------------- lock files
REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<ver>[^\s;]+)")
BAD_SOURCE = re.compile(r"(?:^|\s)(?:-e\b|--editable|git\+|hg\+|svn\+|bzr\+|file:|https?://)", re.I)


def check_lock(rel: str) -> None:
    """Every pinned requirement must carry a sha256 hash and come from the index (no VCS/URL)."""
    text = read(rel)
    if not text:
        return
    # uv/pip-compile write "name==ver \" then indented "--hash=sha256:..." continuation lines.
    # Split into blocks that each start at a requirement line.
    lines = text.splitlines()
    reqs = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        m = REQUIREMENT.match(line.strip())
        if not m:
            i += 1
            continue
        reqs += 1
        block = [line]
        j = i + 1
        while j < len(lines) and (lines[j].startswith((" ", "\t")) or lines[j].strip().startswith("--hash")):
            block.append(lines[j])
            j += 1
        blob = "\n".join(block)
        if "--hash=sha256:" not in blob:
            fail(f"{rel}: '{m.group('name')}=={m.group('ver')}' has no sha256 hash (unpinned = supply-chain risk)")
        i = j
    if reqs == 0:
        fail(f"{rel}: no pinned requirements found (expected name==version with hashes)")
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#") or s.startswith("--hash"):
            continue
        if BAD_SOURCE.search(s):
            fail(f"{rel}:{n}: installs from a VCS/URL/editable source, which runs arbitrary code: {s[:80]!r}")


def check_in_pinned_in_lock(in_rel: str, lock_rel: str) -> None:
    """Each exact pin in the .in must appear, same version, in the lock."""
    intext, locktext = read(in_rel), read(lock_rel)
    if not intext or not locktext:
        return
    for line in intext.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = REQUIREMENT.match(s)
        if not m:
            fail(f"{in_rel}: '{s}' is not an exact == pin; pin it so the lock is reproducible")
            continue
        if not re.search(rf"^{re.escape(m.group('name'))}=={re.escape(m.group('ver'))}\b",
                         locktext, re.M | re.I):
            fail(f"{in_rel}: '{s}' is not pinned to the same version in {lock_rel} (re-lock it)")


# --------------------------------------------------------------------------- install enforcement
def check_requires_hashes() -> None:
    """Wherever we install a lock, pip must run with --require-hashes and --only-binary=:all:
    (so it refuses an unhashed package and never builds from source, which runs setup.py)."""
    for rel in ("scripts/setup.sh", "ghidra/Dockerfile"):
        text = read(rel)
        if not text:
            continue
        # The lock may be referenced directly or via a shell variable (-r "$lock"), so look for a
        # pip/uv install line carrying --require-hashes, plus a reference to the lock file anywhere.
        install = re.search(r"(?:uv\s+)?pip\s+install[^\n]*--require-hashes", text)
        if not install:
            fail(f"{rel}: no 'pip install ... --require-hashes' found (hashes not enforced on install)")
        if "requirements.lock" not in text:
            fail(f"{rel}: does not reference requirements.lock (what is being installed?)")
        if "--only-binary" not in text:
            fail(f"{rel}: installs without --only-binary=:all: (may build a package from source)")


# --------------------------------------------------------------------------- download integrity
def check_pins_present() -> None:
    cfg = read("config.env")
    if not cfg:
        return
    checks = {
        "GHIDRA_SHA256": r'GHIDRA_SHA256="([0-9a-fA-F]{64})"',
        "LLAMA_CPP_COMMIT": r'LLAMA_CPP_COMMIT="([0-9a-fA-F]{40})"',
        "PYGHIDRA_MCP_VERSION": r'PYGHIDRA_MCP_VERSION="([0-9][^"]*)"',
    }
    for key, pat in checks.items():
        if not re.search(pat, cfg):
            fail(f"config.env: {key} is missing or not a valid pinned value")


def check_download_verification() -> None:
    """The three big downloads must each verify integrity before the artifact is used."""
    # Ghidra zip -> sha256 compared against GHIDRA_SHA256
    dockerfile = read("ghidra/Dockerfile")
    if dockerfile and not re.search(r"sha256sum|GHIDRA_SHA256|sha256", dockerfile):
        fail("ghidra/Dockerfile: downloads Ghidra without a sha256 verification step")
    # llama.cpp clone -> HEAD must equal the pinned commit
    getllama = read("scripts/get-llama.sh")
    if getllama and "LLAMA_CPP_COMMIT" not in getllama:
        fail("scripts/get-llama.sh: does not verify the checkout against LLAMA_CPP_COMMIT")
    # model GGUF -> sha256 compared against the Hugging Face LFS oid, pinned in MODEL.lock
    getmodel = read("scripts/get-model.sh")
    if getmodel and "sha256" not in getmodel.lower():
        fail("scripts/get-model.sh: does not verify the downloaded model's sha256")


# --------------------------------------------------------------------------- no pipe-to-shell
PIPE_TO_SHELL = re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.I)


def check_no_remote_exec() -> None:
    """No `curl ... | sh` style installers, and no pip trusting an arbitrary host/index."""
    for p in sorted(LAB.glob("scripts/*.sh")) + [LAB / "ghidra/Dockerfile", LAB / "llama/Dockerfile"]:
        if not p.exists():
            continue
        text = p.read_text(errors="replace")
        rel = p.relative_to(LAB)
        for n, line in enumerate(text.splitlines(), 1):
            if PIPE_TO_SHELL.search(line):
                fail(f"{rel}:{n}: pipes a download straight into a shell: {line.strip()[:80]!r}")
            if "--trusted-host" in line or re.search(r"--index-url(?!.*pypi\.org)", line):
                fail(f"{rel}:{n}: pip points at an untrusted/non-PyPI index: {line.strip()[:80]!r}")


def main() -> int:
    check_lock("agent/requirements.lock")
    check_lock("ghidra/requirements.lock")
    check_in_pinned_in_lock("agent/requirements.in", "agent/requirements.lock")
    check_in_pinned_in_lock("ghidra/requirements.in", "ghidra/requirements.lock")
    check_requires_hashes()
    check_pins_present()
    check_download_verification()
    check_no_remote_exec()

    if PROBLEMS:
        print(f"supply-chain check FAILED ({len(PROBLEMS)} problem(s)):", file=sys.stderr)
        for p in PROBLEMS:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("supply-chain check passed: dependencies hashed and index-only, downloads integrity-verified, no pipe-to-shell")
    return 0


if __name__ == "__main__":
    sys.exit(main())
