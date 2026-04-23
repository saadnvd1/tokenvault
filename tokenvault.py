#!/usr/bin/env python3
"""tokenvault - Central CLI token store. Encrypted, git-synced.

Tokens stored encrypted (AES-256) in the repo. Master key stays local.
Any machine with master.key can decrypt.
"""

import difflib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

# Key lives outside repo, never committed
KEY_DIR = Path.home() / ".config" / "tokenvault"
KEY_FILE = KEY_DIR / "master.key"

# Encrypted data lives in repo dir (alongside this script)
REPO_DIR = Path(__file__).resolve().parent
ENC_FILE = REPO_DIR / "tokens.enc"

# ── Colors ───────────────────────────────────────────────────────────


def _ansi(code, stream="stdout"):
    is_tty = (sys.stdout if stream == "stdout" else sys.stderr).isatty()
    def wrap(text):
        return f"\033[{code}m{text}\033[0m" if is_tty else str(text)
    return wrap


green, red, yellow, cyan = _ansi("32"), _ansi("31"), _ansi("33"), _ansi("36")
bold, dim = _ansi("1"), _ansi("2")
bold_cyan, bold_green, bold_yellow = _ansi("1;36"), _ansi("1;32"), _ansi("1;33")
err_red, err_yellow = _ansi("1;31", "stderr"), _ansi("33", "stderr")

# ── Helpers ──────────────────────────────────────────────────────────


def pluralize(n, word="token"):
    return f"{n} {word}{'s' if n != 1 else ''}"


def project_label(project, desc=""):
    label = bold_cyan(project)
    if desc:
        label += f" {dim('(' + desc + ')')}"
    return label


def mask_token(token):
    if len(token) > 12:
        return token[:4] + dim("." * 8) + token[-4:]
    return yellow("****")


def print_token_table(entries, value_fn):
    """Print aligned desc/value columns. value_fn(entry) -> display string."""
    descs = [e.get("desc", "") or "(no desc)" for e in entries]
    max_w = max(len(d) for d in descs)
    for desc_str, e in zip(descs, entries):
        print(f"  {desc_str:<{max_w}}  {value_fn(e)}")


# ── Crypto ───────────────────────────────────────────────────────────


def ensure_key():
    if not KEY_FILE.exists():
        die(f"No master key. Run {err_yellow('tv init')} first.")


def encrypt(plaintext: bytes) -> bytes:
    result = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2",
         "-pass", f"file:{KEY_FILE}"],
        input=plaintext, capture_output=True
    )
    if result.returncode != 0:
        die(f"Encryption failed: {result.stderr.decode().strip()}")
    return result.stdout


def decrypt(ciphertext: bytes) -> bytes:
    result = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-pbkdf2",
         "-pass", f"file:{KEY_FILE}"],
        input=ciphertext, capture_output=True
    )
    if result.returncode != 0:
        die("Decryption failed. Wrong key or corrupted file.")
    return result.stdout


def load():
    ensure_key()
    if not ENC_FILE.exists():
        return {}
    ciphertext = ENC_FILE.read_bytes()
    plaintext = decrypt(ciphertext)
    return json.loads(plaintext)


def save(data):
    ensure_key()
    plaintext = json.dumps(data, indent=2).encode()
    ciphertext = encrypt(plaintext)
    ENC_FILE.write_bytes(ciphertext)


# ── Commands ─────────────────────────────────────────────────────────

def cmd_init(_args):
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        print(f"{yellow('!')} Master key already exists: {dim(str(KEY_FILE))}")
        return
    key = secrets.token_hex(32)
    KEY_FILE.write_text(key)
    os.chmod(KEY_FILE, 0o600)
    os.chmod(KEY_DIR, 0o700)
    print(f"{bold_green('✓')} Master key generated: {dim(str(KEY_FILE))}")
    print(f"  {dim('Copy this file to other machines at the same path.')}")


def cmd_add(args):
    if len(args) < 2:
        die(f"Usage: tv add {err_yellow('<project> <token>')} [description]")
    project, token = args[0], args[1]
    desc = " ".join(args[2:]) if len(args) > 2 else ""
    data = load()
    if project not in data:
        data[project] = []
    for entry in data[project]:
        if entry.get("desc", "") == desc:
            entry["token"] = token
            save(data)
            print(f"{bold_yellow('~')} Updated {project_label(project, desc)}")
            return
    data[project].append({"token": token, "desc": desc})
    save(data)
    print(f"{bold_green('+')} Added {project_label(project, desc)}")


def cmd_get(args):
    if not args:
        die(f"Usage: tv get {err_yellow('<project>')} [description]")
    project = args[0]
    desc_filter = " ".join(args[1:]) if len(args) > 1 else None
    data = load()
    if project not in data:
        die(f"No tokens for {err_yellow(project)}")
    entries = data[project]
    if desc_filter:
        for e in entries:
            if e.get("desc", "") == desc_filter:
                print(e["token"])
                return
        die(f"No token {err_yellow(desc_filter)} in {err_yellow(project)}")
    if len(entries) == 1:
        print(entries[0]["token"])
    else:
        print(f"{bold_cyan(project)} {dim('—')} {pluralize(len(entries))}")
        print()
        print_token_table(entries, lambda e: green(e["token"]))


def cmd_list(args):
    data = load()
    if not data:
        print(dim("No tokens stored."))
        return
    if args:
        project = args[0]
        if project not in data:
            die(f"No tokens for {err_yellow(project)}")
        entries = data[project]
        print(f"{bold_cyan(project)} {dim('—')} {pluralize(len(entries))}")
        print()
        print_token_table(entries, lambda e: yellow(mask_token(e["token"])))
        return
    n_proj = len(data)
    n_tok = sum(len(v) for v in data.values())
    print(f"{bold('TokenVault')} {dim('—')} {cyan(str(n_proj))} project{'s' if n_proj != 1 else ''}, {cyan(str(n_tok))} token{'s' if n_tok != 1 else ''}")
    print()
    for project, entries in sorted(data.items()):
        descs = [e.get("desc", "") for e in entries if e.get("desc")]
        desc_str = f"  {dim(', '.join(descs))}" if descs else ""
        print(f"  {bold_cyan(project)} {dim('(' + str(len(entries)) + ')')}{desc_str}")


def cmd_remove(args):
    if not args:
        die(f"Usage: tv remove {err_yellow('<project>')} [description]")
    project = args[0]
    desc_filter = " ".join(args[1:]) if len(args) > 1 else None
    data = load()
    if project not in data:
        die(f"No tokens for {err_yellow(project)}")
    if desc_filter:
        before = len(data[project])
        data[project] = [e for e in data[project] if e.get("desc", "") != desc_filter]
        if len(data[project]) == before:
            die(f"No token {err_yellow(desc_filter)} in {err_yellow(project)}")
        if not data[project]:
            del data[project]
        save(data)
        print(f"{red('−')} Removed {project_label(project, desc_filter)}")
    else:
        count = len(data[project])
        del data[project]
        save(data)
        print(f"{red('−')} Removed {project_label(project, pluralize(count))}")


def cmd_dump(_args):
    data = load()
    if not data:
        print(dim("No tokens stored."))
        return
    raw = json.dumps(data, indent=2)
    if not sys.stdout.isatty():
        print(raw)
        return
    for line in raw.splitlines():
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        if stripped.startswith('"') and '": ' in stripped:
            key, rest = stripped.split(": ", 1)
            print(f"{indent}{cyan(key)}: {green(rest)}")
        elif stripped.startswith('"'):
            print(f"{indent}{green(stripped)}")
        elif stripped.rstrip(",") in ("{", "}", "[", "]", "{}", "[]"):
            print(f"{indent}{dim(stripped)}")
        else:
            print(f"{indent}{stripped}")


def cmd_key_path(_args):
    print(KEY_FILE)


def die(msg):
    print(f"{err_red('error:')} {msg}", file=sys.stderr)
    sys.exit(1)


# ── Help ─────────────────────────────────────────────────────────────

HELP_TEXT = f"""\
{bold('TokenVault')} {dim('— encrypted CLI token store')}

{bold('Setup')}
  {cyan('tv init')}                          Generate master key (once per machine)

{bold('Store')}
  {cyan('tv add')} {dim('<project> <token>')} [desc]   Add or update a token
  {cyan('tv remove')} {dim('<project>')} [desc]        Remove token(s)

{bold('Retrieve')}
  {cyan('tv get')} {dim('<project>')} [desc]           Print token value (pipe-safe)
  {cyan('tv list')}                          All projects overview
  {cyan('tv list')} {dim('<project>')}                 Tokens for a project (masked)
  {cyan('tv dump')}                          Print all decrypted JSON

{bold('Info')}
  {cyan('tv key-path')}                      Print master key location

{dim('Aliases: ls=list, rm=remove')}
{dim('Encrypted with AES-256-CBC. Master key at ~/.config/tokenvault/master.key')}\
"""

COMMANDS = {
    "init": cmd_init,
    "add": cmd_add,
    "get": cmd_get,
    "list": cmd_list,
    "ls": cmd_list,
    "remove": cmd_remove,
    "rm": cmd_remove,
    "dump": cmd_dump,
    "key-path": cmd_key_path,
}


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(HELP_TEXT)
        sys.exit(0)
    cmd = args[0]
    if cmd not in COMMANDS:
        matches = difflib.get_close_matches(cmd, COMMANDS.keys(), n=1, cutoff=0.6)
        hint = f" Did you mean {err_yellow(matches[0])}?" if matches else ""
        die(f"Unknown command: {err_yellow(cmd)}.{hint}\n       Run {err_yellow('tv help')} for usage.")
    COMMANDS[cmd](args[1:])


if __name__ == "__main__":
    main()
