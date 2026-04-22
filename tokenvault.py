#!/usr/bin/env python3
"""tokenvault - Central CLI token store. Encrypted, git-synced.

Usage:
    tv init                     # generate master key (once per machine)
    tv add <project> <token> [description]
    tv get <project>            # prints token value only
    tv get <project> <desc>     # specific token by description
    tv list                     # all projects and descriptions
    tv list <project>           # all tokens for a project
    tv remove <project>         # remove all tokens for project
    tv remove <project> <desc>  # remove specific token
    tv dump                     # print entire file (for Claude)
    tv key-path                 # print master key location

Tokens stored encrypted (AES-256) in the repo. Master key stays local.
Any machine with master.key can decrypt.
"""

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


def ensure_key():
    if not KEY_FILE.exists():
        die(f"No master key. Run 'tv init' first.")


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
        die(f"Decryption failed. Wrong key or corrupted file.")
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


def cmd_init(_args):
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        print(f"Master key already exists: {KEY_FILE}")
        return
    # 32 bytes = 256 bits, hex encoded for easy copying
    key = secrets.token_hex(32)
    KEY_FILE.write_text(key)
    os.chmod(KEY_FILE, 0o600)
    os.chmod(KEY_DIR, 0o700)
    print(f"Master key generated: {KEY_FILE}")
    print(f"Copy this file to other machines at the same path.")


def cmd_add(args):
    if len(args) < 2:
        die("Usage: tv add <project> <token> [description]")
    project, token = args[0], args[1]
    desc = " ".join(args[2:]) if len(args) > 2 else ""
    data = load()
    if project not in data:
        data[project] = []
    for entry in data[project]:
        if entry.get("desc", "") == desc:
            entry["token"] = token
            save(data)
            print(f"Updated: {project}" + (f" ({desc})" if desc else ""))
            return
    data[project].append({"token": token, "desc": desc})
    save(data)
    print(f"Added: {project}" + (f" ({desc})" if desc else ""))


def cmd_get(args):
    if not args:
        die("Usage: tv get <project> [description]")
    project = args[0]
    desc_filter = " ".join(args[1:]) if len(args) > 1 else None
    data = load()
    if project not in data:
        die(f"No tokens for '{project}'")
    entries = data[project]
    if desc_filter:
        for e in entries:
            if e.get("desc", "") == desc_filter:
                print(e["token"])
                return
        die(f"No token '{desc_filter}' in {project}")
    if len(entries) == 1:
        print(entries[0]["token"])
    else:
        for e in entries:
            label = e.get("desc", "") or "(no desc)"
            print(f"{label}: {e['token']}")


def cmd_list(args):
    data = load()
    if not data:
        print("No tokens stored.")
        return
    if args:
        project = args[0]
        if project not in data:
            die(f"No tokens for '{project}'")
        for e in data[project]:
            desc = e.get("desc", "") or "(no desc)"
            masked = e["token"][:4] + "..." + e["token"][-4:] if len(e["token"]) > 12 else "****"
            print(f"  {desc}: {masked}")
        return
    for project, entries in sorted(data.items()):
        count = len(entries)
        descs = [e.get("desc", "") for e in entries if e.get("desc")]
        suffix = f" [{', '.join(descs)}]" if descs else ""
        print(f"  {project} ({count} token{'s' if count > 1 else ''}){suffix}")


def cmd_remove(args):
    if not args:
        die("Usage: tv remove <project> [description]")
    project = args[0]
    desc_filter = " ".join(args[1:]) if len(args) > 1 else None
    data = load()
    if project not in data:
        die(f"No tokens for '{project}'")
    if desc_filter:
        before = len(data[project])
        data[project] = [e for e in data[project] if e.get("desc", "") != desc_filter]
        if len(data[project]) == before:
            die(f"No token '{desc_filter}' in {project}")
        if not data[project]:
            del data[project]
        save(data)
        print(f"Removed: {project} ({desc_filter})")
    else:
        del data[project]
        save(data)
        print(f"Removed all tokens for: {project}")


def cmd_dump(_args):
    data = load()
    if not data:
        print("No tokens stored.")
        return
    print(json.dumps(data, indent=2))


def cmd_key_path(_args):
    print(KEY_FILE)


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


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
        print(__doc__.strip())
        sys.exit(0)
    cmd = args[0]
    if cmd not in COMMANDS:
        die(f"Unknown command: {cmd}\nRun 'tv help' for usage.")
    COMMANDS[cmd](args[1:])


if __name__ == "__main__":
    main()
