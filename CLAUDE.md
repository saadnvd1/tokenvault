# tokenvault

Central CLI token store. Encrypted, git-synced. Single-file Python, zero deps.

## Architecture

- `tokenvault.py` - Single file, stdlib + openssl CLI
- `install.sh` - Creates `~/bin/tv` wrapper
- `tokens.enc` - AES-256-CBC encrypted, committed to git
- `~/.config/tokenvault/master.key` - Decryption key, never committed

## Data Format (decrypted)

```json
{
  "project-name": [
    {"token": "sk-abc123", "desc": "openai key"},
    {"token": "ghp-xyz789", "desc": "github pat"}
  ]
}
```

## Commands

- `tv init` - Generate master key (once per machine)
- `tv add <project> <token> [desc]` - Add/update token
- `tv get <project> [desc]` - Print token value
- `tv list [project]` - List projects or tokens (masked)
- `tv remove <project> [desc]` - Remove token(s)
- `tv dump` - Print decrypted JSON
- `tv key-path` - Print master key location

## Standards

- Conventional commits
- Single file, stdlib only, no external deps
- Encryption via openssl subprocess
