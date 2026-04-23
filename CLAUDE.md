# tokenvault

Central CLI token store. Encrypted, git-synced. Single JS file, zero deps.

## Architecture

- `cli.js` - Single file, Node.js built-in crypto
- `package.json` - npm global install (`npm i -g tokenvault`)
- `install.sh` - Alternative: creates `~/bin/tv` wrapper
- `~/.tokenvault/tokens.enc` - AES-256-CBC encrypted data (default path)
- `~/.config/tokenvault/master.key` - Decryption key, never committed
- `TOKENVAULT_DIR` env var - Override data directory (default: `~/.tokenvault`)
- `tokenvault.py` - Legacy Python version (deprecated, kept for reference)

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
- Single file, zero external deps
- Encryption via Node.js crypto (AES-256-CBC + PBKDF2, openssl-compatible)
