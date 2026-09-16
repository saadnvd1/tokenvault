# tokenvault

Central CLI token store. Encrypted, git-synced. Single JS file, zero deps.

## Architecture

- `cli.js` - Single file, Node.js built-in crypto
- `package.json` - npm global install (`npm i -g tokenvault`)
- `install.sh` - Alternative: creates `~/bin/tv` wrapper
- `~/.tokenvault/tokens.enc` - AES-256-CBC encrypted data (default path)
- `~/.config/tokenvault/master.key` - Decryption key, never committed
- `TOKENVAULT_DIR` env var - Override data directory (default: `~/.tokenvault`)
- `test/audit.test.js` - `npm test` (`node --test`, zero deps)
- `~/.local/state/tokenvault/audit.log` - JSONL audit of every get/dump (`TOKENVAULT_AUDIT_LOG` overrides). Entry names, pid, parent chain, cwd, Claude session id — NEVER values. Outside `~/.tokenvault` because that dir pushes to a remote
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

- `tv init` - Create vault git repo + generate master key
- `tv add <project> <token> [desc]` - Add/update token (auto-commits)
- `tv get <project> [desc]` - Print token value
- `tv list [project]` - List projects or tokens (masked)
- `tv remove <project> [desc]` - Remove token(s) (auto-commits)
- `tv dump` - Print decrypted JSON
- `tv remote <url>` - Set git remote for syncing
- `tv push` - Push tokens to remote
- `tv pull` - Pull tokens from remote
- `tv key-path` - Print master key location
- `tv audit [-n N]` - Recent reads from the audit log
- `tv audit check [--post]` - Flag dumps, >5 distinct entries/60s, 3+ missing-entry reads/60s; `--post` sends new findings to wire `tokenvault-audit` (cursor in `audit.log.state.json`). Schedule: see README "Running the check on a schedule"

## Standards

- The GitHub repo is PUBLIC: never commit tokens, keys, audit logs or state files
- Audit logging must stay best-effort — a logging failure never breaks `tv get`
- `cli.js` only runs the CLI when it is `require.main`; it exports `findAnomalies` for tests
- Conventional commits
- Single file, zero external deps
- Encryption via Node.js crypto (AES-256-CBC + PBKDF2, openssl-compatible)
