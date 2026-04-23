#!/bin/bash
set -e
BIN_DIR="$HOME/bin"
mkdir -p "$BIN_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cat > "$BIN_DIR/tv" << EOF
#!/bin/bash
exec node "$SCRIPT_DIR/cli.js" "\$@"
EOF
chmod +x "$BIN_DIR/tv"
echo "Installed: tv → $BIN_DIR/tv"
echo "Make sure $BIN_DIR is in your PATH"
