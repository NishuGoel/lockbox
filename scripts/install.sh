#!/bin/sh
# Builds lockbox from this checkout and installs it: the app into /Applications (replacing the
# old one cleanly, not copying over it) and the `lockbox` CLI into ~/.cargo/bin.
#   cd ~/projects/lockbox && git pull && ./scripts/install.sh
set -eu
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "Building lockbox $(git rev-parse --short HEAD)…"
(cd apps/desktop/src-tauri && cargo tauri build --bundles app >/dev/null)
cargo install --quiet --path crates/cli

osascript -e 'quit app "lockbox"' >/dev/null 2>&1 || true
for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f '/Applications/lockbox.app/' >/dev/null || break; sleep 0.5; done
rm -rf /Applications/lockbox.app.previous
[ -d /Applications/lockbox.app ] && mv /Applications/lockbox.app /Applications/lockbox.app.previous
cp -R target/release/bundle/macos/lockbox.app /Applications/
rm -rf /Applications/lockbox.app.previous
open /Applications/lockbox.app

echo "Installed: $(lockbox --version)"
echo "Browser extension: click ↻ on lockbox in chrome://extensions (Dia and Chrome)."
