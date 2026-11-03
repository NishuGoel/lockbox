#!/bin/sh
# Serves the app UI with mock.js in place of the Tauri backend at http://127.0.0.1:8765
set -eu
cd "$(dirname "$0")"
OUT=$(mktemp -d)
cp -R ../ui/. "$OUT/" && cp mock.js "$OUT/"
sed -i '' 's|<script src="common.js" defer></script>|<script src="mock.js"></script><script src="common.js" defer></script>|' "$OUT/index.html" "$OUT/quick.html"
printf 'html{background:#15181f}\n' >> "$OUT/app.css"   # stands in for the dark window material
echo "http://127.0.0.1:8765  (password: correct horse battery)"
cd "$OUT" && exec python3 -m http.server 8765 --bind 127.0.0.1
