#!/bin/sh
# Builds the Chrome Web Store upload: apps/extension minus tests, with the manifest "key" removed
# (the store assigns its own extension ID and rejects uploads that carry a key).
#   ./scripts/package-extension.sh   → dist/lockbox-extension-<version>.zip
set -eu
cd "$(dirname "$0")/.."
VERSION=$(python3 -c "import json;print(json.load(open('apps/extension/manifest.json'))['version'])")
STAGE=$(mktemp -d)
rsync -a --exclude test --exclude store --exclude '.DS_Store' apps/extension/ "$STAGE/"
python3 - "$STAGE/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m.pop("key", None)
json.dump(m, open(p, "w"), indent=2)
PY
mkdir -p dist
OUT="$PWD/dist/lockbox-extension-$VERSION.zip"
rm -f "$OUT"
(cd "$STAGE" && zip -qr -X "$OUT" .)
rm -rf "$STAGE"
echo "$OUT"
unzip -l "$OUT" | tail -1
