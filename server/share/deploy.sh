#!/bin/sh
# Deploys the lockbox share server to your Cloudflare account (free plan is plenty).
# Needs Node 20+ and, once, `npx wrangler login`. Run it again to update the server;
# each run makes a new creation token, so paste it into lockbox again afterwards.
set -eu
cd "$(dirname "$0")"
W="npx -y wrangler@4"

if ! $W whoami 2>/dev/null | grep -q "logged in"; then
  echo "Log in to Cloudflare first:  npx wrangler login"; exit 1
fi

echo "Deploying…"
OUT=$($W deploy 2>&1) || { echo "$OUT"; exit 1; }
URL=$(printf '%s\n' "$OUT" | grep -oE 'https://[a-zA-Z0-9.-]+\.workers\.dev' | head -1)
[ -n "$URL" ] || { printf '%s\n' "$OUT"; echo "Couldn't find the workers.dev address above."; exit 1; }

# only this token can create links; it never leaves your Mac except to Cloudflare's secret store
TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
printf '%s' "$TOKEN" | $W secret put CREATE_TOKEN >/dev/null
printf '%s' "$TOKEN" | pbcopy

cat <<MSG

Share server is live:  $URL
The token is on your clipboard.

In lockbox: Settings → Sharing → Set up…
  Server address:  $URL
  Token:           paste (⌘V)
MSG
