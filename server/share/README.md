# lockbox share server

A tiny Cloudflare Worker behind lockbox's **Share…** links.

- It stores only **ciphertext**. The key is in the link after `#`, which browsers never send, so the server (and Cloudflare) can't read what you share.
- Each share is its own Durable Object: view counting is exact, the last allowed view deletes it, and an alarm deletes it at expiry.
- Only lockbox can create shares (a bearer token kept in your Keychain). Opening a link needs a click on **Reveal**, so link previews in chat apps don't use up a one-time link.
- A passphrase (optional) is checked in the recipient's browser *before* the view is used, so a typo never burns the link.

## Deploy (once, ~2 minutes)

```sh
npx wrangler login            # opens Cloudflare in your browser
./deploy.sh                   # prints the address, copies the token
```

Then in lockbox: **Settings → Sharing → Set up…** and paste both.
Re-running `deploy.sh` updates the server and rotates the token (paste the new one).

## Run locally

```sh
printf 'CREATE_TOKEN=local-test-token-123\nMIN_TTL_SECONDS=1\n' > .dev.vars
npx wrangler dev --port 8787
```

`test/recipient.js` drives a real browser through every share type against a local server (setup in its header).

## API

| | |
|---|---|
| `POST /api/shares` (token) | `{id, ciphertext, verifier, views: 1-100 \| null, ttl: 60-2592000, passphrase}` |
| `GET /api/shares/:id` | views left, expiry, whether a passphrase is needed (doesn't use a view) |
| `POST /api/shares/:id/open` | the ciphertext; counts one view |
| `DELETE /api/shares/:id` (token) | revoke |
| `GET /s/:id` | the viewer page (static; safe for link previews) |
