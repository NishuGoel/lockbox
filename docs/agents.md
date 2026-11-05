# Using lockbox with Claude Code (and other agents)

Agents work with **references**, never secrets. A reference names a secret:

```
lockbox://<vault>/<item>/<field>      e.g. lockbox://Work/AWS Console/password
```

`<field>` is `password`, `username`, `url`, `notes`, `totp` (the current code) or any custom field name. References are safe in `.env` files, commands, commits and prompts.

## For API keys and tokens

```sh
lockbox ref aws                                  # list an item's references (no values)
lockbox run -- npm run deploy                    # lockbox:// values in the environment
lockbox run --env-file .env -- wrangler deploy   # or in a .env file
```

What happens:
1. lockbox brings its window to the front: *"Claude Code wants to use AWS Console › password to run `npm run deploy` in ~/projects/shop"* — **Deny / Allow once / Allow for 1 hour**.
2. Only after you approve are the values put into **that command's** environment.
3. If the command prints a secret, lockbox replaces it with `‹concealed by lockbox›` before Claude Code sees the output.

"Allow for 1 hour" covers the same agent, the same folder and the same secrets only. **Settings → Agents** limits which vaults agents may use, shows every request and decision, and has **Revoke all**.

The app must be open and unlocked (it's the one that asks you). `lockbox run` never asks for your password in the terminal.

## Tell Claude Code how to use it

Paste this into `~/.claude/CLAUDE.md` (all projects) or a project's `CLAUDE.md`:

```markdown
## Secrets: use lockbox, never ask me to paste them
- Find secrets with `lockbox ref <search>`; it prints lockbox:// references, never values.
- Put references (not values) in .env files: `API_KEY=lockbox://Work/Stripe/api key`.
- Run anything that needs secrets through lockbox: `lockbox run --env-file .env -- <command>`
  or `API_KEY=lockbox://... lockbox run -- <command>`. I approve each use in the lockbox app.
- Never print, echo, log or write secret values anywhere, and never commit real secrets.
- If a secret is missing, tell me which item to add to lockbox instead of asking for the value.
```

## Logging into websites

Coming next: a lockbox MCP server so Claude Code can ask "log in to github.com"; after you approve, the lockbox extension fills that site's login form in your browser without the password passing through Claude.
