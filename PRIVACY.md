# lockbox privacy policy

_Last updated: 4 November 2026_

lockbox is a password manager that runs on your Mac. This policy covers the lockbox app, its command-line tool, and the lockbox browser extension for Chrome and other Chromium browsers.

## The short version

- Your passwords, passkeys and other items are stored **encrypted on your Mac**. lockbox has no account system and **no servers that hold your vault**.
- The browser extension **only talks to the lockbox app on the same Mac**. It sends nothing to the developer or any third party.
- There is **no analytics, advertising or tracking** of any kind.

## What the browser extension handles, and why

| Data | When | What happens to it |
|---|---|---|
| The address of the page or frame you're on | When you focus a login field, open the popup, press the fill shortcut, or a site asks for a passkey | Sent to the lockbox app on your Mac to find logins saved for that site. Not stored. |
| Username and password you type into a login form | Only when you submit the form | Sent to the lockbox app to check whether it's new or changed, so it can offer to save it. Held in the browser's session memory (never written to disk) until you choose Save, Not now or Never, or for at most 3 minutes. |
| Logins and passkeys you choose to fill or use | When you pick one | Passed from the app to that page's own form fields or passkey request. Only for the site the login was saved for. |
| Sites you chose "Never for this site", and site + username pairs you chose "Not now" for | When you click those buttons | Kept in the extension's local storage on your Mac so it stops asking. "Not now" entries expire after 30 days. |

The extension communicates with the lockbox app through Chrome's native messaging, which stays on your computer.

## What the lockbox app sends over the internet

Only these, and only as described:

- **Share links you create.** The item you share is encrypted on your Mac first. Only the encrypted data goes to the share server *you* deploy (your own Cloudflare account). The key is in the part of the link after `#`, which is never sent to any server.
- **Update check.** Once a day the app asks GitHub for the public list of changes to lockbox, to tell you when an update exists. No vault data and no identifiers are sent. You can switch this off in Settings → About.
- **Backups**, if you turn them on, are copies of your encrypted vault written to a folder you choose (by default iCloud Drive). They can't be opened without your master password and Secret Key.

## Sharing, selling, and other uses

No user data is sold, shared with third parties, used for advertising, or used for anything other than filling and saving your logins and passkeys.

## Contact

Questions or concerns: open an issue at https://github.com/NishuGoel/lockbox/issues
