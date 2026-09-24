# Old Session — Web Exploitation (Easy)

> **Category:** Web Exploitation
> **Difficulty:** Easy
> **Flag:** `academy{s3t_s3ss10n_3xp1rat10n5_e3a46efc}`

## Challenge Overview

A simple comment-board web app lets users register, log in, and see a
"Welcome `<username>`" homepage. One of the seeded comments hints that
there's a hidden `/sessions` endpoint — and that endpoint turns out to leak
**every active session on the server**, including the admin's.

![Homepage while logged in as a normal user](images/01-homepage-syaadila.png)

## TL;DR

The server exposes a debug/leftover `/sessions` route that dumps the raw
server-side session store — every session key and its associated user —
with no authentication or access control on that route at all. Sessions
also never expire. Grabbing the admin's session ID from that leaked list
and swapping it into your own cookie is enough to be recognized as `admin`.

## Step-by-Step

### 1. Register and log in

Create a normal account and log in as usual. This lands on the homepage,
shown above, confirming the app tracks the logged-in user server-side via a
session.

### 2. Find the hidden `/sessions` endpoint

One of the seeded comments on the homepage drops a hint:

> *"Hey I found a strange page at /sessions"*

Appending `/sessions` to the app's domain:

```
http://chatelaine.cylabacademy.net:44592/sessions
```

...returns a dump of the server's active session store, with no auth
required to view it.

### 3. Read the leaked session list

The dump lists every live session key (the value normally stored in the
`session` cookie) alongside the account it belongs to:

```
1) session:lgCJTj3lktS6R_QX2jiDBkomeZtAPMDVLXikpOZiNaI, {'_permanent': True, 'key': 'admin'}
2) session:lolrmI6yqLPQQYmXc_rmf4vZ5QVdPv6QBnLYbD7Wu_I, {'_permanent': True, 'key': 'syaadila'}
```

Entry `1` is an **active admin session** — `_permanent: True` means it has
no expiry, so it's been sitting there valid indefinitely.

### 4. Swap in the admin session cookie

Editing the browser's `session` cookie to use the admin's session ID
(`lgCJTj3lktS6R_QX2jiDBkomeZtAPMDVLXikpOZiNaI`) and reloading the homepage
is enough — the server looks up that key server-side, finds it mapped to
`admin`, and treats the browser as the admin user.

### 5. Flag

The homepage now greets `admin` and reveals the flag directly:

![Homepage after swapping to the admin session, showing the flag](images/02-homepage-admin-flag.png)

```
academy{s3t_s3ss10n_3xp1rat10n5_e3a46efc}
```

## Root Cause

Two separate issues combine here:

1. **Information disclosure** — a `/sessions` debug endpoint was left
   exposed in production with no authentication, dumping the entire
   server-side session store to anyone who requests it.
2. **No session expiration** — sessions are created with `_permanent: True`
   and never rotated or expired, so a leaked session ID (like the admin's)
   remains valid indefinitely rather than becoming useless after a short
   window.

Even without the leak, server-side sessions that never expire are risky:
any session ID that ever gets exposed (logs, referrer headers, shoulder
surfing, XSS, etc.) stays exploitable forever.

## Remediation

- Remove debug/introspection routes like `/sessions` before deploying to
  production, or gate them behind strong authentication and IP allow-lists.
- Set sensible expiration on all sessions (`_permanent: False`, or a short
  `PERMANENT_SESSION_LIFETIME`) and rotate session IDs on login/privilege
  changes.
- Never expose the session store itself — treat the mapping of session ID
  → user identity as sensitive server-side data.
- Regenerate session identifiers after authentication to reduce the value
  of any previously leaked session ID.

## Tools Used

- Browser (URL navigation to `/sessions`, DevTools to edit the `session`
  cookie)
