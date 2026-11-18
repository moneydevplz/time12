# Time12 Pass: Add Sign-in to Your Site

Welcome! This guide shows you how to let people sign in to your site with their Time12 Pass account. You don't need to build a login form or manage passwords yourself, because Time12 Pass handles that on its own sign-in page.

**Here's the short version:**

1. Paste the client script into your page.
2. Add a "Sign in" button that calls `Time12Pass.signIn()`.
3. Add a sign-out button that calls `Time12Pass.logout()`.
4. Add the footer badge.
5. Host your page over https. You don't need to register anything first.

If you're new to this, start with the Quick start below, then come back to the detailed sections when you need them. Every step includes the code you need, so you can copy and paste as you go.

---

---

## Quick start

1. Paste the client script (Step 1) into your page unchanged.
2. Add a "Sign in" button wired to `Time12Pass.signIn()`.
3. Wire your sign-out button to `Time12Pass.logout()`.
4. Add the footer badge (Step 4).
5. Host the file over https. There is nothing to register.

---

## Step 1: The client

Put this in a `<script>` tag in the `<head>` of your page, before any code that uses `Time12Pass`.

```html
<script>
(() => {
  "use strict";

  const AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth";
  const LOGIN_URL = "https://pass.time12.xin/";
  const LOGIN_ORIGIN = "https://pass.time12.xin";

  const COOKIE = "time12pass_token";
  const STATE_KEY = "time12pass_state";
  const BOUNCE_KEY = "time12pass_bounce";
  const secure = location.protocol === "https:" ? "; Secure" : "";
  // Apps on time12.xin and its subdomains share one cookie, also set by the login page.
  const COOKIE_DOMAIN = "time12.xin";
  const onSharedDomain = location.hostname === COOKIE_DOMAIN || location.hostname.endsWith("." + COOKIE_DOMAIN);
  const cookieAttrs = `${onSharedDomain ? "; Domain=" + COOKIE_DOMAIN : ""}; Path=/; SameSite=Lax${secure}`;

  // ---- Cookie ----
  function readCookie() {
    const hit = document.cookie.split("; ").find((c) => c.startsWith(COOKIE + "="));
    return hit ? decodeURIComponent(hit.slice(COOKIE.length + 1)) : null;
  }
  function writeCookie(token, expiresAt) {
    const ms = new Date(expiresAt).getTime();
    const maxAge = Number.isFinite(ms) ? Math.max(0, Math.floor((ms - Date.now()) / 1000)) : 7 * 24 * 3600;
    document.cookie = `${COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAge}${cookieAttrs}`;
  }
  function clearCookie() {
    document.cookie = `${COOKIE}=; Max-Age=0${cookieAttrs}`;
  }

  // ---- Returning from a full-page sign-in: the token arrives in the URL fragment ----
  function takeTokenFromUrl() {
    if (!location.hash.includes("token=")) return false;
    const p = new URLSearchParams(location.hash.slice(1));
    const token = p.get("token");
    const expectedState = sessionStorage.getItem(STATE_KEY);
    history.replaceState(null, "", location.pathname + location.search); // keep the token out of the address bar
    sessionStorage.removeItem(STATE_KEY);
    if (!token || !expectedState || p.get("state") !== expectedState) return false; // not a sign-in we started
    writeCookie(token, p.get("expiresAt"));
    if (readCookie() !== token) throw new Error("Time12 Pass: this browser is blocking cookies for this site.");
    return true;
  }

  // A token counts only if it was made for THIS site.
  const audOk = (aud) => aud === location.origin || (aud === COOKIE_DOMAIN && onSharedDomain && location.protocol === "https:");

  // ---- Ask Time12 Pass whether a token is still valid ----
  async function verify(token) {
    const res = await fetch(AUTH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ action: "verify" }),
    });
    if (res.status === 401) return null; // bad, expired, or logged-out token
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) throw new Error("Time12 Pass: verify failed (" + res.status + ")");
    if (!audOk(data.aud)) return null; // made for another site: treat as signed out
    return { userId: data.userId, username: data.username, aud: data.aud, expiresAt: data.expiresAt };
  }

  function randomState() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function goToLogin(extra) {
    const state = randomState();
    sessionStorage.setItem(STATE_KEY, state);
    sessionStorage.setItem(BOUNCE_KEY, String(Date.now()));
    const back = location.origin + location.pathname + location.search;
    location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(back)}&state=${state}${extra}`;
  }

  // ---- Popup sign-in. Call this directly inside a click handler: browsers block
  // window.open() calls that don't happen synchronously during a user click. ----
  function signIn() {
    return new Promise((resolve, reject) => {
      const state = randomState();
      const url = `${LOGIN_URL}?popup=1&redirect=${encodeURIComponent(location.origin)}&state=${state}`;
      const popup = window.open(url, "time12pass", "width=420,height=640");
      if (!popup) {
        reject(new Error("Time12 Pass: popup blocked. Call signIn() directly inside a click handler."));
        return;
      }

      let done = false;
      function cleanup() {
        clearInterval(poll);
        window.removeEventListener("message", onMessage);
      }
      function onMessage(event) {
        if (event.origin !== LOGIN_ORIGIN) return; // only the Time12 Pass window we opened
        if (!event.data || event.data.type !== "time12pass" || event.data.state !== state) return; // not our request
        done = true;
        cleanup();
        try { popup.close(); } catch {}
        if (event.data.error) {
          reject(new Error(event.data.error === "cancelled" ? "Time12 Pass: sign-in was cancelled." : "Time12 Pass: " + event.data.error));
          return;
        }
        writeCookie(event.data.token, event.data.expiresAt);
        verify(event.data.token).then((user) => {
          if (user) return resolve(user);
          clearCookie();
          reject(new Error("Time12 Pass: sign-in didn't verify."));
        }).catch((err) => { clearCookie(); reject(err); });
      }
      const poll = setInterval(() => {
        if (popup.closed && !done) { cleanup(); reject(new Error("Time12 Pass: sign-in window was closed.")); }
      }, 500);
      window.addEventListener("message", onMessage);
    });
  }

  // ---- Public API ----
  async function requireLogin(options = {}) {
    takeTokenFromUrl();
    const token = readCookie();
    if (token) {
      const user = await verify(token); // throws if Time12 Pass can't be reached, so the person stays signed in
      if (user) {
        sessionStorage.removeItem(BOUNCE_KEY);
        return user;
      }
      clearCookie();
    }
    // Stop a redirect loop if the login page keeps sending the person straight back.
    if (Date.now() - Number(sessionStorage.getItem(BOUNCE_KEY) || 0) < 15000) {
      throw new Error("Time12 Pass: sign-in keeps sending you back. Check that the page is on https (or http://localhost) and that cookies and storage are allowed.");
    }
    goToLogin(options.switchAccount ? "&prompt=login" : "");
    return new Promise(() => {}); // the page is navigating away
  }

  async function getUser() {
    takeTokenFromUrl();
    const token = readCookie();
    return token ? verify(token) : null;
  }

  async function logout(returnTo = location.origin + "/") {
    const token = readCookie();
    clearCookie();
    if (token) {
      try {
        await fetch(AUTH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
          body: JSON.stringify({ action: "logout" }),
        });
      } catch {}
    }
    // End the shared session on the login page, then return.
    location.href = `${LOGIN_URL}?logout=1&redirect=${encodeURIComponent(returnTo)}`;
  }

  window.Time12Pass = { signIn, requireLogin, getUser, logout, token: readCookie };
})();
</script>
```

---

## Step 2a: Popup sign-in (recommended)

Keep the page as it is for signed-out visitors, and add a sign-in button.

```html
<div id="app">
  <!-- your existing content -->
  <button id="signIn" type="button" hidden>Sign in</button>
  <span id="who" hidden></span>
  <button id="signOut" type="button" hidden>Sign out</button>
</div>

<script>
  async function render() {
    const user = await Time12Pass.getUser().catch(() => null); // null if signed out; never redirects
    document.getElementById("signIn").hidden = !!user;
    document.getElementById("who").hidden = !user;
    document.getElementById("signOut").hidden = !user;
    if (user) {
      document.getElementById("who").textContent = user.username; // textContent, never innerHTML
      startApp(user); // your existing startup code
    }
  }

  document.getElementById("signIn").addEventListener("click", () => {
    // Call this first in the click handler, before any await.
    Time12Pass.signIn()
      .then(render)
      .catch((err) => { if (!/cancelled/.test(err.message)) alert(err.message); });
  });

  render();
</script>
```

## Step 2b: Full-page sign-in (alternative)

Use this when every part of the page requires sign-in.

```html
<div id="app" hidden>
  <span id="who"></span>
  <button id="signOut" type="button">Sign out</button>
</div>

<script>
  Time12Pass.requireLogin()
    .then((user) => {
      document.getElementById("app").hidden = false;
      document.getElementById("who").textContent = user.username;
      startApp(user);
    })
    .catch((err) => {
      document.body.textContent = err.message; // Time12 Pass can't be reached, or a setup problem
    });
</script>
```

`requireLogin()` behaves as follows:

| Situation | Result |
| --- | --- |
| Already signed in | Resolves immediately. No redirect. |
| Not signed in | Sends the person to `pass.time12.xin`, then returns them to your page, signed in. |
| Time12 Pass can't be reached | Rejects with an error. The person is **not** signed out. |

For a "switch account" button, call `Time12Pass.requireLogin({ switchAccount: true })`, or call `signIn()` again.

---

## Step 3: Sign out

```html
<button id="signOut" type="button">Sign out</button>
<script>
  document.getElementById("signOut").addEventListener("click", () => Time12Pass.logout());
</script>
```

To return somewhere else after sign-out: `Time12Pass.logout("https://your-site.example.com/goodbye")`.

---

## Step 4: Footer badge

Add this where you want the badge, or replace an existing "powered by" line:

```html
<footer class="t12-powered">Powered by <strong>Time12</strong></footer>
<style>
  .t12-powered { text-align: center; font-size: 11px; letter-spacing: 0.04em; opacity: 0.65; padding: 16px 0; }
  .t12-powered strong { font-weight: 700; letter-spacing: 0.06em; }
</style>
```

If you're replacing an existing badge, keep its styling and change only the text to **Powered by Time12**.

---

## Step 5: Hosting

Host the file over https (Netlify, GitHub Pages, Cloudflare Pages, or any static host). `http://localhost` works for testing. Opening the file from disk (`file://`) does not work.

There is nothing to register. Any https site can use Time12 Pass right away. If your site is outside `time12.xin`, the first person to sign in sees a one-time "Allow <site>?" screen on `pass.time12.xin`. After they click Allow, it is remembered. Sites on `time12.xin` and its subdomains skip this screen.

---

## Worked example: a site with its own login

### Before

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>My Notes</title></head>
<body>
  <form id="login">
    <input id="user" placeholder="Username">
    <input id="pass" type="password" placeholder="Password">
    <button>Log in</button>
  </form>

  <div id="app" style="display:none">
    <h1>My Notes</h1>
    <button id="logout">Sign out</button>
  </div>

  <script>
    document.getElementById("login").onsubmit = async (e) => {
      e.preventDefault();
      const r = await fetch("/api/login", {
        method: "POST",
        body: JSON.stringify({ username: user.value, password: pass.value }),
      });
      const d = await r.json();
      localStorage.setItem("token", d.token);
      showApp();
    };
    function showApp() {
      document.getElementById("login").style.display = "none";
      document.getElementById("app").style.display = "block";
      loadNotes(localStorage.getItem("token"));
    }
    document.getElementById("logout").onclick = () => { localStorage.removeItem("token"); location.reload(); };
    if (localStorage.getItem("token")) showApp();
  </script>
</body>
</html>
```

### After

Paste the full client from Step 1 into the `<head>`. It is shown as a placeholder below to keep the example short.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My Notes</title>
  <script>
    /* PASTE THE FULL TIME12 PASS CLIENT FROM STEP 1 HERE, UNCHANGED */
  </script>
</head>
<body>
  <button id="signIn" type="button" hidden>Sign in</button>

  <div id="app" hidden>
    <h1>My Notes</h1>
    <p>Signed in as <span id="who"></span></p>
    <button id="logout" type="button">Sign out</button>
  </div>

  <footer class="t12-powered">Powered by <strong>Time12</strong></footer>
  <style>
    .t12-powered { text-align: center; font-size: 11px; letter-spacing: 0.04em; opacity: 0.65; padding: 16px 0; }
    .t12-powered strong { font-weight: 700; letter-spacing: 0.06em; }
  </style>

  <script>
    async function render() {
      const user = await Time12Pass.getUser().catch(() => null);
      document.getElementById("signIn").hidden = !!user;
      document.getElementById("app").hidden = !user;
      if (user) {
        document.getElementById("who").textContent = user.username;
        loadNotes(Time12Pass.token());
      }
    }
    document.getElementById("signIn").addEventListener("click", () => {
      Time12Pass.signIn().then(render).catch((err) => { if (!/cancelled/.test(err.message)) alert(err.message); });
    });
    document.getElementById("logout").addEventListener("click", () => Time12Pass.logout());
    render();
  </script>
</body>
</html>
```

### Converting a typical site

| Your site has | Change it to |
| --- | --- |
| A login or register form | Remove it. Use `signIn()` or `requireLogin()`. |
| `fetch(".../login")` or `fetch(".../register")` from the page | Remove it. See [Migrating from direct sign-in](#migrating-from-direct-sign-in). |
| A token saved in `localStorage` or your own cookie | Remove it. Use `Time12Pass.token()`. |
| A sign-out button | Call `Time12Pass.logout()`. |
| A username display | Fill it from `user.username` using `textContent`. |
| Requests to your own server | Send `Authorization: Bearer ${Time12Pass.token()}`. |
| An older "powered by" badge | Replace it with Step 4. |
| A Content-Security-Policy | Add `connect-src https://lbujqhnadkwqgojbhalw.supabase.co`. |

---

## Calling your own server

Send the token with each request:

```js
const res = await fetch("/api/notes", {
  headers: { Authorization: `Bearer ${Time12Pass.token()}` },
});
if (res.status === 401) {
  // signed out or expired: show the sign-in button again
}
```

Your server must check the token with `verify` and trust only the `userId`, `username`, and `aud` it returns. Never trust a username sent by the browser. Use `userId` as the key for user data. You can cache a successful check for up to a minute.

**Always check `aud`.** It is the site the token was made for. Accept a token only if `aud` matches your own origin (for example, `https://your-site.example.com`), or `time12.xin` for apps on that domain.

### Node (Express)

```js
const AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth";
const SITE_AUDS = new Set(["https://your-site.example.com"]); // every origin your pages run on
const cache = new Map(); // token -> { user, until }

async function requireUser(req, res, next) {
  const token = (req.get("Authorization") || "").replace(/^Bearer /, "");
  if (!token) return res.status(401).json({ error: "Sign in required" });

  const hit = cache.get(token);
  if (hit && hit.until > Date.now()) { req.user = hit.user; return next(); }

  const r = await fetch(AUTH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ action: "verify" }),
  });
  if (r.status >= 500) return res.status(503).json({ error: "Sign-in service unavailable" });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || !data.success || !SITE_AUDS.has(data.aud)) {
    return res.status(401).json({ error: "Sign in required" });
  }

  req.user = { userId: data.userId, username: data.username };
  cache.set(token, { user: req.user, until: Date.now() + 60_000 });
  next();
}

app.get("/api/notes", requireUser, (req, res) => {
  // use req.user.userId as the key for this person's data
});
```

### Python

```python
import requests

AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth"
SITE_AUDS = {"https://your-site.example.com"}

def verify(token):
    """Return {"userId", "username"}, or None if the token is invalid, expired,
    logged out, or made for another site."""
    r = requests.post(
        AUTH_URL,
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "verify"},
        timeout=10,
    )
    if r.status_code == 401:
        return None
    r.raise_for_status()
    data = r.json()
    if not data.get("success") or data.get("aud") not in SITE_AUDS:
        return None
    return {"userId": data["userId"], "username": data["username"]}
```

---

## Storing the token for existing code

If your app reads a token from `localStorage` in many places, you don't need to rewrite each call. Copy the Time12 Pass result into the keys your app already uses:

```js
function onSignedIn(user) {
  localStorage.setItem("authToken", Time12Pass.token());
  localStorage.setItem("userId", user.userId);
  localStorage.setItem("username", user.username);
  startApp();
}

// Popup flow:
document.getElementById("signIn").addEventListener("click", () => Time12Pass.signIn().then(onSignedIn));
// Full-page flow:
// Time12Pass.requireLogin().then(onSignedIn);
```

On sign-out, clear those keys, then call `Time12Pass.logout()`:

```js
function signOut() {
  localStorage.removeItem("authToken");
  localStorage.removeItem("userId");
  localStorage.removeItem("username");
  Time12Pass.logout();
}
```

---

## How it works

### Popup flow

1. The person clicks "Sign in". Your click handler calls `Time12Pass.signIn()`, which opens:

   ```
   https://pass.time12.xin/?popup=1&redirect=<your origin, URL-encoded>&state=<random value>
   ```

   in a new window, and listens for a `message` event from `https://pass.time12.xin`.
2. If the person is already signed in on this browser, the popup finishes immediately. Otherwise they sign in (or create an account) in the popup. For a site outside `time12.xin`, they see the one-time "Allow" screen first.
3. The popup sends `window.opener.postMessage({ type: "time12pass", token, expiresAt, state }, "https://your-origin")`, targeted at your exact origin, and closes itself. On cancel, it sends `{ type: "time12pass", error: "cancelled", state }` instead.
4. Your page checks that `event.origin` is `https://pass.time12.xin` and that `state` matches, stores the token (a cookie works well), and calls `verify`. It accepts the token only if `aud` is its own site.
5. On later visits, the app calls `verify` through `Time12Pass.getUser()`. A `null` result means showing the "Sign in" button again.

`Time12Pass.signIn()` does steps 1 to 4 and resolves with the verified user.

**Popups need a direct user click.** Browsers block `window.open()` unless it runs synchronously inside a click handler. Do not call it after an `await`, inside a `.then()`, or in a `setTimeout`.

### Full-page flow

1. The app has no valid token, so it sends the person to:

   ```
   https://pass.time12.xin/?redirect=<your page, URL-encoded>&state=<random value>
   ```

2. If the person is already signed in on this browser, the login page sends them straight back. Otherwise they sign in first.
3. They return to your page with the token in the fragment:

   ```
   https://your-app.example.com/page#token=...&expiresAt=...&state=...
   ```

   The fragment is never sent to servers, so the token stays out of server logs. The token is made only for the site that asked (its `aud` is that origin).
4. The app checks that `state` matches, stores the token, removes the fragment from the address bar, and calls `verify`.
5. On later visits, the app calls `verify`. A 401 response means sending the person to the login page again.

`requireLogin()` does steps 1 to 5 for you.

### Login page parameters

| Parameter | Meaning |
| --- | --- |
| `redirect` | Where to send the person after sign-in (full-page flow), or the origin to message back (popup flow). Must be https, or `http://localhost` / `http://127.0.0.1` for testing. Sites outside `time12.xin` show a one-time "Allow" screen first, which the person completes themselves. |
| `popup=1` | Finish with `postMessage` to the opener and close, instead of navigating. Takes effect only when the page was opened with `window.open()`; otherwise the full-page flow applies. |
| `state` | A random value your app creates. It is returned unchanged so your app can confirm the sign-in is one it started. |
| `prompt=login` | Show the form even if the person is already signed in. Use this for "switch account". |
| `logout=1` | Sign the person out of the shared session, then go to `redirect`. With `popup=1` and an opener, it posts `{ loggedOut: true }` back and closes. |

### Apps on time12.xin

When someone signs in, the login page also sets a `time12pass_token` cookie for `.time12.xin`. It holds a token made for `time12.xin`. Any app on `time12.xin` or a subdomain can read it, so those apps are signed in without any redirect. The Step 1 client already does this.

### Signing out

`Time12Pass.logout()` revokes the token, clears the cookie, and ends the shared session on `pass.time12.xin`. That also ends every site token made from that session, so all connected apps sign out together.

---

## API reference

**Endpoint** (every call is a `POST` with a JSON body):

```
https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth
```

No API key is needed, and CORS is open.

| Action | Send | Success response | Errors |
| --- | --- | --- | --- |
| `register` | `{ action, username, password }` | 201 `{ success, userId, username, token, expiresAt }` | 400, 409, 410, 429 |
| `login` | `{ action, username, password }` | 200 `{ success, userId, username, token, expiresAt }` | 400, 401, 410, 429 |
| `issue` | `{ action, audience }` with `Authorization: Bearer <session token>` | 200 `{ success, userId, username, aud, token, expiresAt }` | 400, 401, 429 |
| `verify` | `{ action }` with `Authorization: Bearer <token>` | 200 `{ success, userId, username, aud, expiresAt }` | 401 |
| `whoami` | Same as `verify` (older name) | Same as `verify` | 401 |
| `logout` | `{ action }` with `Authorization: Bearer <token>` | 200 `{ success }` | 401 |

`register` and `login` return a **session token** (`aud` is `pass`). Only the login page uses it: it exchanges it with `issue` for a token made for one site. Your app receives only that site token.

### Command-line examples

Log in:

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"action":"login","username":"sam","password":"secret"}'
```

Check a token:

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"action":"verify"}'
```

Log out:

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"action":"logout"}'
```

Get a token for your site (use the session token from `login`):

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <session token from login>" \
  -d '{"action":"issue","audience":"https://your-site.example.com"}'
```

### Checking a token in JavaScript

```js
async function checkToken(token) {
  const res = await fetch("https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ action: "verify" }),
  });
  const data = await res.json();
  const onTime12Domain = location.hostname === "time12.xin" || location.hostname.endsWith(".time12.xin");
  const expectedAud = onTime12Domain && location.protocol === "https:" ? "time12.xin" : location.origin;
  return res.ok && data.success && data.aud === expectedAud ? { userId: data.userId, username: data.username } : null;
}
```

### The token

- It is a signed string (`payload.signature`), not a JWT. Treat it as opaque and always check it with `verify`.
- Each token is made for one audience, `aud`:
  - a **session** token (`aud` is `pass`), kept by the login page
  - a **site** token (`aud` is that site's origin, such as `https://notes.example.com`)
  - a **first-party** token (`aud` is `time12.xin`), for apps on `time12.xin` and its subdomains
- Reject any token whose `aud` is not your own site.
- Tokens last 7 days from login. There is no refresh; after that the person signs in again.
- A new login does not cancel earlier sessions. Each one stays valid until it expires or is logged out.
- `logout` revokes the token. Logging out a session also ends every site token made from it.
- `verify` fails if the account has been deleted.

### Errors

Every failure has the form `{ "success": false, "error": "message" }`. Check the HTTP status code, not the wording.

| Status | Meaning |
| --- | --- |
| 400 | Invalid input: missing field, invalid username or password, invalid JSON, or unknown action |
| 401 | Wrong username or password, or an invalid, expired, or logged-out token |
| 409 | Username already taken |
| 410 | `login` or `register` called directly from another site's page after the cutoff (see [Migrating from direct sign-in](#migrating-from-direct-sign-in)) |
| 429 | Too many attempts. The response includes `retryAfter` (seconds). |
| 500 | Server problem. Try again later. |

Treat any text a user typed, including usernames, as plain text. Never insert it into page HTML directly.

### Usernames and sub-accounts

- Letters, digits, and `#` only, up to 20 characters. Stored in lowercase; login is not case-sensitive.
- `org@` is an organization account. `name@org` is a sub-account that belongs to an organization.
- `register` rejects `@`. An organization's manager creates its sub-accounts.
- Sub-accounts sign in with the full `name@org`. `verify` returns that full string as `username`.

### Passwords

- Passwords are compared exactly as typed. Keep passwords on the Time12 Pass sign-in page. If your form trims input, do the same on register and login.
- `register` rejects passwords that start or end with a space, and passwords over 128 characters.

### Rate limits

- Login: 10 attempts per username per 15 minutes (a successful login resets the count), and 100 per IP address per 10 minutes.
- Register: 20 per IP address per hour.
- Issue: 120 per person per 10 minutes.
- Past a limit, the response is 429 with `retryAfter`.

---

## Security model

Any site can request a sign-in. The "Allow" screen prevents a link that someone builds by hand from sending a token to an unknown site. It shows the full address of the requesting site and sends nothing until the person clicks Allow. The login page also checks `state`, sends tokens in the fragment or a targeted `postMessage` (never broadcast), and accepts only https or localhost addresses.

A site the person allows receives a token made only for that site. Its `aud` is the site's origin. Your server should check `aud`, so a token from one site cannot be used on another. Only a session token can create site tokens, and sessions stay on the login page.

Keep in mind:

- An allowed site can act for the person on that site for up to 7 days, so only allow sites you trust.
- A server that does not check `aud` accepts a token made for any site. Add the check shown in "Calling your own server".
- The shared `time12.xin` token works in every app on `time12.xin` and its subdomains.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `signIn()` rejects with "popup blocked" | `window.open()` ran after an `await` or outside the click handler. Make `signIn()` the first call in the click handler. |
| `signIn()` rejects with "sign-in window was closed" | The person closed the popup before finishing. This is expected. |
| `signIn()` rejects with "sign-in was cancelled" | The person chose Cancel on the "Allow" screen. This is expected, and the example above ignores it. |
| "The redirect address must use https" | The page is served over `http://` or `file://`. Host it over https, or use `http://localhost` for testing. |
| Sign-in keeps sending you back (full-page flow) | The browser drops the `#token` fragment or blocks storage. Allow cookies and storage for the site, then reload. |
| "This browser is blocking cookies for this site" | Cookies are blocked (private mode or strict settings). Allow cookies for the site. |
| Signed in on the login page, but the app asks you to sign in again | `verify` returned an `aud` that doesn't match this site's origin. Protocol, host, and port all matter, so open the page on the same origin you signed in from. Tokens issued before per-site tokens existed also require signing in again. |
| `verify` returns 401 right after sign-in | The token was altered. Check that the `state` handling and the `postMessage` listener are unchanged, and paste the client again as-is. |
| The app's server returns 401 | The server isn't sending `Authorization: Bearer <token>` to `verify`, or the cached result is older than a minute. |
| `Time12Pass is undefined` | The client `<script>` appears after the code that uses it. Move it earlier. |
| CSP error mentioning `supabase.co` | Add `connect-src https://lbujqhnadkwqgojbhalw.supabase.co` to the Content-Security-Policy. |

---

## Migrating from direct sign-in

Some sites call `register` or `login` directly from their own page, sending the password from a form on the site. That pattern is being retired.

### Timeline

| When | What happens |
| --- | --- |
| Now | Direct `register` or `login` calls from another site's page still work. A successful response also includes a `deprecation` object (`message`, `sunsetAt`, `daysLeft`, `migrateTo`). |
| **2026-12-18, 00:00 Gulf Standard Time (UTC+4)** | The same direct call from another site's page returns `410 Gone` with `code: "use_redirect"` and a `loginUrl`. |

The cutoff is `2026-12-18T00:00:00+04:00`. `verify`, `logout`, and `issue` are not affected. Calls from `pass.time12.xin` itself, and calls from a server with no `Origin` header, are not affected either.

### What is affected

- **Affected:** a browser page on a site other than `pass.time12.xin` calling `register` or `login` directly with `fetch()`. The browser sends an `Origin` header on this request automatically.
- **Not affected:** server-side calls with no `Origin` header, `pass.time12.xin` itself, and all calls to `verify`, `logout`, or `issue`.

### How to migrate

Before:

```js
// Stops working on 2026-12-18
async function login(username, password) {
  const res = await fetch("https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "login", username, password }),
  });
  const data = await res.json();
  if (data.success) localStorage.setItem("token", data.token);
  return data;
}
```

After:

```js
document.getElementById("signInButton").addEventListener("click", () => {
  Time12Pass.signIn().then(() => {
    localStorage.setItem("token", Time12Pass.token()); // only if other code reads this key
  });
});
```

Remove your own login form and the direct `fetch()`. `signIn()` opens the Time12 Pass form in a popup, so passwords never pass through your page's JavaScript. For an automatic flow with no button, use `Time12Pass.requireLogin()`.

If your backend handles passwords itself, that remains supported with no deadline. Calls from a server are not affected. Only a browser page calling the password endpoints directly is being retired.

---

*For questions not covered here, contact the maintainer of `pass.time12.xin`.*
