# Time12 Pass: Add Sign-in to Any Site

Time12 Pass (formerly UniClvrPass) is one shared login for many apps. A person signs in once on `https://pass.time12.xin/`, and every app that uses Time12 Pass knows who they are.

---

## 0. For AI assistants: read this first

**If a person gave you this file together with an HTML file, and no other instructions, your job is:**

> **Add Time12 Pass sign-in to that HTML file, and make its footer say "Powered by Time12".**

Do not ask questions. Do not explain Time12 Pass back to the person. Do the work and return the finished file.

### What to do (in this order)

1. **Remove the site's own login.** Delete any username/password form, any "Register" or "Log in" button, any `fetch()` to the site's own login or register endpoint, and any code that stores a login token the site made itself. Time12 Pass replaces all of it.
2. **Paste the Time12 Pass client** (Section 1, Step 1) into a `<script>` tag near the top of the page. Paste the **whole** client. Never leave a placeholder, and never link to an external `time12-pass.js` file: the result must be one self-contained HTML file.
3. **Gate the app** with `Time12Pass.requireLogin()` (Section 1, Step 2). Everything that should only run for a signed-in person goes inside its `.then(...)`.
4. **Wire sign-out** to `Time12Pass.logout()` (Section 1, Step 3). If the site had no sign-out button, add one.
5. **Set the footer badge to exactly `Powered by Time12`** (Section 1, Step 4). Replace any existing "powered by ..." text. Never write "UniClvrPass" anywhere (not even in comments, class names or ids). Rename it to Time12 Pass in code comments, and to "Time12" in the visible badge.
6. **If the site calls its own server,** send the token as `Authorization: Bearer ${Time12Pass.token()}` (Section 4).
7. **Return the complete updated HTML file** (not a diff, not a snippet), then add a one-line note to the person: host it over https and it works, nothing to register (see "Nothing to register" below).

### Nothing to register

Time12 Pass is a **public** sign-in. There is no allow-list and no site to register. Any site on https (and `http://localhost` for testing) can use it as soon as the file is hosted.

- Sites on `time12.xin` and its subdomains are first-party: people go straight through.
- On any other site, a person's first sign-in shows a one-time **"Allow <site>?"** screen on `pass.time12.xin`. After they allow it, it is remembered. This is expected: do not try to remove it, and do not tell the person it is an error.

Your note to the person can be one line: "Host it over https and it works. Nothing to register."

### Rules that are easy to get wrong

| Do | Don't |
| --- | --- |
| Use the **redirect** flow (`requireLogin()`). The person types their password only on `pass.time12.xin`. | Don't build a new login form, and never send passwords through the site's own backend. |
| Keep the result as **one HTML file**. | Don't add a build step, an npm package or a separate `.js` file. |
| Keep the site's existing look, layout and features. | Don't redesign the page or remove features. |
| Write the badge as `Powered by <strong>Time12</strong>`. | Don't write "Time12 Pass" or "UniClvrPass" in the badge. |
| Treat the username (and anything typed by a person) as untrusted text. Use `textContent`, not `innerHTML`. | Don't put usernames into HTML strings. |
| If the page has a Content-Security-Policy, add `connect-src https://lbujqhnadkwqgojbhalw.supabase.co` to it. | Don't leave a CSP that blocks the sign-in check. |
| Keep the client's `aud` check (the token must be made for this site). On any server you write, do the same (Section 4). | Don't accept a token whose `aud` is another site, and don't remove the check to make an error go away. |

### If the HTML you were given is the Time12 Pass login page itself

If the page's title is "Sign in – Time12 Pass", it **is** the login page. Do not add sign-in to it and do not change it. Tell the person it is the Time12 Pass login page and needs no changes.

---

## 1. The copy-paste recipe

### Step 1: Paste the client

Put this in a `<script>` tag in the page's `<head>` (or at the top of `<body>`), **before** any script that uses `Time12Pass`. It is a complete, working client. Paste it unchanged.

```html
<script>
(() => {
  "use strict";

  const AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth";
  const LOGIN_URL = "https://pass.time12.xin/";

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

  // ---- Coming back from the login page: the token arrives in the URL fragment ----
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

  // A token is only good here if Time12 Pass made it for THIS site: this site's own origin, or "time12.xin" on Time12's own domain.
  const audOk = (aud) => aud === location.origin || (aud === COOKIE_DOMAIN && onSharedDomain && location.protocol === "https:");

  // ---- Ask Time12 Pass whether a token is still good ----
  async function verify(token) {
    const res = await fetch(AUTH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ action: "verify" }),
    });
    if (res.status === 401) return null; // bad, expired or logged-out token
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) throw new Error("Time12 Pass: verify failed (" + res.status + ")");
    if (!audOk(data.aud)) return null; // made for another site (or an old token with no site): treat as signed out
    return { userId: data.userId, username: data.username, aud: data.aud, expiresAt: data.expiresAt };
  }

  function goToLogin(extra) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const state = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    sessionStorage.setItem(STATE_KEY, state);
    sessionStorage.setItem(BOUNCE_KEY, String(Date.now()));
    const back = location.origin + location.pathname + location.search;
    location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(back)}&state=${state}${extra}`;
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
    // Also end the shared session on the login page, then come back.
    location.href = `${LOGIN_URL}?logout=1&redirect=${encodeURIComponent(returnTo)}`;
  }

  window.Time12Pass = { requireLogin, getUser, logout, token: readCookie };
})();
</script>
```

### Step 2: Gate the app

Hide the app until the person is signed in, then show it inside `.then(...)`. Move the site's existing startup code in here.

```html
<div id="app" hidden>
  <!-- the site's existing content -->
  <span id="who"></span>
  <button id="signOut" type="button">Sign out</button>
</div>

<script>
  Time12Pass.requireLogin()
    .then((user) => {
      // user = { userId, username, aud, expiresAt }
      document.getElementById("app").hidden = false;
      document.getElementById("who").textContent = user.username;   // textContent, never innerHTML
      startApp(user);                                               // the site's existing startup code
    })
    .catch((err) => {
      document.body.textContent = err.message;   // Time12 Pass can't be reached, or a set-up problem
    });
</script>
```

`requireLogin()` does one of three things:

| Situation | What happens |
| --- | --- |
| Already signed in | Resolves right away with `user`. No redirect, no flash. |
| Not signed in | Sends the person to `pass.time12.xin`, they sign in (or register), and they land back on the same page, then it resolves with `user`. |
| Time12 Pass can't be reached | Rejects with an error, and the person is **not** signed out. Show a message. |

Use `Time12Pass.getUser()` instead if a page should work for signed-out people too (it returns the user or `null` and never redirects). Then show a "Sign in" button that calls `Time12Pass.requireLogin()`.

### Step 3: Sign out

```html
<button id="signOut" type="button">Sign out</button>
<script>
  document.getElementById("signOut").addEventListener("click", () => Time12Pass.logout());
</script>
```

`logout()` revokes the token, clears the cookie, ends the shared Time12 Pass session, and returns to the site's home. To return somewhere else: `Time12Pass.logout("https://your-site.example.com/goodbye")` (a site the person has not allowed yet gets a "Back to ..." button instead of an automatic redirect).

For a "switch account" button: `Time12Pass.requireLogin({ switchAccount: true })` shows the form even if the person is already signed in.

### Step 4: The footer badge

Replace any existing "powered by ..." line with this. If the site has none, add it at the bottom of the page (or on the sign-in/landing screen).

```html
<footer class="t12-powered">Powered by <strong>Time12</strong></footer>
<style>
  .t12-powered { text-align: center; font-size: 11px; letter-spacing: 0.04em; opacity: 0.65; padding: 16px 0; }
  .t12-powered strong { font-weight: 700; letter-spacing: 0.06em; }
</style>
```

If the site already has a badge element with its own styling, keep that element and its CSS, and only change the text so it reads exactly: **Powered by Time12** (with "Time12" bold).

| Find this | Change it to |
| --- | --- |
| `powered by UniClvrPass` (any capitalisation) | `Powered by <strong>Time12</strong>` |
| `Powered by Time12 Pass` | `Powered by <strong>Time12</strong>` |
| `UniClvrPass` in comments, ids, class names | `Time12 Pass` (rename class names too, for example `.uniclvrpass` becomes `.powered-by strong`) |

### Step 5: Host it

Host the file over https (Netlify, GitHub Pages, Cloudflare Pages, any static host). For local testing, `http://localhost:PORT` and `http://127.0.0.1:PORT` also work. Opening the file straight from disk (`file://`) does not work. Nothing needs to be registered.

---

## 2. Worked example (before and after)

### Before: a typical site with its own login

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

### After: the same site on Time12 Pass

The login form, the `/api/login` call, the token in `localStorage` and the manual sign-out code are gone. The client (Step 1) is pasted in, shown here as one marker so the example stays short. **In your real output the whole client must be there.**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My Notes</title>
  <script>
    /* ===== PASTE THE FULL TIME12 PASS CLIENT FROM STEP 1 HERE, UNCHANGED ===== */
  </script>
</head>
<body>
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
    Time12Pass.requireLogin()
      .then((user) => {
        document.getElementById("app").hidden = false;
        document.getElementById("who").textContent = user.username;
        // Same data call as before, now with the Time12 Pass token:
        loadNotes(Time12Pass.token());
      })
      .catch((err) => { document.body.textContent = err.message; });

    document.getElementById("logout").addEventListener("click", () => Time12Pass.logout());
  </script>
</body>
</html>
```

---

## 3. What to look for in the HTML you were given

| If the site has... | Do this |
| --- | --- |
| A form with a password field, "Log in", "Register", "Sign up" | Delete it. `requireLogin()` replaces it (the Time12 Pass page has its own Login and Register). |
| `fetch(".../login")`, `fetch(".../register")`, or a call to the Time12 Pass API with `action: "login"` or `"register"` | Delete it. Use the redirect flow instead. |
| `localStorage.setItem("token", ...)` or a cookie the site made itself | Remove it. The token now comes from `Time12Pass.token()`. (If many parts of the code read a stored token, use Section 5.) |
| `if (!token) showLoginScreen()` | Replace with `Time12Pass.requireLogin().then(...)`. |
| A sign-out button | Make it call `Time12Pass.logout()`. |
| A name or avatar of the signed-in person | Fill it from `user.username` using `textContent`. |
| Requests to the site's own server | Add the header `Authorization: Bearer ${Time12Pass.token()}` (Section 4). |
| "powered by UniClvrPass" or any old branding | Change to `Powered by <strong>Time12</strong>` (Step 4). |
| A Content-Security-Policy `<meta>` | Add `connect-src https://lbujqhnadkwqgojbhalw.supabase.co` (and keep `script-src 'unsafe-inline'` if the page uses inline scripts). |

---

## 4. Calling your own server

Send the token with every request:

```js
const res = await fetch("/api/notes", {
  headers: { Authorization: `Bearer ${Time12Pass.token()}` },
});
if (res.status === 401) Time12Pass.requireLogin();   // token expired or logged out: sign in again
```

### Checking the token on your server

Your server calls `verify` and trusts **only** the `userId`, `username` and `aud` that come back. Never trust a username or id sent by the browser. Use `userId` as the key for the person's data. You can cache a good result for about a minute, no longer, so logouts take effect quickly.

**Always check `aud`.** It is the site the token was made for. A token whose `aud` is not your own site is rejected, even though it is otherwise valid: this is what stops a site the person allowed from using its token against your server. `aud` is your site's exact origin (scheme, host and port, no path), such as `https://your-site.example.com`. For an app that runs on `time12.xin` or one of its subdomains it is `time12.xin`. If your pages run on more than one origin, accept each of them.

**Node (Express):**

```js
const AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth";
const SITE_AUDS = new Set(["https://your-site.example.com"]); // every origin your pages run on ("time12.xin" for apps on time12.xin)
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
  if (!r.ok || !data.success) return res.status(401).json({ error: "Sign in required" });
  if (!SITE_AUDS.has(data.aud)) return res.status(401).json({ error: "Sign in required" }); // made for another site

  req.user = { userId: data.userId, username: data.username };
  cache.set(token, { user: req.user, until: Date.now() + 60_000 });
  next();
}

app.get("/api/notes", requireUser, (req, res) => {
  // use req.user.userId as the key for this person's data
});
```

**Python:**

```python
import requests

AUTH_URL = "https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth"
SITE_AUDS = {"https://your-site.example.com"}  # every origin your pages run on ("time12.xin" for apps on time12.xin)

def verify(token):
    """Returns {"userId", "username"} or None if the token is bad, expired, logged out, or made for another site."""
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

## 5. Apps that already read a token from their own storage

Some apps read the token from `localStorage` in dozens of places (for example `localStorage.getItem("authToken")`). Don't rewrite every call. Instead, sign in with Time12 Pass at startup and **copy the result into the keys the app already uses**:

```js
Time12Pass.requireLogin().then((user) => {
  localStorage.setItem("authToken", Time12Pass.token());   // use the key names the app already reads
  localStorage.setItem("userId", user.userId);
  localStorage.setItem("username", user.username);
  startApp();                                              // the app's existing startup, unchanged
});
```

And on sign-out, clear those keys, then call `Time12Pass.logout()`:

```js
function signOut() {
  localStorage.removeItem("authToken");
  localStorage.removeItem("userId");
  localStorage.removeItem("username");
  Time12Pass.logout();
}
```

(The Time12 dashboard itself uses a version of this pattern: it keeps its existing `authToken` / `userId` / `username` keys, but they are now filled only after returning from `pass.time12.xin`.)

---

## 6. How it works

### The redirect flow

1. The app has no valid token, so it sends the person to the login page:

   ```
   https://pass.time12.xin/?redirect=<your page, URL-encoded>&state=<random value>
   ```

2. If they are already signed in on this browser, the login page sends them straight back. If not, they sign in (or create an account) first.
3. They land back on your page with the token in the part of the address after the `#`:

   ```
   https://your-app.example.com/page#token=...&expiresAt=...&state=...
   ```

   The `#` part is never sent to servers, so the token stays out of logs. The token is made only for the site that asked (its `aud` is that site's origin), so it is no use anywhere else.
4. The app checks that `state` matches what it sent, stores the token (a cookie works well), removes the `#...` part from the address bar, and calls `verify`, which also says who the token was made for (`aud`). The app accepts it only if that is its own site.
5. On later visits the app only calls `verify`. A 401 means send the person to the login page again.

`requireLogin()` does steps 1 to 5 for you.

### Login page parameters

`https://pass.time12.xin/` (the `index.html` hosted at pass.time12.xin)

| Parameter | Meaning |
| --- | --- |
| `redirect` | Where to send the person after sign-in. Must be an https address (or `http://localhost` / `http://127.0.0.1` for testing). Any site is accepted; sites outside `time12.xin` show the one-time "Allow?" screen first. |
| `state` | A random value your app makes up. It is handed back unchanged so your app can check the sign-in is one it started. |
| `prompt=login` | Show the form even if the person is already signed in (use it for "switch account"). |
| `logout=1` | Sign the person out of the shared session, then send them to `redirect`. |

### Apps on time12.xin

When someone signs in (or is already signed in), the login page also sets a `time12pass_token` cookie for `.time12.xin`. It holds a token made for `time12.xin` (its `aud` is `time12.xin`), not the person's Pass session, and no other site ever receives it. Any app on `time12.xin` or one of its subdomains can read it, so those apps are signed in with no redirect at all. The client in Step 1 already does this: just use it as shown. Any page on a `time12.xin` subdomain can read this cookie, so only host trusted apps there.

### Set-up of the login page (once)

1. Host `index.html` at `https://pass.time12.xin/` (any https static host works: Netlify, GitHub Pages, Cloudflare Pages).
2. That's all. There is no list to maintain. Sites on `COOKIE_DOMAIN` (`time12.xin` and its subdomains) skip the "Allow?" screen; every other site shows it once per person.

### Signing out

Send the person to `https://pass.time12.xin/?logout=1&redirect=<where to land>` (or call `Time12Pass.logout()`). Also call the `logout` action with your saved token so it is revoked even if the login page's browser storage is empty. `Time12Pass.logout()` does both. Signing out on the login page ends the person's Pass session, and that also ends every site token made from it, so all apps sign out together.

---

## 7. API reference

**API endpoint** (one URL, every call is a `POST` with a JSON body):

```
https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth
```

| Action | Send | Success reply | Fails with |
| --- | --- | --- | --- |
| `register` | `{ action, username, password }` | 201 `{ success, userId, username, token, expiresAt }` | 400, 409, 429 |
| `login` | `{ action, username, password }` | 200 `{ success, userId, username, token, expiresAt }` | 400, 401, 429 |
| `issue` | `{ action, audience }` + `Authorization: Bearer <session token>` | 200 `{ success, userId, username, aud, token, expiresAt }` | 400, 401, 429 |
| `verify` | `{ action }` + `Authorization: Bearer <token>` | 200 `{ success, userId, username, aud, expiresAt }` | 401 |
| `whoami` | same as `verify` (older name) | same as `verify` | 401 |
| `logout` | `{ action }` + `Authorization: Bearer <token>` | 200 `{ success }` | 401 |

No API key is needed, and CORS is open.

`register` and `login` return a **session token** (`aud` is `pass`). Only the login page uses it: it swaps it for a token made for one site with `issue`, where `audience` is that site's origin (for example `https://notes.example.com`, https only, or `http://localhost:PORT` for testing) or `time12.xin` for the shared first-party token. Apps never see the session token.

### Direct API sign-in (only if a site truly needs its own form or runs on a server)

Prefer the redirect flow above. Use this only if the app has its own login form that cannot be replaced, or it runs on a server. **Passwords should only ever go from your login form to Time12 Pass over https, never through your own backend.**

**Log in:**

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"action":"login","username":"sam","password":"secret"}'
```

Reply: `{ "success": true, "userId": 12, "username": "sam", "token": "...", "expiresAt": "2026-11-22T10:00:00.000Z" }`

**Check a token:**

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"action":"verify"}'
```

Reply: `{ "success": true, "userId": 12, "username": "sam", "aud": "https://your-site.example.com", "expiresAt": "..." }`

**Log out:**

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"action":"logout"}'
```

**Create an account:** same as login but with `"action":"register"`.

**Get a token for your site** (login returns a session token, so swap it for one made for your site and keep only that one):

```bash
curl -X POST https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <session token from login>" \
  -d '{"action":"issue","audience":"https://your-site.example.com"}'
```

Reply: `{ "success": true, "userId": 12, "username": "sam", "aud": "https://your-site.example.com", "token": "...", "expiresAt": "..." }`

In JavaScript, `verify` looks like this:

```js
async function checkToken(token) {
  const res = await fetch("https://lbujqhnadkwqgojbhalw.supabase.co/functions/v1/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ action: "verify" }),
  });
  const data = await res.json();
  // aud must be your own site: location.origin (or "time12.xin" for apps on time12.xin)
  return res.ok && data.success && data.aud === location.origin ? { userId: data.userId, username: data.username } : null;
}
```

### The token

- A signed string (`payload.signature`), **not a JWT**. Treat it as opaque and always ask `verify`.
- Every token is made for one audience, `aud`: a **session** token (`aud` is `pass`, kept by the login page), a **site** token (`aud` is that site's origin, like `https://notes.example.com`), or the shared **first-party** token (`aud` is `time12.xin`, for apps on `time12.xin` and its subdomains). `verify` returns `aud`. **Reject any token whose `aud` is not your own site.**
- A site token is made from a session with `issue`. Only a session token can call `issue`, so a site that was handed a token cannot make tokens for other sites.
- Lasts 7 days from login. A site token ends when its session ends. There is no refresh; after that the person signs in again.
- A new login does **not** cancel older sessions. Each login makes its own session and all stay valid until they expire or are logged out.
- `logout` revokes the token you send. Logging out a session also ends every site token made from it, so signing out on the login page signs the person out of every app.
- `verify` also fails if the account has been deleted.
- Tokens made before per-site tokens existed have no `aud`. `verify` returns `aud: null` for them and apps reject them, so the person signs in once more. They run out by themselves within 7 days.

### Errors

Every failure is `{ "success": false, "error": "message" }`. Check the HTTP status, not the wording.

| Status | Meaning |
| --- | --- |
| 400 | Bad input: missing field, invalid username or password, invalid JSON, unknown action |
| 401 | Wrong username or password, or an invalid, expired or logged-out token (for `issue`, also a token that is not a session token) |
| 409 | Username already taken, or the organization name already exists |
| 429 | Too many attempts. The reply includes `retryAfter` (seconds) |
| 500 | Server problem. Try again later |

Username errors can include `details` (the offending characters). Treat it, and anything a user typed, as untrusted text and never put it into page HTML directly.

### Usernames and sub-accounts

- Letters, digits and `#` only, up to 20 characters. Stored in lowercase; login is not case sensitive.
- `org@` is an organization account. `name@org` is a sub-account that belongs to that organization. Each side of the `@` can be up to 20 characters.
- `register` rejects `@`. The organization's manager creates sub-accounts.
- Sub-accounts sign in with the full `name@org`, and `verify` returns that full string as `username`, plus the sub-account's own `userId`.

### Passwords

- Used exactly as typed. Nothing trims them; if your form trims, do it identically on register and login.
- `register` rejects passwords that start or end with a space, and passwords over 128 characters.

### Rate limits

- Login: 10 attempts per username per 15 minutes (a successful login resets it), and 100 per IP per 10 minutes.
- Register: 20 per IP per hour.
- Issue: 120 per person per 10 minutes.
- Past a limit you get 429 with `retryAfter`.

---

## 8. Security model of a public sign-in

Because any site can ask for a sign-in, the "Allow?" screen is what stops a crafted link (`pass.time12.xin/?redirect=https://stranger.example`) from quietly sending a token to a stranger. It shows the full address of the site, as plain text, and sends nothing until the person clicks Allow. Other protections: `state` must match, the token travels in the `#` fragment (never to servers), and only https (or localhost) addresses are accepted.

A site the person allows gets a token made **only for that site**: its `aud` is the site's origin. `verify` returns `aud`, and the client in Step 1 (and any server written as in Section 4) rejects a token whose `aud` is not its own site. So a site the person allowed cannot use its token to sign in to another app or to call another app's server. Only a session token can make site tokens, and sessions never leave the login page. Signing out on the login page ends every site token made from it.

What this does **not** change:

- A site the person allows can still act as that person on that site for up to 7 days, so only allow sites you trust.
- A server that does not check `aud` (for example an older one that only calls `verify` and reads `username`) still accepts a token made for any site, until you add the check from Section 4. Apps and servers written before this change keep working, because they always ask `verify`.
- The shared `time12.xin` token is accepted by every app on `time12.xin` and its subdomains, so only host trusted apps there.

---

## 9. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| "The redirect address must use https" | The page is on `http://` or `file://`. Host it over https. For local testing use `http://localhost:PORT`. |
| "Sign-in keeps sending you back" | The browser is dropping the `#token=...` part or blocking storage (private mode, strict settings). Allow cookies and storage for the site, then reload. |
| The person sees "Allow <site>?" | Expected for sites outside `time12.xin`. They click Allow once and it is remembered. |
| "This browser is blocking cookies for this site" | The browser blocks cookies (private mode, strict settings). Ask the person to allow cookies for the site. |
| Signed in on the login page, but the app sends the person to sign in again | `verify` works, but its `aud` is not this site's origin. A different `www`, port or `http`/`https` counts as a different site, so always open the page on the same origin it signs in from. People with a token from before per-site tokens also sign in once more. |
| `verify` returns 401 right after sign-in | The token was cut or changed. Make sure the `state` check and `#` handling were not edited, and paste the client again unchanged. |
| Sign-in works, but the app's own server says 401 | The server isn't sending `Authorization: Bearer <token>` to `verify`, or the cached result is older than a minute. |
| Nothing is blocked, yet `Time12Pass` is undefined | The client `<script>` comes **after** the code that uses it. Move it earlier. |
| CSP error in the console mentioning `supabase.co` | Add `connect-src https://lbujqhnadkwqgojbhalw.supabase.co` to the page's Content-Security-Policy. |