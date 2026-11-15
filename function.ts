import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/*
 * UniClvrPass auth function. Every call is POST with a JSON body { action, ... }.
 *   register  { username, password }           -> 201 { success, userId, username, token, expiresAt }
 *   login     { username, password }           -> 200 { success, userId, username, token, expiresAt }
 *             The token from register/login is a SESSION token (aud "pass"). Only the login page holds it.
 *   issue     { audience } + Bearer <session token>
 *                                              -> 200 { success, userId, username, aud, token, expiresAt }
 *             Makes a token for ONE site. audience = that site's origin ("https://notes.example.com"),
 *             or "time12.xin" for the shared first-party token (time12.xin and its subdomains).
 *   verify    (Authorization: Bearer <token>)  -> 200 { success, userId, username, aud, expiresAt } | 401
 *             aud is the site the token was made for ("pass" for a session token, null for a token made
 *             before per-site tokens existed). Apps and servers must reject a token whose aud is not their own.
 *   whoami    alias of verify (kept for older apps)
 *   logout    (Authorization: Bearer <token>)  -> 200 { success } | 401   (revokes that one token)
 * Every failure is { success: false, error } with 400 / 401 / 409 / 429 / 500.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// --- Settings ---
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7; // sessions last 7 days; site tokens never outlive their session
const MAX_PASSWORD_LENGTH = 128;

// Passwords are stored as "pbkdf2-sha256$<iterations>$<salt>$<hash>": a random salt per account, and slow on purpose.
// Accounts made before this still hold a plain SHA-256 hex hash. They keep working and are upgraded on their next login.
const PBKDF2_PREFIX = "pbkdf2-sha256";
const PBKDF2_ITERATIONS = 600_000; // stored with each hash, so it can be raised later; older hashes upgrade on login

// Token audiences (the `aud` claim). Any other value is a site origin such as "https://notes.example.com".
const SESSION_AUD = "pass"; // register/login tokens. The login page swaps one for site tokens with `issue`.
const FIRST_PARTY_AUD = "time12.xin"; // one shared token for time12.xin and its subdomains (they share a cookie)

// IP limits are generous on purpose: a whole classroom can share one IP.
const LIMITS = {
  registerIp: { limit: 20, windowSec: 60 * 60 },
  loginIp: { limit: 100, windowSec: 10 * 60 },
  loginUser: { limit: 10, windowSec: 15 * 60 },
  issueUser: { limit: 120, windowSec: 10 * 60 },
};

// --- Response helpers (every failure has the same shape) ---
function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", ...extraHeaders },
  });
}

function fail(status: number, error: string, extra: Record<string, unknown> = {}, extraHeaders: Record<string, string> = {}) {
  return json({ success: false, error, ...extra }, status, extraHeaders);
}

// --- Base64 helpers (Unicode safe) ---
function b64encode(str: string): string {
  return btoa(unescape(encodeURIComponent(str)));
}
function b64decode(str: string): string {
  return decodeURIComponent(escape(atob(str)));
}

// --- Crypto helpers ---
async function sha256Hex(text: string): Promise<string> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacKey(): Promise<CryptoKey | null> {
  const secret = Deno.env.get("SECRET_AUTH_KEY");
  if (!secret) return null;
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function sign(payload: string, key: CryptoKey): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  return btoa(String.fromCharCode(...sig)).replace(/=/g, "");
}

// --- Passwords: PBKDF2-SHA-256 with a random salt per account ---
const LEGACY_HASH_RE = /^[0-9a-f]{64}$/i; // plain SHA-256 hex: how every account was stored before

function toB64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function fromB64Url(str: string): Uint8Array {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations }, material, 256);
  return new Uint8Array(bits);
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_PREFIX}$${PBKDF2_ITERATIONS}$${toB64Url(salt)}$${toB64Url(hash)}`;
}

// ok: the password matches. needsUpgrade: it matches, but is stored the old way (or with fewer iterations than now).
async function verifyPassword(password: string, stored: unknown): Promise<{ ok: boolean; needsUpgrade: boolean }> {
  const no = { ok: false, needsUpgrade: false };
  if (typeof stored !== "string") return no;
  if (LEGACY_HASH_RE.test(stored)) {
    const ok = safeEqual(await sha256Hex(password), stored);
    return { ok, needsUpgrade: ok };
  }
  const [prefix, iterStr, saltStr, hashStr] = stored.split("$");
  const iterations = Number(iterStr);
  if (prefix !== PBKDF2_PREFIX || !Number.isInteger(iterations) || iterations < 1 || !saltStr || !hashStr) return no;
  try {
    const ok = safeEqual(toB64Url(await pbkdf2(password, fromB64Url(saltStr), iterations)), hashStr);
    return { ok, needsUpgrade: ok && iterations < PBKDF2_ITERATIONS };
  } catch {
    return no; // a damaged stored hash means "wrong password", never a 500
  }
}

// Checked against when the username doesn't exist, so a wrong username takes as long as a wrong password.
let dummyHash: Promise<string> | null = null;
const getDummyHash = () => (dummyHash ??= hashPassword(crypto.randomUUID()));

// --- Tokens: "<base64 payload>.<HMAC signature>", payload = { username, exp, aud, sid? } ---
//   aud: who the token is for (SESSION_AUD, FIRST_PARTY_AUD, or one site's origin).
//   sid: on a site token, the hash of the session token it was issued from. Logging that session out kills it too.
// The format is unchanged apart from the two new fields, so anything that only reads { username, exp } still works.
type Claims = { username: string; exp: number; aud: string | null; sid: string | null };

async function createSignedToken(
  username: string,
  aud: string,
  opts: { exp?: number; sid?: string } = {}
): Promise<{ token: string; exp: number }> {
  const key = await hmacKey();
  if (!key) throw new Error("SECRET_AUTH_KEY is not set");
  const exp = opts.exp ?? Date.now() + TOKEN_TTL_MS;
  const claims: Record<string, unknown> = { username, exp, aud };
  if (opts.sid) claims.sid = opts.sid;
  const payload = b64encode(JSON.stringify(claims)).replace(/=/g, "");
  return { token: `${payload}.${await sign(payload, key)}`, exp };
}

async function verifyToken(token: string): Promise<Claims | null> {
  const key = await hmacKey();
  if (!key) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;

  if (!safeEqual(await sign(payload, key), sig)) return null;

  try {
    const data = JSON.parse(b64decode(payload + "=".repeat((4 - (payload.length % 4)) % 4)));
    if (typeof data.username !== "string" || typeof data.exp !== "number") return null;
    if (data.exp < Date.now()) return null;
    // Tokens made before per-site tokens existed have no aud. They still verify (aud: null) so nothing breaks
    // mid-week, but apps reject them and `issue` refuses them, so they only run out their 7 days.
    return {
      username: data.username,
      exp: data.exp,
      aud: typeof data.aud === "string" ? data.aud : null,
      sid: typeof data.sid === "string" ? data.sid : null,
    };
  } catch {
    return null;
  }
}

// Full check used by verify, issue and logout: signature + not expired + not logged out + account still exists.
async function authenticate(req: Request) {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  const claims = await verifyToken(token);
  if (!claims) return null;

  const tokenHash = await sha256Hex(token);
  // A site token is also dead once the session it came from (sid) has been logged out.
  const hashes = claims.sid ? [tokenHash, claims.sid] : [tokenHash];
  const { data: revoked, error: revokedError } = await supabase
    .from("revoked_tokens")
    .select("token_hash")
    .in("token_hash", hashes)
    .limit(1);
  if (revokedError) throw new Error("Revocation check failed: " + revokedError.message);
  if (revoked && revoked.length > 0) return null;

  const { data: user, error: userError } = await supabase
    .from("users")
    .select("id, username")
    .eq("username", claims.username)
    .maybeSingle();
  if (userError) throw new Error("User lookup failed: " + userError.message);
  if (!user) return null;

  return { userId: user.id, username: user.username, aud: claims.aud, exp: claims.exp, tokenHash };
}

// --- Audiences: what `issue` is allowed to make a token for ---
// "time12.xin" (first-party), or the origin of an https site (http only for localhost / 127.0.0.1 testing).
// Anything with a path, query or credentials is cut down to its origin, so one site always gets one audience.
function normalizeAudience(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const raw = input.trim();
  if (raw === FIRST_PARTY_AUD) return FIRST_PARTY_AUD;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  const isLocal = u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  if (u.protocol !== "https:" && !isLocal) return null;
  if (u.username || u.password) return null;
  return u.origin;
}

// --- Rate limiting ---
function clientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-real-ip") ||
    (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim()
  );
}

async function rateLimit(key: string, limit: number, windowSec: number) {
  const { data, error } = await supabase.rpc("rl_hit", { p_key: key, p_limit: limit, p_window_seconds: windowSec });
  if (error) throw new Error("Rate limiter failed: " + error.message);
  const row = Array.isArray(data) ? data[0] : data;
  return { allowed: !!row?.allowed, retryAfter: (row?.retry_after as number) ?? windowSec };
}

function tooMany(retryAfter: number) {
  const minutes = Math.max(1, Math.ceil(retryAfter / 60));
  return fail(
    429,
    `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
    { retryAfter },
    { "Retry-After": String(retryAfter) }
  );
}

async function limitByIp(req: Request, name: string, cfg: { limit: number; windowSec: number }): Promise<Response | null> {
  const ip = clientIp(req);
  if (!ip) return null; // can't identify the caller: don't punish everyone with one shared bucket
  const rl = await rateLimit(`${name}:ip:${ip}`, cfg.limit, cfg.windowSec);
  return rl.allowed ? null : tooMany(rl.retryAfter);
}

// --- Username rule (also enforced by a CHECK constraint on users.username) ---
// Letters, digits and #. Optional single @ for organisations ("org@") and sub-accounts ("name@org").
// Each side of the @ is at most 20 characters.
const USERNAME_RE = /^[a-z0-9#]{1,20}(@[a-z0-9#]{0,20})?$/i;

type UsernameCheck =
  | { valid: true }
  | { valid: false; error: string; details?: Array<{ char: string; reason: string }> };

function describeBadChar(char: string): string {
  if (char === " ") return "spaces not allowed";
  if (char === ".") return "dots not allowed";
  if (char === "-" || char === "_") return "hyphens and underscores not allowed";
  if (/[!$%^&*()+=\[\]{};':"\\|,<>/?`~]/.test(char)) return "special characters not allowed";
  if (/[^\x00-\x7F]/.test(char)) return "unicode/emoji not allowed";
  return "not alphanumeric";
}

function validateUsername(username: unknown): UsernameCheck {
  if (!username || typeof username !== "string") {
    return { valid: false, error: "Username is required" };
  }
  const trimmed = username.trim();
  if (trimmed.length === 0) return { valid: false, error: "Username cannot be empty" };
  if (USERNAME_RE.test(trimmed)) return { valid: true };

  // Explain why it failed. The raw input is never echoed inside `error`
  // (apps may show it as HTML); offending characters are only in `details`.
  const bad = new Map<string, string>();
  for (const ch of trimmed) {
    if (!/[a-zA-Z0-9#@]/.test(ch) && !bad.has(ch)) bad.set(ch, describeBadChar(ch));
  }
  if (bad.size > 0) {
    const reasons = [...new Set(bad.values())].join("; ");
    return {
      valid: false,
      error: `Username has invalid characters (${reasons}). Only use A-Z, 0-9, and #.`,
      details: [...bad].map(([char, reason]) => ({ char, reason })),
    };
  }
  const parts = trimmed.split("@");
  if (parts.length > 2) return { valid: false, error: "Username can contain only one @" };
  if (parts[0].length === 0) return { valid: false, error: "Username must have a name before the @" };
  return {
    valid: false,
    error: "Username too long. Max 20 characters" + (parts.length === 2 ? " on each side of the @." : "."),
  };
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return fail(400, "Invalid JSON body");
    }
    if (!body || typeof body !== "object") return fail(400, "Invalid JSON body");

    const { action, username, password } = body;

    // ---------- register ----------
    if (action === "register") {
      const limited = await limitByIp(req, "register", LIMITS.registerIp);
      if (limited) return limited;

      if (typeof username !== "string" || typeof password !== "string" || !username || !password) {
        return fail(400, "Missing username or password");
      }
      // Passwords are never trimmed anywhere. Leading/trailing spaces are refused up front
      // so a password can't register fine and then fail to log in.
      if (password.length > MAX_PASSWORD_LENGTH) {
        return fail(400, `Password too long (max ${MAX_PASSWORD_LENGTH} characters)`);
      }
      if (password !== password.trim()) {
        return fail(400, "Password cannot start or end with spaces");
      }

      // "@" is reserved for organisations; sub-accounts are not created through register.
      if (username.includes("@")) {
        const baseUsername = username.split("@")[0].trim().toLowerCase();
        const { data: existingOrg, error: orgError } = await supabase
          .from("users")
          .select("id")
          .eq("username", baseUsername + "@")
          .maybeSingle();
        if (orgError) throw new Error("Database error: " + orgError.message);

        if (existingOrg) {
          const safeName = /^[a-z0-9#]{1,20}$/.test(baseUsername) ? ` "${baseUsername}"` : "";
          return fail(409, `Organization${safeName} already exists`);
        }
        return fail(400, "Username cannot contain @ symbol (reserved for organizations)", {
          details: [{ char: "@", reason: "reserved for organization namespaces" }],
        });
      }

      const check = validateUsername(username);
      if (!check.valid) return fail(400, check.error, { details: check.details });

      const normalizedUsername = username.trim().toLowerCase();

      const { data: existing, error: existingError } = await supabase
        .from("users")
        .select("id")
        .eq("username", normalizedUsername)
        .maybeSingle();
      if (existingError) throw new Error("Database error: " + existingError.message);
      if (existing) return fail(409, "Username already taken");

      const passwordHash = await hashPassword(password);
      const { data, error } = await supabase
        .from("users")
        .insert([{ username: normalizedUsername, password_hash: passwordHash }])
        .select();

      if (error) {
        if (error.code === "23505") return fail(409, "Username already taken"); // lost a race
        if (error.code === "23514") return fail(400, "Username is not allowed");
        throw new Error("Registration failed: " + error.message);
      }

      const { token, exp } = await createSignedToken(data[0].username, SESSION_AUD);
      return json(
        {
          success: true,
          userId: data[0].id,
          username: data[0].username,
          token,
          expiresAt: new Date(exp).toISOString(),
        },
        201
      );
    }

    // ---------- login ----------
    if (action === "login") {
      const limited = await limitByIp(req, "login", LIMITS.loginIp);
      if (limited) return limited;

      if (typeof username !== "string" || typeof password !== "string" || !username || !password) {
        return fail(400, "Missing username or password");
      }

      const check = validateUsername(username);
      if (!check.valid) return fail(400, check.error, { details: check.details });

      const normalizedUsername = username.trim().toLowerCase();

      // Per-account lockout: counts every attempt, cleared by a successful login.
      const userKey = `login:user:${normalizedUsername}`;
      const userLimit = await rateLimit(userKey, LIMITS.loginUser.limit, LIMITS.loginUser.windowSec);
      if (!userLimit.allowed) return tooMany(userLimit.retryAfter);

      const { data: user, error } = await supabase
        .from("users")
        .select("id, username, password_hash")
        .eq("username", normalizedUsername)
        .maybeSingle();
      if (error) throw new Error("Login error: " + error.message);

      // Password is compared exactly as sent (no trimming), same as register. An unknown username still does a full
      // hash, so the response time doesn't reveal whether the account exists.
      const pw = await verifyPassword(password, user ? user.password_hash : await getDummyHash());
      if (!user || !pw.ok) {
        return fail(401, "Invalid username or password");
      }

      // Move the account from the old plain SHA-256 hash (or a lower iteration count) to the current one.
      // This never blocks a login: if it fails, the person is still signed in and it is retried next time.
      if (pw.needsUpgrade) {
        try {
          const upgraded = await hashPassword(password);
          const { error: upgradeError } = await supabase
            .from("users")
            .update({ password_hash: upgraded })
            .eq("id", user.id)
            .eq("password_hash", user.password_hash); // only if nobody changed it in the meantime
          if (upgradeError) console.error("password upgrade failed:", upgradeError.message);
        } catch (e) {
          console.error("password upgrade failed:", (e as Error).message);
        }
      }

      await supabase.from("rate_limits").delete().eq("key", userKey);

      const { token, exp } = await createSignedToken(user.username, SESSION_AUD);
      return json({
        success: true,
        userId: user.id,
        username: user.username,
        token,
        expiresAt: new Date(exp).toISOString(),
      });
    }

    // ---------- issue: swap a session token for a token made for one site ----------
    if (action === "issue") {
      const auth = await authenticate(req);
      // Only a real session token may issue. Site tokens and pre-aud tokens (aud null) cannot, so a site that
      // was handed a token can never mint tokens for other sites.
      if (!auth || auth.aud !== SESSION_AUD) return fail(401, "Invalid or expired token");

      const issueLimit = await rateLimit(`issue:user:${auth.username}`, LIMITS.issueUser.limit, LIMITS.issueUser.windowSec);
      if (!issueLimit.allowed) return tooMany(issueLimit.retryAfter);

      const aud = normalizeAudience(body.audience);
      if (!aud) {
        return fail(400, "Invalid audience. Use a site's origin, like https://example.com (https only, or http://localhost for testing)");
      }

      // The site token expires with its session and is tied to it (sid), so signing out of the session signs out every site.
      const { token, exp } = await createSignedToken(auth.username, aud, { exp: auth.exp, sid: auth.tokenHash });
      return json({
        success: true,
        userId: auth.userId,
        username: auth.username,
        aud,
        token,
        expiresAt: new Date(exp).toISOString(),
      });
    }

    // ---------- verify (public) / whoami (old name) ----------
    if (action === "verify" || action === "whoami") {
      const auth = await authenticate(req);
      if (!auth) return fail(401, "Invalid or expired token");
      return json({
        success: true,
        userId: auth.userId,
        username: auth.username,
        aud: auth.aud,
        expiresAt: new Date(auth.exp).toISOString(),
      });
    }

    // ---------- logout ----------
    if (action === "logout") {
      const auth = await authenticate(req);
      if (!auth) return fail(401, "Invalid or expired token");

      const { error } = await supabase
        .from("revoked_tokens")
        .upsert({ token_hash: auth.tokenHash, expires_at: new Date(auth.exp).toISOString() });
      if (error) throw new Error("Logout failed: " + error.message);

      // Housekeeping: forget revoked tokens that have expired anyway.
      await supabase.from("revoked_tokens").delete().lt("expires_at", new Date().toISOString());

      return json({ success: true });
    }

    return fail(400, "Invalid action");
  } catch (error) {
    console.error("auth error:", (error as Error).message);
    return fail(500, "Server error");
  }
});