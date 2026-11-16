import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { newChallenge, verifyRegistration, verifyAssertion, WebAuthnError } from './webauthn.js';
import { db } from './db.js';
import { jwks, signToken } from './tokens.js';

const PORT = Number(process.env.PORT || 4000);
// Passkeys are bound to this origin and RP ID. Set ORIGIN (e.g. https://id.6j0.org) in production.
// RP_ID defaults to the ORIGIN hostname. Keep it that way: an RP ID of the parent domain would let every app
// subdomain use these passkeys (and their PRF output) directly, which is what this service exists to prevent.
const originOf = (req) => process.env.ORIGIN || `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
const rpIdOf = (req) => process.env.RP_ID || new URL(originOf(req)).hostname;
const MAX_SEALED = 4 * 1024;

// The apps allowed to sign in here: APPS="bored=https://bored.6j0.org,chorechart=https://chorechart.6j0.org".
// The name is the token audience and goes into each app's key derivation, so never rename or reuse one.
// After sign-in the browser is sent to exactly this origin, never to a URL from the request.
const APPS = Object.fromEntries(String(process.env.APPS || '').split(',').map(s => s.trim()).filter(Boolean).map(entry => {
  const [name, origin] = entry.split('=');
  if (!/^[a-z0-9-]{1,32}$/.test(name || '')) throw new Error(`APPS: bad app name in "${entry}"`);
  const u = new URL(origin);
  if (u.origin !== origin || !['https:', 'http:'].includes(u.protocol)) throw new Error(`APPS: "${origin}" must be a bare origin like https://app.example`);
  return [name, origin];
}));
if (!Object.keys(APPS).length) console.warn('APPS is empty: no app can sign in. Example: APPS=bored=http://localhost:3000');

// ---------- helpers ----------

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const q = (sql) => db.prepare(sql);

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
}

async function readJson(req) {
  let size = 0; const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > 64 * 1024) throw new HttpError(413, 'Body too large');
    chunks.push(c);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new HttpError(400, 'Invalid JSON'); }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

const secureFlag = () => (String(process.env.ORIGIN || '').startsWith('https:') ? '; Secure' : '');

function newSession(userId) {
  const token = randomBytes(24).toString('hex');
  q('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, userId);
  return { 'Set-Cookie': `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}${secureFlag()}` };
}

// Encrypted values from the browser look like "iv.ciphertext" in base64url. The server never decrypts them.
function sealed(v, field) {
  if (typeof v !== 'string' || v.length > MAX_SEALED || !/^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/.test(v)) throw new HttpError(400, `Bad ${field}`);
  return v;
}

function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

// ---------- passwords ----------
// The browser never sends the password (see public/id.js): it sends authKey = HKDF(Argon2id(password, salt, kdf)),
// which we hash again with scrypt. The key that unwraps the root secret is a different HKDF output and stays in the
// browser. Anyone with the database can still guess passwords offline, which is why the page insists on strong ones.

const scryptAsync = promisify(scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1 };
// Argon2id cost for new passwords (RFC 9106's second recommended option, with one lane), and the floor we accept.
// Stored per password, so it can be raised later without breaking existing ones. Keep in sync with public/id.js.
const KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1 }; // m in KiB: 64 MiB
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;

function username(v) {
  const u = String(v ?? '').trim().toLowerCase();
  if (!USERNAME_RE.test(u)) throw new HttpError(400, 'Usernames are 3–32 letters, numbers, dots, dashes or underscores, starting with a letter or number.');
  return u;
}
function bytes64(v, field, length) {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]+$/.test(v) || Buffer.from(v, 'base64url').length !== length) throw new HttpError(400, `Bad ${field}`);
  return v;
}
function kdf(v) {
  const ok = v && v.alg === 'argon2id' && Object.keys(v).length === 4
    && Number.isInteger(v.m) && v.m >= KDF.m && v.m <= 1048576    // up to 1 GiB
    && Number.isInteger(v.t) && v.t >= KDF.t && v.t <= 20
    && Number.isInteger(v.p) && v.p >= 1 && v.p <= 4;
  if (!ok) throw new HttpError(400, 'Bad kdf');
  return JSON.stringify({ alg: v.alg, m: v.m, t: v.t, p: v.p });
}

async function hashAuthKey(authKey) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(Buffer.from(authKey, 'base64url'), salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}
async function checkAuthKey(authKey, stored) {
  const [, N, r, p, salt, hash] = stored.split('$');
  const got = await scryptAsync(Buffer.from(authKey, 'base64url'), Buffer.from(salt, 'base64url'), 32, { N: +N, r: +r, p: +p });
  return timingSafeEqual(got, Buffer.from(hash, 'base64url'));
}
// Checked against for unknown usernames, so they take as long as wrong passwords.
const DUMMY_HASH = await hashAuthKey(randomBytes(32).toString('base64url'));

// Unknown usernames get a stable fake salt, so /prelogin doesn't reveal which usernames exist.
const fakeSaltKey = q("SELECT value FROM meta WHERE key = 'fake_salt_key'").get()?.value || (() => {
  const v = randomBytes(32).toString('base64url');
  q("INSERT INTO meta (key, value) VALUES ('fake_salt_key', ?)").run(v);
  return v;
})();
const fakeSalt = (name) => createHmac('sha256', fakeSaltKey).update(name).digest().subarray(0, 16).toString('base64url');

// Fixed-window rate limits, in memory (one replica, like the passkey challenges).
const attempts = new Map(); // key -> { n, reset }
const LIMIT_WINDOW_MS = 15 * 60 * 1000;
function limit(key, max) {
  const now = Date.now();
  if (attempts.size > 10000) for (const [k, v] of attempts) if (v.reset < now) attempts.delete(k);
  let a = attempts.get(key);
  if (!a || a.reset < now) attempts.set(key, a = { n: 0, reset: now + LIMIT_WINDOW_MS });
  if (++a.n > max) throw new HttpError(429, 'Too many attempts. Wait 15 minutes and try again.');
}
// Behind a reverse proxy, set TRUST_PROXY=1 so limits apply per client rather than to the proxy.
const clientIp = (req) => (process.env.TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;

// The validated fields shared by register and set/change password.
const passwordFields = (body) => ({
  username: username(body.username),
  salt: bytes64(body.salt, 'salt', 16),
  kdf: kdf(body.kdf),
  authKey: bytes64(body.authKey, 'auth key', 32),
  wrappedRoot: sealed(body.wrappedRoot, 'wrapped root'),
});
const taken = (name, exceptUserId = 0) => Boolean(q('SELECT 1 FROM passwords WHERE username = ? AND user_id != ?').get(name, exceptUserId));
const signInMethods = (userId) => q('SELECT COUNT(*) n FROM passkeys WHERE user_id = ?').get(userId).n
  + q('SELECT COUNT(*) n FROM passwords WHERE user_id = ?').get(userId).n;

const publicUser = (u) => ({ guid: u.guid });
const userEntity = (guid) => ({ id: Buffer.from(guid).toString('base64url'), name: `6j0.org ${guid.slice(0, 8)}`, displayName: '6j0.org identity' });

// ---------- routes ----------

const routes = [];
// auth: true (must be signed in) | false (no user)
const route = (method, pattern, handler, { auth = true } = {}) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '(\\d+)'; }) + '$');
  routes.push({ method, re, keys, handler, auth });
};

const webauthnCtx = (req, kind) => ({ origin: originOf(req), rpId: rpIdOf(req), kind });

// Create an identity: the server picks the GUID; the browser creates a passkey with PRF, makes a random root secret,
// and sends it back only wrapped under that passkey's PRF-derived key.
route('POST', '/api/passkey/register/options', async ({ req, res }) => {
  const guid = randomUUID();
  send(res, 200, { challenge: newChallenge('register', { guid }), rp: { id: rpIdOf(req), name: '6j0.org' }, user: userEntity(guid) });
}, { auth: false });

route('POST', '/api/passkey/register/verify', async ({ req, body, res }) => {
  const reg = verifyRegistration(body, webauthnCtx(req, 'register'));
  const wrapped = sealed(body.wrappedRoot, 'wrapped root');
  const userId = tx(() => {
    const { lastInsertRowid } = q('INSERT INTO users (guid) VALUES (?)').run(reg.data.guid);
    q(`INSERT INTO passkeys (user_id, credential_id, public_key, alg, sign_count, wrapped_root, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`).run(lastInsertRowid, reg.credentialId, reg.publicKey, reg.alg, reg.signCount, wrapped);
    return lastInsertRowid;
  });
  send(res, 200, { user: publicUser(q('SELECT * FROM users WHERE id = ?').get(userId)) }, newSession(userId));
}, { auth: false });

route('POST', '/api/passkey/login/options', async ({ req, res }) => {
  send(res, 200, { challenge: newChallenge('login'), rpId: rpIdOf(req) });
}, { auth: false });

route('POST', '/api/passkey/login/verify', async ({ req, body, res }) => {
  const pk = q('SELECT * FROM passkeys WHERE credential_id = ?').get(String(body.credentialId || ''));
  if (!pk) throw new HttpError(401, "This passkey isn't registered with 6j0.org. Was the identity deleted?");
  const { signCount } = verifyAssertion(body, pk, webauthnCtx(req, 'login'));
  const user = q('SELECT * FROM users WHERE id = ?').get(pk.user_id);
  if (body.userHandle && Buffer.from(body.userHandle, 'base64url').toString() !== user.guid) throw new HttpError(401, 'Passkey user mismatch');
  q(`UPDATE passkeys SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?`).run(signCount, pk.id);
  send(res, 200, { user: publicUser(user), wrappedRoot: pk.wrapped_root }, newSession(user.id));
}, { auth: false });

// Add another passkey: the browser unlocks the root secret with an existing passkey, then wraps it for the new one.
route('POST', '/api/passkey/add/options', async ({ req, user, res }) => {
  const mine = q('SELECT credential_id, wrapped_root FROM passkeys WHERE user_id = ?').all(user.id);
  send(res, 200, {
    challenge: newChallenge('add', { userId: user.id }),
    rp: { id: rpIdOf(req), name: '6j0.org' },
    user: userEntity(user.guid),
    existing: mine.map(p => ({ credentialId: p.credential_id, wrappedRoot: p.wrapped_root })),
  });
});

route('POST', '/api/passkey/add/verify', async ({ req, user, body, res }) => {
  const reg = verifyRegistration(body, webauthnCtx(req, 'add'));
  if (reg.data.userId !== user.id) throw new HttpError(403, 'Passkey request was for a different identity');
  q(`INSERT INTO passkeys (user_id, credential_id, public_key, alg, sign_count, wrapped_root) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(user.id, reg.credentialId, reg.publicKey, reg.alg, reg.signCount, sealed(body.wrappedRoot, 'wrapped root'));
  send(res, 200, { ok: true });
});

// Create an identity with a username + password instead of a passkey.
route('POST', '/api/password/register', async ({ req, body, res }) => {
  limit(`register:${clientIp(req)}`, 20);
  const f = passwordFields(body);
  if (taken(f.username)) throw new HttpError(409, 'That username is taken. Try another one.');
  const authHash = await hashAuthKey(f.authKey);
  const userId = tx(() => {
    const { lastInsertRowid } = q('INSERT INTO users (guid) VALUES (?)').run(randomUUID());
    q(`INSERT INTO passwords (user_id, username, salt, kdf, auth_hash, wrapped_root, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`).run(lastInsertRowid, f.username, f.salt, f.kdf, authHash, f.wrappedRoot);
    return lastInsertRowid;
  });
  send(res, 200, { user: publicUser(q('SELECT * FROM users WHERE id = ?').get(userId)) }, newSession(userId));
}, { auth: false });

// Step 1 of password sign-in: the Argon2id salt and cost for a username (fake but stable ones if it doesn't exist).
route('POST', '/api/password/prelogin', async ({ req, body, res }) => {
  limit(`prelogin:${clientIp(req)}`, 200);
  const name = username(body.username);
  const pw = q('SELECT salt, kdf FROM passwords WHERE username = ?').get(name);
  send(res, 200, pw ? { salt: pw.salt, kdf: JSON.parse(pw.kdf) } : { salt: fakeSalt(name), kdf: KDF });
}, { auth: false });

// Step 2: check authKey. Unknown username and wrong password get the same answer.
route('POST', '/api/password/login', async ({ req, body, res }) => {
  const name = username(body.username);
  limit(`login-ip:${clientIp(req)}`, 50);
  limit(`login-user:${name}`, 10);
  const authKey = bytes64(body.authKey, 'auth key', 32);
  const pw = q('SELECT * FROM passwords WHERE username = ?').get(name);
  const ok = await checkAuthKey(authKey, pw?.auth_hash || DUMMY_HASH);
  if (!pw || !ok) throw new HttpError(401, 'Wrong username or password.');
  q(`UPDATE passwords SET last_used_at = datetime('now') WHERE id = ?`).run(pw.id);
  const user = q('SELECT * FROM users WHERE id = ?').get(pw.user_id);
  send(res, 200, { user: publicUser(user), wrappedRoot: pw.wrapped_root }, newSession(user.id));
}, { auth: false });

// My password, if any: what the page needs to unlock the root secret with it (and to show the username).
route('GET', '/api/password', async ({ user, res }) => {
  const pw = q('SELECT username, salt, kdf, wrapped_root, created_at, last_used_at FROM passwords WHERE user_id = ?').get(user.id);
  send(res, 200, { password: pw ? { username: pw.username, salt: pw.salt, kdf: JSON.parse(pw.kdf), wrappedRoot: pw.wrapped_root,
    created_at: pw.created_at, last_used_at: pw.last_used_at } : null });
});

// Set a password, or change it. Changing needs proof of the current one (currentAuthKey), so a stolen session
// can't lock the owner out of their password.
route('PUT', '/api/password', async ({ req, user, body, res }) => {
  const f = passwordFields(body);
  const current = q('SELECT * FROM passwords WHERE user_id = ?').get(user.id);
  if (current) {
    limit(`login-user:${current.username}`, 10);
    if (!await checkAuthKey(bytes64(body.currentAuthKey, 'current auth key', 32), current.auth_hash)) throw new HttpError(403, 'Your current password is wrong.');
  }
  if (taken(f.username, user.id)) throw new HttpError(409, 'That username is taken. Try another one.');
  const authHash = await hashAuthKey(f.authKey);
  q(`INSERT INTO passwords (user_id, username, salt, kdf, auth_hash, wrapped_root) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (user_id) DO UPDATE SET username = excluded.username, salt = excluded.salt, kdf = excluded.kdf,
       auth_hash = excluded.auth_hash, wrapped_root = excluded.wrapped_root, created_at = datetime('now')`)
    .run(user.id, f.username, f.salt, f.kdf, authHash, f.wrappedRoot);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/password', async ({ user, res }) => {
  if (!q('SELECT 1 FROM passkeys WHERE user_id = ?').get(user.id))
    throw new HttpError(409, "Your password is your only way to sign in. Add a passkey before removing it, or you'll lose your identity and every app's data.");
  q('DELETE FROM passwords WHERE user_id = ?').run(user.id);
  send(res, 200, { ok: true });
});

route('GET', '/api/passkeys', async ({ user, res }) => {
  send(res, 200, q('SELECT id, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY id').all(user.id));
});

route('DELETE', '/api/passkeys/:id', async ({ user, params, res }) => {
  if (signInMethods(user.id) <= 1) throw new HttpError(409, "That's your only way to sign in. Add another passkey or a password before removing it, or you'll lose your identity and every app's data.");
  const r = q('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(params.id, user.id);
  if (!r.changes) throw new HttpError(404, 'Passkey not found');
  send(res, 200, { ok: true });
});

route('POST', '/api/logout', async ({ req, res }) => {
  const { sid } = parseCookies(req.headers.cookie);
  if (sid) q('DELETE FROM sessions WHERE token = ?').run(sid);
  send(res, 200, { ok: true }, { 'Set-Cookie': `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag()}` });
}, { auth: false });

route('GET', '/api/me', async ({ user, res }) => send(res, 200, publicUser(user)));

// The apps that can sign in here (for the "continue to …" screen and the key handoff).
route('GET', '/api/apps', async ({ res }) => send(res, 200, APPS), { auth: false });

// Sign the browser in to an app. The browser derives that app's key itself and encrypts it to the app page's
// ephemeral public key; the server only issues the signed token and says where to send it.
route('POST', '/api/authorize', async ({ req, user, body, res }) => {
  const app = String(body.app || '');
  if (!Object.hasOwn(APPS, app)) throw new HttpError(400, `Unknown app "${app}"`);
  const nonce = String(body.nonce || '');
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new HttpError(400, 'Bad nonce');
  const token = signToken({ iss: originOf(req), sub: user.guid, aud: app, nonce });
  send(res, 200, { token, origin: APPS[app] });
});

route('GET', '/.well-known/jwks.json', async ({ res }) => {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(jwks));
}, { auth: false });

route('GET', '/healthz', async ({ res }) => send(res, 200, { ok: true }), { auth: false });

// ---------- server ----------

const STATIC = {
  '/': 'index.html', '/index.html': 'index.html', '/authorize': 'index.html', '/id.js': 'id.js', '/style.css': 'style.css',
};
// Vendored @noble/hashes (Argon2id for the password fallback). Pinned; see README "Vendored code".
const NOBLE = 'vendor/noble-hashes-2.4.0';
for (const f of ['argon2.js', 'blake2.js', '_blake.js', '_md.js', '_u64.js', 'utils.js']) STATIC[`/${NOBLE}/${f}`] = `${NOBLE}/${f}`;
const MIME = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8' };

// This page holds every identity's root secret while it's open: same-origin scripts only, no framing.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'GET' && STATIC[url.pathname]) {
      const file = STATIC[url.pathname];
      res.writeHead(200, {
        'Content-Type': MIME[file.split('.').pop()], 'Cache-Control': 'no-cache',
        'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
        'Cross-Origin-Opener-Policy': 'same-origin',
      });
      return res.end(await readFile(new URL('./public/' + file, import.meta.url)));
    }
    for (const r of routes) {
      const m = r.method === req.method && url.pathname.match(r.re);
      if (!m) continue;
      const params = Object.fromEntries(r.keys.map((k, i) => [k, Number(m[i + 1])]));
      let user = null;
      if (r.auth) {
        const { sid } = parseCookies(req.headers.cookie);
        user = (sid && q('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(sid)) || null;
        if (!user) throw new HttpError(401, 'Please sign in');
      }
      // Basic CSRF guard: state-changing requests must be same-origin JSON.
      if (req.method !== 'GET' && !String(req.headers['content-type'] || '').startsWith('application/json'))
        throw new HttpError(415, 'Expected application/json');
      const body = req.method === 'GET' ? {} : await readJson(req);
      return await r.handler({ req, res, user, params, body });
    }
    throw new HttpError(404, 'Not found');
  } catch (e) {
    if (e instanceof WebAuthnError) e = new HttpError(400, e.message);
    if (!(e instanceof HttpError)) console.error(e);
    send(res, e.status || 500, { error: e instanceof HttpError ? e.message : 'Something went wrong' });
  }
});

server.listen(PORT, () => console.log(`6j0.org identity → http://localhost:${PORT} (apps: ${Object.keys(APPS).join(', ') || 'none'})`));
