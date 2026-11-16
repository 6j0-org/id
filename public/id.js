// 6j0.org identity: one sign-in for every 6j0.org app, and a separate encryption key for each of them.
//
// Keys
// - Each passkey yields a secret via the WebAuthn PRF extension. HKDF turns it into a key-encryption key that wraps
//   the identity's random 256-bit *root secret*. The server stores one wrapped copy per passkey and never sees the
//   PRF output or the root secret.
// - Fallback for passkey managers without PRF: one username + password per identity. The page runs
//   Argon2id(password, random salt, m=64 MiB, t=3, p=1) and splits the result with HKDF into an *auth key*, which
//   it sends to sign in (the server stores only scrypt(auth key)), and a key-encryption key that wraps the root
//   secret like a passkey's does and never leaves the browser. The password itself is never sent. Anyone with the
//   database can still guess passwords offline, so new passwords must be long (or generated).
//   WebCrypto has no Argon2, so it comes from a pinned, vendored copy of @noble/hashes (public/vendor/): the only
//   third-party code this page loads. Its Argon2 isn't covered by noble's audit; it was checked against Node's
//   OpenSSL Argon2id before vendoring.

import { argon2idAsync } from './vendor/noble-hashes-2.4.0/argon2.js';
// - After sign-in the root secret is kept in IndexedDB as a non-extractable HKDF key, so later visits from apps sign
//   in without another passkey prompt. Signing out here deletes it.
// - App key = HKDF(root, salt "6j0-id", info "6j0/v1/app/<app>"), 32 bytes. Every app gets a different key, and no
//   app can compute another's: only this origin can use the passkey and the root secret.
//
// Sign-in handoff (/authorize?app=<name>&nonce=<random>&epk=<x>.<y>)
// 1. The app page makes an ephemeral ECDH P-256 key pair, remembers it with the nonce, and sends the public half here.
// 2. This page asks the server for a signed token (aud = app, nonce), derives the app key, and encrypts it to the app:
//    ECDH(our ephemeral private, app's public) → HKDF(salt = nonce, info "6j0/v1/handoff/<app>") → AES-256-GCM.
// 3. It redirects to the app's registered origin (from the server, never from the URL) with everything in the
//    fragment, which browsers don't send to servers: #id_token=…&epk=<x>.<y>&key=<iv.ciphertext>&state=<nonce>
// The app's server verifies the token against /.well-known/jwks.json; only the app's page can decrypt the key.

const subtle = crypto.subtle;
const te = new TextEncoder();

class PrfUnsupportedError extends Error {
  constructor() { super("This browser or passkey manager can't create the encryption key 6j0.org needs."); }
}

// ---------- encoding / AES-GCM ----------
const b64u = {
  enc: (buf) => {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let s = ''; for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec: (str) => {
    const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  },
};

async function seal(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return `${b64u.enc(iv)}.${b64u.enc(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes))}`;
}
async function openBytes(key, sealedStr) {
  const [iv, ct] = String(sealedStr).split('.');
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: b64u.dec(iv) }, key, b64u.dec(ct)));
}
async function hkdfAes(secret, salt, info) {
  const base = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(salt), info: te.encode(info) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ---------- PRF ----------
let prfSaltCache;
const prfSalt = async () => (prfSaltCache ||= new Uint8Array(await subtle.digest('SHA-256', te.encode('6j0-id-root-v1'))));
const kekFromPrf = (prf) => hkdfAes(new Uint8Array(prf), '6j0-id', 'root-kek-v1');

async function prfSupport() {
  if (!window.isSecureContext || !window.PublicKeyCredential) return false;
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps && 'extension:prf' in caps) return Boolean(caps['extension:prf']);
  } catch {}
  return null;
}

async function prfFromGet(allow) {
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), // not sent to the server; this is only to read PRF
    allowCredentials: allow.map(id => ({ type: 'public-key', id: b64u.dec(id) })),
    userVerification: 'required', timeout: 120000,
    extensions: { prf: { eval: { first: await prfSalt() } } },
  } });
  const prf = cred.getClientExtensionResults().prf?.results?.first;
  if (!prf) throw new PrfUnsupportedError();
  return { prf, credentialId: b64u.enc(cred.rawId) };
}

async function createPasskey(opts, exclude = []) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: b64u.dec(opts.challenge),
    rp: opts.rp,
    user: { id: b64u.dec(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    excludeCredentials: exclude.map(id => ({ type: 'public-key', id: b64u.dec(id) })),
    attestation: 'none', timeout: 120000,
    extensions: { prf: { eval: { first: await prfSalt() } } },
  } });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf?.enabled) throw new PrfUnsupportedError();
  const credentialId = b64u.enc(cred.rawId);
  // Some authenticators only return PRF output on get(), so ask once more (after another tap) if needed.
  let prf = ext.prf.results?.first;
  if (!prf) { await nextStep('Confirm your new passkey once more to finish setting up encryption.'); prf = (await prfFromGet([credentialId])).prf; }
  const r = cred.response;
  return {
    prf,
    payload: {
      credentialId,
      clientDataJSON: b64u.enc(r.clientDataJSON),
      authenticatorData: b64u.enc(r.getAuthenticatorData()),
      publicKey: b64u.enc(r.getPublicKey()),
      alg: r.getPublicKeyAlgorithm(),
    },
  };
}

// ---------- passwords ----------
// Argon2id cost for new passwords; keep in sync with server.js (which rejects anything lower).
const KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1 }; // m in KiB: 64 MiB

// Argon2id once, then HKDF into two unrelated keys: one to prove the password to the server, one to wrap the root.
// kdf comes from the server for existing passwords, so bound it: a hostile value could make the page hang.
async function passwordKeys(password, salt, kdf) {
  const { alg, m, t, p } = kdf || {};
  if (alg !== 'argon2id' || !(m >= 8 * p && m <= 1048576) || !(t >= 1 && t <= 20) || !(p >= 1 && p <= 4)) throw new Error('Unsupported password settings');
  // Async so the page stays responsive: it takes about a second on a laptop, longer on a phone.
  const bits = await argon2idAsync(te.encode(password.normalize('NFKC')), b64u.dec(salt), { m, t, p, dkLen: 32 });
  const hkdf = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  const authKey = b64u.enc(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('6j0-id'), info: te.encode('password-auth-v1') }, hkdf, 256));
  const kek = await hkdfAes(bits, '6j0-id', 'password-kek-v1');
  bits.fill(0);
  return { authKey, kek };
}

// Fresh salt + keys for a new password, and the root secret wrapped under it: the body for register / PUT.
async function newPasswordBody(name, password, raw) {
  const salt = b64u.enc(crypto.getRandomValues(new Uint8Array(16)));
  const { authKey, kek } = await passwordKeys(password, salt, KDF);
  return { username: name, salt, kdf: KDF, authKey, wrappedRoot: await seal(kek, raw) };
}

const COMMON = ['password', 'passw0rd', '123456', '12345678', 'qwerty', 'letmein', 'iloveyou', 'admin', 'welcome',
  'abc123', '111111', 'monkey', 'dragon', 'football', 'baseball', 'sunshine', 'princess', '6j0'];

// Why a new password isn't good enough, or '' if it is. The server can't check (it never sees the password).
function passwordProblem(password, name) {
  const lower = password.toLowerCase();
  if (password.length < 12) return 'Use at least 12 characters, or tap "Generate one".';
  if (password.length > 256) return 'Use at most 256 characters.';
  if (name && lower.includes(name.toLowerCase())) return "Don't put your username in your password.";
  if (new Set(password).size < 6) return 'That password repeats too much. Try a longer phrase, or tap "Generate one".';
  if (password.length < 20 && COMMON.some(w => lower.includes(w))) return 'That password is too easy to guess. Try a longer phrase, or tap "Generate one".';
  return '';
}

// 4 groups of 5 characters from 31 that don't look alike: about 99 bits, e.g. "k7mq2-x9fpz-r4tnh-a8wvc".
function generatePassword() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  let out = '';
  while (out.length < 20) for (const b of crypto.getRandomValues(new Uint8Array(32))) {
    if (b < 248 && out.length < 20) out += alphabet[b % 31]; // 248 = 8 × 31, so no bias
  }
  return out.match(/.{5}/g).join('-');
}

// ---------- root secret storage (IndexedDB, non-extractable) ----------
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('6j0-id', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('keys');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbDo(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('keys', mode), req = fn(tx.objectStore('keys'));
    tx.oncomplete = () => { db.close(); resolve(req?.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

let root = null; // { guid, key: CryptoKey (HKDF, deriveBits) }

async function loadRoot(guid) {
  try { const r = await idbDo('readonly', s => s.get('root')); root = r && r.guid === guid ? r : null; } catch { root = null; }
  return Boolean(root);
}
async function installRoot(guid, raw) {
  root = { guid, key: await subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']) };
  raw.fill(0);
  try { await idbDo('readwrite', s => s.put(root, 'root')); } catch {}
}
async function clearRoot() {
  root = null;
  try { await idbDo('readwrite', s => s.delete('root')); } catch {}
}

const appKeyBits = (app) => subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: te.encode('6j0-id'), info: te.encode(`6j0/v1/app/${app}`) }, root.key, 256);

// ---------- API ----------
async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: method !== 'GET' ? { 'Content-Type': 'application/json' } : {},
    body: method !== 'GET' ? JSON.stringify(body ?? {}) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { status: res.status });
  return data;
}

// ---------- identity flows ----------
async function createIdentity() {
  const opts = await api('/api/passkey/register/options', { method: 'POST' });
  const { prf, payload } = await createPasskey(opts);
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const res = await api('/api/passkey/register/verify', { method: 'POST', body: { ...payload, wrappedRoot: await seal(await kekFromPrf(prf), raw) } });
  await installRoot(res.user.guid, raw);
  return res.user;
}

async function signIn() {
  const opts = await api('/api/passkey/login/options', { method: 'POST' });
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: b64u.dec(opts.challenge), rpId: opts.rpId, userVerification: 'required', timeout: 120000,
    extensions: { prf: { eval: { first: await prfSalt() } } },
  } });
  const prf = cred.getClientExtensionResults().prf?.results?.first;
  if (!prf) throw new PrfUnsupportedError();
  const r = cred.response;
  const res = await api('/api/passkey/login/verify', { method: 'POST', body: {
    credentialId: b64u.enc(cred.rawId),
    clientDataJSON: b64u.enc(r.clientDataJSON),
    authenticatorData: b64u.enc(r.authenticatorData),
    signature: b64u.enc(r.signature),
    userHandle: r.userHandle ? b64u.enc(r.userHandle) : undefined,
  } });
  await installRoot(res.user.guid, await openBytes(await kekFromPrf(prf), res.wrappedRoot));
  return res.user;
}

async function createWithPassword(name, password) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const res = await api('/api/password/register', { method: 'POST', body: await newPasswordBody(name, password, raw) });
  await installRoot(res.user.guid, raw);
  return res.user;
}

async function signInWithPassword(name, password) {
  const { salt, kdf } = await api('/api/password/prelogin', { method: 'POST', body: { username: name } });
  const { authKey, kek } = await passwordKeys(password, salt, kdf);
  const res = await api('/api/password/login', { method: 'POST', body: { username: name, authKey } });
  await installRoot(res.user.guid, await openBytes(kek, res.wrappedRoot));
  return res.user;
}

class WrongPasswordError extends Error {
  constructor() { super('That password is wrong.'); }
}

// Unlock the raw root secret while signed in (the stored copy is non-extractable), with the password.
// Returns the auth key too, which changing the password needs.
async function unlockWithPassword(pw, password) {
  const { authKey, kek } = await passwordKeys(password, pw.salt, pw.kdf);
  try { return { raw: await openBytes(kek, pw.wrappedRoot), authKey }; } catch { throw new WrongPasswordError(); }
}

// ...or with one of the passkeys in `existing` ([{ credentialId, wrappedRoot }]).
async function unlockWithPasskey(existing) {
  const unlock = await prfFromGet(existing.map(p => p.credentialId));
  return openBytes(await kekFromPrf(unlock.prf), existing.find(p => p.credentialId === unlock.credentialId).wrappedRoot);
}

// ...with whichever the person picks, if they have both.
async function unlockRoot(existing, pw) {
  const how = existing.length && pw ? await choose('Confirm it’s you', 'Unlock your identity with a passkey or your password first.',
    [['passkey', 'Use a passkey'], ['password', 'Use my password']]) : existing.length ? 'passkey' : 'password';
  if (how === 'passkey') return unlockWithPasskey(existing);
  return (await askPassword('Confirm it’s you', 'Enter your password to unlock your identity.', pw.username,
    (password) => unlockWithPassword(pw, password))).raw;
}

async function addPasskey() {
  const opts = await api('/api/passkey/add/options', { method: 'POST' });
  const existing = opts.existing.map(p => p.credentialId);
  const { password: pw } = await api('/api/password');
  const raw = await unlockRoot(opts.existing, pw);
  await nextStep('Confirmed. Now create the new passkey: on this device, your phone (scan the QR code), or a security key. It must support PRF: some password managers, including Bitwarden, do not.', 'Create new passkey');
  const { prf, payload } = await createPasskey(opts, existing);
  const body = { ...payload, wrappedRoot: await seal(await kekFromPrf(prf), raw) };
  raw.fill(0);
  return api('/api/passkey/add/verify', { method: 'POST', body });
}

// Set a password (unlocking with a passkey), or change it (unlocking with the current password).
async function setPassword() {
  const { password: pw } = await api('/api/password');
  let raw, currentAuthKey;
  if (pw) {
    ({ raw, authKey: currentAuthKey } = await askPassword('Change your password', 'First enter your current password.', pw.username,
      (password) => unlockWithPassword(pw, password)));
  } else {
    const opts = await api('/api/passkey/add/options', { method: 'POST' });
    raw = await unlockWithPasskey(opts.existing);
  }
  try {
    await askNewPassword(pw ? 'New password' : 'Set a password',
      pw ? 'Choose a new password. You can change your username too.'
        : 'Choose a username and password, so you can sign in where your passkey isn’t available.',
      pw?.username || '',
      async (name, password) => api('/api/password', { method: 'PUT', body: { ...await newPasswordBody(name, password, raw), currentAuthKey } }));
  } finally { raw.fill(0); }
}

// Send the signed-in browser back to the app with a token and that app's key, encrypted to the app page.
async function handoff({ app, nonce, epk }) {
  const { token, origin } = await api('/api/authorize', { method: 'POST', body: { app, nonce } });
  const [x, y] = epk.split('.');
  const peer = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x, y, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const mine = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: peer }, mine.privateKey, 256);
  const wrapKey = await hkdfAes(new Uint8Array(shared), nonce, `6j0/v1/handoff/${app}`);
  const appKey = new Uint8Array(await appKeyBits(app));
  const key = await seal(wrapKey, appKey);
  appKey.fill(0);
  const pub = await subtle.exportKey('jwk', mine.publicKey);
  const frag = new URLSearchParams({ id_token: token, epk: `${pub.x}.${pub.y}`, key, state: nonce });
  location.replace(`${origin}/#${frag}`);
}

// ---------- UI ----------
const app = document.getElementById('app');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hostOf = (origin) => { try { return new URL(origin).host; } catch { return origin; } };

// Shown up front when the browser says it can't do PRF, and after a passkey turns out not to (the browser can't tell
// in advance when a password-manager extension or app takes over the passkey prompt).
const PRF_ADVICE = `6j0.org encrypts each app's data with a key that only your passkey can make, using a passkey
  feature called <b>PRF</b>. This browser or passkey manager doesn't support it. <b>Some password managers, including
  Bitwarden, don't support it yet.</b><br><br>
  Passkeys that do: a <b>security key</b> (YubiKey 5, Nitrokey 3, SoloKey 2 and similar), <b>Google Password
  Manager</b> (Chrome, Android) and <b>iCloud Keychain</b> (Safari on macOS/iOS 18 or newer).<br><br>
  Or use a <b>username and password</b> instead: any password manager can store those.`;

// Put an error in an .error element: the full PRF advice for PrfUnsupportedError, plain text otherwise.
function showError(el, e) {
  if (e instanceof PrfUnsupportedError) el.innerHTML = `<b>${esc(e.message)}</b><div class="notice warn">${PRF_ADVICE}</div>`;
  else el.textContent = errorText(e);
}

function errorText(e) {
  if (e instanceof PrfUnsupportedError) return e.message;
  if (e?.name === 'NotAllowedError') return 'Passkey request was cancelled or timed out.';
  if (e?.name === 'InvalidStateError') return 'That device already has a passkey for this identity.';
  return e?.message || 'Something went wrong';
}

// "Tap to continue" between passkey prompts (Safari allows only one prompt per tap). Rejects if dismissed.
function nextStep(message, button = 'Continue') {
  return new Promise((resolve, reject) => {
    const sheet = document.createElement('div');
    sheet.className = 'sheet';
    sheet.innerHTML = `<div class="panel stack" role="dialog" aria-live="polite">
      <h2>One more step</h2><p class="note">${esc(message)}</p>
      <div class="two"><button type="button" class="btn ghost" data-act="cancel">Cancel</button>
        <button type="button" class="btn" data-act="go">${esc(button)}</button></div></div>`;
    document.body.appendChild(sheet);
    sheet.querySelector('[data-act=go]').onclick = () => { sheet.remove(); resolve(); };
    sheet.querySelector('[data-act=cancel]').onclick = () => { sheet.remove(); reject(Object.assign(new Error('Cancelled'), { name: 'NotAllowedError' })); };
    sheet.querySelector('[data-act=go]').focus();
  });
}

// A dialog with a form. onSubmit(form) runs on submit: its result resolves the promise and closes the dialog, and
// an error is shown in the dialog so the person can fix it and try again. Cancel rejects like a cancelled passkey.
function formSheet(title, message, fieldsHtml, submitLabel, onSubmit) {
  return new Promise((resolve, reject) => {
    const sheet = document.createElement('div');
    sheet.className = 'sheet';
    sheet.innerHTML = `<form class="panel stack" role="dialog" aria-label="${esc(title)}">
      <h2>${esc(title)}</h2>${message ? `<p class="note">${esc(message)}</p>` : ''}${fieldsHtml}
      <div class="error" role="alert"></div>
      <div class="two"><button type="button" class="btn ghost" data-act="cancel">Cancel</button>
        <button class="btn">${esc(submitLabel)}</button></div></form>`;
    document.body.appendChild(sheet);
    const form = sheet.querySelector('form'), err = sheet.querySelector('.error'), go = sheet.querySelector('button:not([type])');
    form.onsubmit = async (e) => {
      e.preventDefault();
      err.textContent = ''; go.disabled = true; go.textContent = 'Working…';
      try { const r = await onSubmit(form); sheet.remove(); resolve(r); }
      catch (e) { if (e?.name === 'NotAllowedError') { sheet.remove(); reject(e); } else showError(err, e); }
      finally { go.disabled = false; go.textContent = submitLabel; }
    };
    sheet.querySelector('[data-act=cancel]').onclick = () => { sheet.remove(); reject(Object.assign(new Error('Cancelled'), { name: 'NotAllowedError' })); };
    (form.querySelector('input:not([type=hidden]):not([readonly])') || go).focus();
  });
}

// Pick one of [[value, label], ...]. Cancel rejects like a cancelled passkey.
function choose(title, message, options) {
  return new Promise((resolve, reject) => {
    const sheet = document.createElement('div');
    sheet.className = 'sheet';
    sheet.innerHTML = `<div class="panel stack" role="dialog" aria-label="${esc(title)}">
      <h2>${esc(title)}</h2><p class="note">${esc(message)}</p>
      ${options.map(([v, label]) => `<button type="button" class="btn" data-pick="${esc(v)}">${esc(label)}</button>`).join('')}
      <button type="button" class="btn ghost" data-act="cancel">Cancel</button></div>`;
    document.body.appendChild(sheet);
    sheet.querySelectorAll('[data-pick]').forEach(b => b.onclick = () => { sheet.remove(); resolve(b.dataset.pick); });
    sheet.querySelector('[data-act=cancel]').onclick = () => { sheet.remove(); reject(Object.assign(new Error('Cancelled'), { name: 'NotAllowedError' })); };
    sheet.querySelector('[data-pick]').focus();
  });
}

// Ask for an existing password; resolves with check(password). The read-only username helps password managers.
function askPassword(title, message, name, check) {
  return formSheet(title, message, `
    <input type="hidden" name="username" autocomplete="username" value="${esc(name)}">
    <label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label>`,
    'Continue', (form) => check(form.password.value));
}

// The username + new password fields, with "Generate one" (which shows the generated password so it can be saved).
const newPasswordFields = (name = '') => `
  <label class="field">Username <span class="hint">Private: only used to sign in, never shown to anyone.</span>
    <input name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required minlength="3" maxlength="32"
      pattern="[A-Za-z0-9][A-Za-z0-9._\\-]{2,31}" value="${esc(name)}"></label>
  <label class="field">Password <span class="hint">At least 12 characters. A long phrase is easier to remember.</span>
    <input type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
  <button type="button" class="btn ghost small" data-act="generate">Generate one</button>
  <label class="field">Confirm password<input type="password" name="confirm" autocomplete="new-password" required></label>
  <p class="note">Save it in a password manager. There's no email, so <b>nobody can reset a forgotten password</b>:
    add a passkey later as a backup.</p>`;

// Ask for a username + new password; checks them, then resolves with submit(name, password).
function askNewPassword(title, message, name, submit) {
  const done = formSheet(title, message, newPasswordFields(name), 'Save', async (form) => {
    const user = form.username.value.trim().toLowerCase(), password = form.password.value;
    const problem = passwordProblem(password, user);
    if (problem) throw new Error(problem);
    if (password !== form.confirm.value) throw new Error("The passwords don't match.");
    return submit(user, password);
  });
  wireGenerate(document.body.lastElementChild.querySelector('form'));
  return done;
}

function wireGenerate(form) {
  form.querySelector('[data-act=generate]').onclick = () => {
    const p = generatePassword();
    for (const input of [form.password, form.confirm]) { input.type = 'text'; input.value = p; }
    form.password.select();
  };
}

function readRequest(apps) {
  if (location.pathname !== '/authorize') return null;
  const p = new URLSearchParams(location.search);
  const req = { app: p.get('app') || '', nonce: p.get('nonce') || '', epk: p.get('epk') || '' };
  if (!Object.hasOwn(apps, req.app)) return { error: `"${req.app}" isn't a 6j0.org app.` };
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(req.nonce) || !/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(req.epk))
    return { error: 'This sign-in link is incomplete. Go back to the app and try again.' };
  return { ...req, origin: apps[req.app] };
}

function viewSignIn(request, support) {
  const to = request && !request.error ? ` to continue to <b>${esc(hostOf(request.origin))}</b>` : '';
  app.innerHTML = `
    <h1>6j0.org</h1>
    <p class="lead">One anonymous identity for every 6j0.org app. Sign in${to}.</p>
    <button class="btn" data-act="signin">Sign in with passkey</button>
    <button class="btn ghost" data-act="create" ${support === false ? 'disabled' : ''}>Create an identity with a passkey</button>
    <div class="error" role="alert" id="passkeyErr"></div>
    <div class="notice ${support === false ? 'warn' : ''}">${support === false ? PRF_ADVICE : `
      <b>No names or email.</b> Your identity is a random ID with a passkey or a password. Each app gets its own
      encryption key, and no app can read another's data.<br><br>
      Your passkey or password <b>is</b> your identity, and nobody can reset it. After signing in, add a second way
      in (another passkey, or a password), so losing one doesn't lose everything.`}</div>
    <h2>Or use a username and password</h2>
    <form class="stack" id="pwSignIn">
      <label class="field">Username<input name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required></label>
      <label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label>
      <div class="error" role="alert" id="pwErr"></div>
      <button class="btn ${support === false ? '' : 'ghost'}">Sign in with password</button>
    </form>
    <button class="btn ghost" data-act="pwcreate">Create an identity with a password</button>`;
  const passkeyErr = app.querySelector('#passkeyErr'), pwErr = app.querySelector('#pwErr');
  const run = (err, fn) => async () => {
    passkeyErr.textContent = ''; pwErr.textContent = '';
    try { await fn(); await afterSignIn(request); } catch (e) { if (e?.name !== 'NotAllowedError' || err === passkeyErr) showError(err, e); }
  };
  app.querySelector('[data-act=signin]').onclick = run(passkeyErr, signIn);
  app.querySelector('[data-act=create]').onclick = run(passkeyErr, createIdentity);
  const form = app.querySelector('#pwSignIn'), go = form.querySelector('button');
  form.onsubmit = (e) => {
    e.preventDefault();
    go.disabled = true; go.textContent = 'Signing in…';
    run(pwErr, () => signInWithPassword(form.username.value.trim().toLowerCase(), form.password.value))()
      .finally(() => { go.disabled = false; go.textContent = 'Sign in with password'; });
  };
  app.querySelector('[data-act=pwcreate]').onclick = run(pwErr, () => askNewPassword('Create an identity',
    'Pick a username and password. Your identity is still anonymous: apps never see your username.', '', createWithPassword));
}

async function viewManage(me, apps, notice = '') {
  const [passkeys, { password: pw }] = await Promise.all([api('/api/passkeys'), api('/api/password')]);
  const ways = passkeys.length + (pw ? 1 : 0);
  const fmt = (iso) => iso ? new Date(iso.replace(' ', 'T') + 'Z').toLocaleDateString() : 'never';
  app.innerHTML = `
    <h1>6j0.org</h1>
    <p class="lead">Signed in as anonymous identity <code>${esc(me.guid.slice(0, 8))}</code>.</p>
    ${notice ? `<div class="notice">${esc(notice)}</div>` : ''}
    <h2>Apps</h2>
    <div class="list">${Object.entries(apps).map(([name, origin]) =>
      `<a class="row" href="${esc(origin)}/">${esc(name)}<span class="sub">${esc(hostOf(origin))}</span></a>`).join('') || '<p class="note">No apps are configured.</p>'}</div>
    <h2>Ways to sign in</h2>
    <div class="notice ${ways < 2 ? 'warn' : ''}">${ways < 2
      ? `<b>You only have one way to sign in.</b> If you lose ${pw ? 'or forget your password' : 'your passkey'}, your identity and every app's encrypted data are gone for good. Add a ${pw ? 'passkey (on your phone or a security key)' : 'second passkey or a password'} as a backup.`
      : `You have ${ways} ways to sign in, so losing one won't lock you out.`}</div>
    <div class="list">
      ${pw ? `<div class="row"><span>Password</span>
        <span class="sub">username <b>${esc(pw.username)}</b> · last used ${fmt(pw.last_used_at)}</span>
        <button class="btn ghost small" data-act="setpw">Change</button>
        ${ways > 1 ? `<button class="btn danger small" data-act="rmpw" aria-label="Remove password">Remove</button>` : ''}</div>` : ''}
      ${passkeys.map((p, i) => `<div class="row"><span>Passkey ${i + 1}</span>
        <span class="sub">added ${fmt(p.created_at)} · last used ${fmt(p.last_used_at)}</span>
        ${ways > 1 ? `<button class="btn danger small" data-rm="${p.id}" aria-label="Remove passkey ${i + 1}">Remove</button>` : ''}</div>`).join('')}
    </div>
    <button class="btn ghost" data-act="add">${passkeys.length ? 'Add another passkey' : 'Add a passkey'}</button>
    ${pw ? '' : `<button class="btn ghost" data-act="setpw">Add a password</button>`}
    <div class="error" role="alert"></div>
    <button class="btn danger" data-act="logout">Sign out of 6j0.org</button>
    <p class="note">Signing out here stops apps from signing you in automatically. Apps you're already signed in to stay signed in until you sign out of them.</p>`;
  const err = app.querySelector('.error');
  const act = (fn, done) => async () => {
    err.textContent = '';
    try { await fn(); await viewManage(me, apps, done); } catch (e) { if (e?.name !== 'NotAllowedError' || !e.message.startsWith('Cancelled')) showError(err, e); }
  };
  app.querySelector('[data-act=add]').onclick = act(addPasskey, 'Passkey added. You now have a backup.');
  app.querySelectorAll('[data-act=setpw]').forEach(b => b.onclick = act(setPassword, pw ? 'Password changed.' : 'Password added. You now have a backup.'));
  app.querySelector('[data-act=rmpw]')?.addEventListener('click', () => {
    if (confirm("Remove your password? You won't be able to sign in with it anymore.")) act(() => api('/api/password', { method: 'DELETE' }))();
  });
  app.querySelectorAll('[data-rm]').forEach(b => b.onclick = () => {
    if (confirm("Remove this passkey? You won't be able to sign in with it anymore.")) act(() => api(`/api/passkeys/${b.dataset.rm}`, { method: 'DELETE' }))();
  });
  app.querySelector('[data-act=logout]').onclick = async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch {}
    await clearRoot();
    await boot();
  };
}

function viewMessage(title, text) {
  app.innerHTML = `<h1>6j0.org</h1><h2>${esc(title)}</h2><p class="lead">${esc(text)}</p><a class="btn ghost" href="/">Manage your identity</a>`;
}

let appsCache = {};
async function afterSignIn(request) {
  const me = await api('/api/me');
  if (request && !request.error) {
    viewMessage('Signing you in…', `Taking you back to ${hostOf(request.origin)}.`);
    return handoff(request);
  }
  history.replaceState(null, '', '/');
  return viewManage(me, appsCache);
}

async function boot() {
  appsCache = await api('/api/apps');
  const request = readRequest(appsCache);
  if (request?.error) return viewMessage("Can't sign in", request.error);
  let me = null;
  try { me = await api('/api/me'); } catch {}
  // Signed in here and this browser still holds the root secret: no passkey prompt needed.
  if (me && await loadRoot(me.guid)) return afterSignIn(request);
  viewSignIn(request, await prfSupport());
}

boot().catch(e => viewMessage('Something went wrong', errorText(e)));
