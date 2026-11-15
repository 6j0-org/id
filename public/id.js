// 6j0.org identity: one passkey for every 6j0.org app, and a separate encryption key for each of them.
//
// Keys
// - Each passkey yields a secret via the WebAuthn PRF extension. HKDF turns it into a key-encryption key that wraps
//   the identity's random 256-bit *root secret*. The server stores one wrapped copy per passkey and never sees the
//   PRF output or the root secret.
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

async function addPasskey() {
  const opts = await api('/api/passkey/add/options', { method: 'POST' });
  const existing = opts.existing.map(p => p.credentialId);
  const unlock = await prfFromGet(existing);
  const wrapped = opts.existing.find(p => p.credentialId === unlock.credentialId).wrappedRoot;
  const raw = await openBytes(await kekFromPrf(unlock.prf), wrapped);
  await nextStep('Confirmed. Now create the new passkey: on this device, your phone (scan the QR code), a security key, or a password manager like Bitwarden.', 'Create new passkey');
  const { prf, payload } = await createPasskey(opts, existing);
  const body = { ...payload, wrappedRoot: await seal(await kekFromPrf(prf), raw) };
  raw.fill(0);
  return api('/api/passkey/add/verify', { method: 'POST', body });
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

const UPGRADE_ADVICE = `6j0.org encrypts each app's data with a key that only your passkey can make, and this browser
  or passkey manager can't do that yet. Please update to the latest <b>Chrome</b>, <b>Edge</b>, <b>Safari</b>
  (macOS/iOS 18 or newer) or <b>Firefox</b>, or store your passkey in <b>Bitwarden</b>, then try again.`;

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
    <button class="btn ghost" data-act="create" ${support === false ? 'disabled' : ''}>Create an identity</button>
    <div class="error" role="alert"></div>
    <div class="notice ${support === false ? 'warn' : ''}">${support === false ? UPGRADE_ADVICE : `
      <b>No usernames, passwords or email.</b> Your identity is a random ID and a passkey. Each app gets its own
      encryption key from your passkey, and no app can read another's data.<br><br>
      Your passkey <b>is</b> your identity: keep it in a password manager like <b>Bitwarden</b>, or add a second
      device after signing in, so losing one device doesn't lose everything.`}</div>`;
  const err = app.querySelector('.error');
  const run = (fn) => async () => {
    err.textContent = '';
    try { await fn(); await afterSignIn(request); } catch (e) { err.textContent = errorText(e); }
  };
  app.querySelector('[data-act=signin]').onclick = run(signIn);
  app.querySelector('[data-act=create]').onclick = run(createIdentity);
}

async function viewManage(me, apps, notice = '') {
  const passkeys = await api('/api/passkeys');
  const fmt = (iso) => iso ? new Date(iso.replace(' ', 'T') + 'Z').toLocaleDateString() : 'never';
  app.innerHTML = `
    <h1>6j0.org</h1>
    <p class="lead">Signed in as anonymous identity <code>${esc(me.guid.slice(0, 8))}</code>.</p>
    ${notice ? `<div class="notice">${esc(notice)}</div>` : ''}
    <h2>Apps</h2>
    <div class="list">${Object.entries(apps).map(([name, origin]) =>
      `<a class="row" href="${esc(origin)}/">${esc(name)}<span class="sub">${esc(hostOf(origin))}</span></a>`).join('') || '<p class="note">No apps are configured.</p>'}</div>
    <h2>Passkeys</h2>
    <div class="notice ${passkeys.length < 2 ? 'warn' : ''}">${passkeys.length < 2
      ? '<b>You only have one passkey.</b> If you lose it, your identity and every app\'s encrypted data are gone for good. Add another one: on your phone, a security key, or a password manager like <b>Bitwarden</b>.'
      : `You have ${passkeys.length} passkeys, so losing one device won't lock you out.`}</div>
    <div class="list">${passkeys.map((p, i) => `<div class="row"><span>Passkey ${i + 1}</span>
      <span class="sub">added ${fmt(p.created_at)} · last used ${fmt(p.last_used_at)}</span>
      ${passkeys.length > 1 ? `<button class="btn danger small" data-rm="${p.id}" aria-label="Remove passkey ${i + 1}">Remove</button>` : ''}</div>`).join('')}</div>
    <button class="btn ghost" data-act="add">Add another passkey</button>
    <div class="error" role="alert"></div>
    <button class="btn danger" data-act="logout">Sign out of 6j0.org</button>
    <p class="note">Signing out here stops apps from signing you in automatically. Apps you're already signed in to stay signed in until you sign out of them.</p>`;
  const err = app.querySelector('.error');
  app.querySelector('[data-act=add]').onclick = async () => {
    err.textContent = '';
    try { await addPasskey(); await viewManage(me, apps, 'Passkey added. You now have a backup.'); } catch (e) { err.textContent = errorText(e); }
  };
  app.querySelectorAll('[data-rm]').forEach(b => b.onclick = async () => {
    if (!confirm("Remove this passkey? You won't be able to sign in with it anymore.")) return;
    try { await api(`/api/passkeys/${b.dataset.rm}`, { method: 'DELETE' }); await viewManage(me, apps); } catch (e) { err.textContent = errorText(e); }
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
