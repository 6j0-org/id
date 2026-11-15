// Minimal WebAuthn (passkey) verification using only node:crypto.
//
// Registration trusts the browser-provided SPKI public key (AuthenticatorAttestationResponse.getPublicKey())
// and uses attestation "none", so no CBOR parsing is needed. We still check the challenge, origin,
// RP ID hash, user-presence/verification flags and that the credential ID matches the authenticator data.
// Sign-in verifies the assertion signature over authenticatorData || SHA-256(clientDataJSON).

import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export class WebAuthnError extends Error {}

const sha256 = (data) => createHash('sha256').update(data).digest();
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s, what) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new WebAuthnError(`Bad ${what}`);
  return Buffer.from(s, 'base64url');
};

export const ALGS = { ES256: -7, RS256: -257 };
const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40;

// ---------- challenges (single use, short-lived, in memory) ----------
const challenges = new Map(); // challenge (b64url) -> { kind, data, expires }
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export function newChallenge(kind, data = {}) {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
  const challenge = b64u(randomBytes(32));
  challenges.set(challenge, { kind, data, expires: now + CHALLENGE_TTL_MS });
  return challenge;
}

function takeChallenge(challenge, kind) {
  const c = challenges.get(challenge);
  challenges.delete(challenge);
  if (!c || c.kind !== kind || c.expires < Date.now()) throw new WebAuthnError('This passkey request expired. Please try again.');
  return c.data;
}

// ---------- shared checks ----------
function checkClientData(clientDataB64, type, kind, origin) {
  const raw = fromB64u(clientDataB64, 'clientDataJSON');
  let cd;
  try { cd = JSON.parse(raw.toString('utf8')); } catch { throw new WebAuthnError('Bad clientDataJSON'); }
  if (cd.type !== type) throw new WebAuthnError('Wrong passkey operation');
  if (cd.origin !== origin) throw new WebAuthnError(`Passkey origin mismatch (${cd.origin})`);
  const data = takeChallenge(cd.challenge, kind);
  return { hash: sha256(raw), data };
}

function checkAuthData(authDataB64, rpId) {
  const ad = fromB64u(authDataB64, 'authenticatorData');
  if (ad.length < 37) throw new WebAuthnError('Bad authenticatorData');
  if (!ad.subarray(0, 32).equals(sha256(rpId))) throw new WebAuthnError('Passkey is for a different site');
  const flags = ad[32];
  if (!(flags & FLAG_UP) || !(flags & FLAG_UV)) throw new WebAuthnError('Passkey did not verify the user');
  return { ad, flags, signCount: ad.readUInt32BE(33) };
}

// ---------- registration ----------
// Returns { credentialId, publicKey (b64url SPKI), alg, signCount, data } where data is what newChallenge stored.
export function verifyRegistration(body, { origin, rpId, kind }) {
  const { data } = checkClientData(body.clientDataJSON, 'webauthn.create', kind, origin);
  const { ad, flags, signCount } = checkAuthData(body.authenticatorData, rpId);
  if (!(flags & FLAG_AT) || ad.length < 55) throw new WebAuthnError('Passkey did not include credential data');
  const idLen = ad.readUInt16BE(53);
  const credId = ad.subarray(55, 55 + idLen);
  if (!credId.equals(fromB64u(body.credentialId, 'credential ID'))) throw new WebAuthnError('Credential ID mismatch');

  const alg = Number(body.alg);
  if (alg !== ALGS.ES256 && alg !== ALGS.RS256) throw new WebAuthnError('Unsupported passkey algorithm');
  const spki = fromB64u(body.publicKey, 'public key');
  let key;
  try { key = createPublicKey({ key: spki, format: 'der', type: 'spki' }); } catch { throw new WebAuthnError('Bad passkey public key'); }
  if ((alg === ALGS.ES256) !== (key.asymmetricKeyType === 'ec')) throw new WebAuthnError('Passkey key type mismatch');
  return { credentialId: b64u(credId), publicKey: b64u(spki), alg, signCount, data };
}

// ---------- sign-in ----------
// stored: { public_key, alg, sign_count } for the credential the browser used. Returns { signCount, data }.
export function verifyAssertion(body, stored, { origin, rpId, kind }) {
  const { hash, data } = checkClientData(body.clientDataJSON, 'webauthn.get', kind, origin);
  const { ad, signCount } = checkAuthData(body.authenticatorData, rpId);
  const sig = fromB64u(body.signature, 'signature');
  const key = createPublicKey({ key: Buffer.from(stored.public_key, 'base64url'), format: 'der', type: 'spki' });
  const signed = Buffer.concat([ad, hash]);
  const ok = stored.alg === ALGS.ES256
    ? verify('sha256', signed, { key, dsaEncoding: 'der' }, sig)
    : verify('sha256', signed, key, sig);
  if (!ok) throw new WebAuthnError('Passkey signature check failed');
  // Synced passkeys report 0; only enforce the counter when both sides use one.
  if (signCount && stored.sign_count && signCount <= stored.sign_count) throw new WebAuthnError('Passkey counter went backwards; it may be cloned');
  return { signCount, data };
}
