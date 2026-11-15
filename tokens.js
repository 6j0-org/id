// Sign-in tokens for 6j0.org apps: compact JWTs signed with Ed25519 ("EdDSA"), using only node:crypto.
//
// The signing key is generated on first start and kept next to the database (SIGNING_KEY_PATH), so it lives on the
// same volume and survives restarts. Apps fetch the public half from /.well-known/jwks.json.
// To rotate: stop the server, delete the file, start it again. Apps re-fetch the JWKS when they see an unknown kid.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const TOKEN_TTL_S = 120; // long enough for one redirect; apps also reject a token they've already seen

const defaultPath = () => join(dirname(process.env.DB_PATH || new URL('./data.sqlite', import.meta.url).pathname), 'signing-key.pem');
const keyPath = process.env.SIGNING_KEY_PATH || defaultPath();

function loadKey() {
  if (existsSync(keyPath)) return createPrivateKey(readFileSync(keyPath));
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  console.log(`Generated a new token signing key at ${keyPath}`);
  return privateKey;
}

const privateKey = loadKey();
const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }); // { kty: 'OKP', crv: 'Ed25519', x }
const kid = createHash('sha256').update(publicJwk.x).digest('base64url').slice(0, 16);

export const jwks = { keys: [{ ...publicJwk, kid, alg: 'EdDSA', use: 'sig' }] };

const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

// claims: { iss, sub, aud, nonce }. Adds iat, exp and a random jti.
export function signToken(claims) {
  const now = Math.floor(Date.now() / 1000);
  const head = enc({ alg: 'EdDSA', typ: 'JWT', kid });
  const body = enc({ ...claims, iat: now, exp: now + TOKEN_TTL_S, jti: randomBytes(16).toString('base64url') });
  const sig = sign(null, Buffer.from(`${head}.${body}`), privateKey).toString('base64url');
  return `${head}.${body}.${sig}`;
}
