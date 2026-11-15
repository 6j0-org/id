# 6j0.org identity

One anonymous identity, one passkey, for every 6j0.org app, and a separate encryption key for each app.

Apps send people here to sign in (`id.6j0.org/authorize`). This service runs the passkey and sends the browser back
to the app with:

- a **signed token** (an Ed25519 JWT with `aud` set to the app's name) that the app's server checks against
  `/.well-known/jwks.json`, and
- that **app's own encryption key**, encrypted to a one-time key the app's page made, in the URL fragment (browsers
  don't send the fragment to any server).

Identities are a random GUID plus one or more passkeys. No name, email or password.

## Why a separate service

Passkeys belong to an RP ID (relying party ID, the domain they're registered to). If every app shared the RP ID
`6j0.org`, any `*.6j0.org` page, including one with an XSS bug, could use the passkey and its PRF output to sign in
anywhere and rebuild every app's encryption key. Here the passkeys belong to `id.6j0.org` only, and this page gives
each app nothing but its own key. A bug in one app exposes that app, not the others.

## Run

Needs Node ≥ 24 (uses the built-in `node:sqlite`). No dependencies.

```sh
APPS=bored=http://127.0.0.1:3000 npm start   # http://localhost:4000
```

Passkeys need a **secure context** (`http://localhost` counts) and a browser + passkey manager that supports the
WebAuthn **PRF** extension (current Chrome/Edge, Safari on macOS/iOS 18+, Firefox, Bitwarden).

Env vars:

| Var | Default | |
|---|---|---|
| `PORT` | `4000` | |
| `DB_PATH` | `./data.sqlite` | Identities, passkey public keys, wrapped root secrets, sessions. |
| `SIGNING_KEY_PATH` | `signing-key.pem` next to `DB_PATH` | Ed25519 token signing key, generated on first start. |
| `ORIGIN` | from `Host` | e.g. `https://id.6j0.org`. Required in production: passkeys are bound to it, and `https:` turns on `Secure` cookies. |
| `RP_ID` | `ORIGIN` hostname | Leave it alone. Setting it to the parent domain defeats the point (see above). |
| `APPS` | none | Comma-separated `name=origin` list of apps allowed to sign in, e.g. `bored=https://bored.6j0.org,chorechart=https://chorechart.6j0.org`. The browser is only ever sent back to these origins. |

**Never rename or reuse an app name.** It's the token audience and goes into the app's key derivation, so renaming
one changes that app's key and makes everyone's data in it unreadable. Changing `ORIGIN` orphans every passkey.

This is a prototype, so there are no database migrations.

## Adding sign-in to an app

1. Add `name=https://app.6j0.org` to `APPS` here.
2. In the app's page, to sign in: make an ephemeral ECDH P-256 key pair and a random nonce (16–64 base64url chars),
   keep both (IndexedDB can hold the non-extractable private key), and go to
   `ID_ORIGIN/authorize?app=<name>&nonce=<nonce>&epk=<x>.<y>` (the public key's JWK `x` and `y`).
3. The browser comes back to `https://app.6j0.org/#id_token=…&epk=<x>.<y>&key=<iv>.<ciphertext>&state=<nonce>`.
   In the page: clear the fragment, check `state` against the stored nonce, then
   `ECDH(your private, epk) → HKDF-SHA-256(salt = nonce, info = "6j0/v1/handoff/<name>") → AES-256-GCM` decrypts
   `key` into the 32-byte app key. Derive the app's own key-encryption key from it, and use that to wrap the app's
   data key.
4. Send `id_token` and the nonce to the app's server. It verifies the Ed25519 signature (keys from
   `/.well-known/jwks.json`, by `kid`), `iss` = `ID_ORIGIN`, `aud` = `<name>`, `exp`, `nonce`, and that it hasn't
   seen the `jti` before. `sub` is the identity's stable ID. Keep it server-side and give the account its own
   public ID, so people can't link accounts across apps.

The bored repo is the reference implementation: `idtoken.js` (server) and `finishIdSignIn` in `public/secure.js`.

## How it works

| Piece | Where |
|---|---|
| Root secret: random 32 bytes per identity, wrapped under `HKDF(PRF output)` for each passkey. The server stores only the wrapped copies. | `public/id.js` |
| After sign-in, the root secret stays in IndexedDB as a non-extractable key, so apps sign in without another passkey prompt until you sign out here. | `public/id.js` |
| App key: `HKDF(root, salt "6j0-id", info "6j0/v1/app/<name>")`. | `public/id.js` |
| Tokens: EdDSA JWT, 2-minute lifetime, `{iss, sub, aud, nonce, iat, exp, jti}`. | `tokens.js` |
| Passkey verification (`node:crypto` only). | `webauthn.js` (shared with bored) |

## TODO

- [ ] **P0: Rate limiting** on identity creation and sign-in.
- [ ] **P0: Back up the volume.** Losing the database loses every identity, and with it every app's encrypted data.
  Losing the signing key just means apps re-fetch the new one.
- [ ] **P1: This page can derive every app's key** for whoever signs in, so a compromised id.6j0.org (or its
  deployment) is a compromise of every app. Keep it minimal: no third-party code, strict CSP, separate deployment.
- [ ] **P1: Session lifetime and revocation.** Identity sessions last 30 days, with no "sign out everywhere".
  Session tokens are stored unhashed.
- [ ] **P1: Signing out here doesn't sign you out of apps** that already have their own session.
- [ ] **P2: Passkey challenges live in process memory,** so run one replica.
- [ ] **P2: Removing a passkey doesn't rotate the root secret** (rotating it would change every app key).
- [ ] **P2: No identity deletion.**
