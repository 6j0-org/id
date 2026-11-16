import { DatabaseSync } from 'node:sqlite';

export const db = new DatabaseSync(process.env.DB_PATH || new URL('./data.sqlite', import.meta.url).pathname);

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- An identity has no name or email: just a random GUID, authenticated by passkeys and/or one username + password.
-- It is the "sub" every 6j0.org app sees for this person.
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY,
  guid       TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One row per passkey. wrapped_root is the identity's random root secret, encrypted in the browser with a key derived
-- from this passkey's PRF output (see public/id.js). The server never sees the root secret or any app key.
CREATE TABLE IF NOT EXISTS passkeys (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,                -- base64url
  public_key    TEXT NOT NULL,                       -- SPKI DER, base64url
  alg           INTEGER NOT NULL,                    -- COSE: -7 ES256, -257 RS256
  sign_count    INTEGER NOT NULL DEFAULT 0,
  wrapped_root  TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at  TEXT
);

-- At most one username + password per identity, for people whose passkey manager can't do PRF (see public/id.js).
-- The browser never sends the password: it runs Argon2id(password, salt, kdf) itself and sends only auth_key, a
-- separate HKDF output. auth_hash is scrypt(auth_key). wrapped_root is the root secret wrapped under another HKDF
-- output of the same Argon2id result, which never leaves the browser. Usernames are private: only used to sign in.
CREATE TABLE IF NOT EXISTS passwords (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  username     TEXT NOT NULL UNIQUE,                  -- lowercase
  salt         TEXT NOT NULL,                         -- Argon2id salt, 16 bytes, base64url
  kdf          TEXT NOT NULL,                         -- JSON Argon2id cost: {"alg":"argon2id","m":<KiB>,"t":<passes>,"p":<lanes>}
  auth_hash    TEXT NOT NULL,                         -- scrypt$N$r$p$salt$hash
  wrapped_root TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT
);

-- Server-side secrets that must survive restarts (e.g. the key for fake salts of unknown usernames).
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// Prototype: no migrations. After a schema change, delete data.sqlite*.
