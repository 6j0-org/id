import { DatabaseSync } from 'node:sqlite';

export const db = new DatabaseSync(process.env.DB_PATH || new URL('./data.sqlite', import.meta.url).pathname);

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- An identity has no name, email or password: just a random GUID, authenticated by passkeys.
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

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// Prototype: no migrations. After a schema change, delete data.sqlite*.
