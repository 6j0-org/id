# 6j0.org identity server. No npm packages: just Node (>= 24, for the built-in node:sqlite) and the app's own files.
FROM node:24-alpine

WORKDIR /app
COPY package.json server.js db.js webauthn.js tokens.js ./
COPY public ./public

# The SQLite database (identities, passkey public keys, wrapped root secrets) and the token signing key live here;
# mount a volume to keep them. Losing the volume loses every identity, and with it every app's encrypted data.
RUN mkdir -p /data && chown node:node /data
VOLUME /data

# Set ORIGIN (e.g. https://id.6j0.org) and APPS (e.g. bored=https://bored.6j0.org) in production.
ENV PORT=4000 DB_PATH=/data/data.sqlite
EXPOSE 4000
USER node
CMD ["node", "server.js"]
