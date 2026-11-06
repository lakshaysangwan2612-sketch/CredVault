# CredVault

Digital credential wallet. Node + Express + MongoDB, plain-HTML frontend served by Express.

## Run locally
1. Install Node 18+ and MongoDB (or use a free MongoDB Atlas URI)
2. `cp .env.example .env` and set `JWT_SECRET` (and `MONGO_URI` if using Atlas)
3. `npm install && npm start` -> http://localhost:3000

Demo logins (auto-seeded, password `demo1234`): student@credvault.edu, admin@credvault.edu

## How verification works
- On issue: canonical JSON -> SHA-256 hash -> signed with the institution Ed25519 private key.
- On verify: the hash is recomputed from the stored fields and the signature is checked
  against the public key (also served at /api/public-key). Editing any field breaks both.

## API
POST /api/auth/register | /api/auth/login
GET  /api/wallet, PATCH /api/wallet/:id/visibility        (student)
POST /api/admin/issue | /api/admin/bulk | /api/admin/revoke/:id, GET /api/admin/credentials  (admin)
GET  /api/verify/:idOrHash, /api/portfolio/:email, /api/public-key  (public)

## Deploy on AWS (simple)
EC2 t3.micro (or Lightsail) + MongoDB Atlas free tier: clone the repo, set .env,
`npm install`, run with `pm2 start server.js`, and put nginx or a load balancer in front for HTTPS.

## Before real use
Add rate limiting on /api/auth and /api/verify, and keep the signing key in a secrets manager rather than the DB.
