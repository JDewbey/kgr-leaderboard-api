# KGR Leaderboard API

- POST `/submitScore`  { txHash, address, score:number }
- GET  `/leaderboard?limit=100`

Requires env:
- DATABASE_URL (Postgres connection string)
- KGR_CORS (comma-separated allowed origins; leave empty for first test)

Start: `node server.js`
