// KGR Global Leaderboard API — Hardened + Postgres + Rate Limit + Health + Autoprune

// -------- Imports --------
const express = require("express");
const fetch = require("node-fetch"); // v2.x (CommonJS)
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit"); // v6.x (require-friendly)
const { Pool } = require("pg");

// -------- Stellar constants --------
const HORIZON     = "https://horizon.stellar.org";
const KALE_CODE   = "KALE";
const KALE_ISSUER = "GBDVX4VELCDSQ54KQJYTNHXAHFLBCA77ZY2USQBM4CSHTTV7DME7KALE";
const TREASURY    = "GDIH6XE3UZ5CW37X3OKVS3SYKHG32PRPXPT3722NJ2AY3MOLCQNMUUTT";

// -------- App setup --------
const app = express();
app.set("trust proxy", 1);                   // so req.ip works behind Render
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use((_, res, next) => {                  // no caching for API responses
  res.set("Cache-Control", "no-store");
  next();
});

// CORS (lock down later with KGR_CORS="https://yourgame.com,https://other.com")
const ALLOWED = (process.env.KGR_CORS || "")
  .split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!ALLOWED.length) return cb(null, true); // open for first smoke tests
    if (!origin) return cb(null, true);         // allow curl/postman
    cb(null, ALLOWED.includes(origin));
  }
}));

// --- Basic health endpoints (keep these early) ---
app.get("/", (_req, res) => res.send("ok"));
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// -------- Database (Render Postgres via DATABASE_URL) --------
if (!process.env.DATABASE_URL) {
  console.warn("[kgr] WARNING: DATABASE_URL is not set");
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scores (
      id          BIGSERIAL PRIMARY KEY,
      address     TEXT NOT NULL,
      score       BIGINT NOT NULL CHECK (score >= 0 AND score <= 1000000000),
      tx_hash     TEXT NOT NULL UNIQUE,
      paid_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip          TEXT,
      ua          TEXT
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_scores_score_desc
      ON scores (score DESC, created_at ASC, id ASC);
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_scores_tx_hash
      ON scores (tx_hash);
  `);
  console.log("[kgr] DB ready");
}
ensureSchema().catch(err => {
  console.error("[kgr] DB init failed:", err);
  process.exit(1);
});

// -------- Helpers --------
function clampScore(raw) {
  const n = Math.floor(Number(raw));
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(n, 1_000_000_000);
}
async function getJson(url) {
  const r = await fetch(url, { headers: { "Accept": "application/json" } });
  if (!r.ok) throw new Error(`Horizon error ${r.status}`);
  return r.json();
}
function isRecent(iso, minutes = 30) {
  try { return (Date.now() - new Date(iso).getTime()) <= minutes * 60 * 1000; }
  catch { return false; }
}
async function txAlreadyUsed(txHash) {
  const { rows } = await pool.query(`SELECT 1 FROM scores WHERE tx_hash = $1 LIMIT 1`, [txHash]);
  return rows.length > 0;
}
async function topN(n = 50) {
  const { rows } = await pool.query(
    `SELECT address, score, tx_hash AS "txHash", paid_at AS "paidAtISO"
       FROM scores
       ORDER BY score DESC, created_at ASC, id ASC
       LIMIT $1`,
    [n]
  );
  return rows;
}

// -------- Per-route rate limiter for /submitScore --------
const submitLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 12,                    // 12 submits/min per key
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    try {
      if (req.path === "/submitScore" && req.body && typeof req.body.address === "string") {
        return `addr:${req.body.address.toUpperCase()}`;
      }
    } catch {}
    return `ip:${req.ip}`; // fallback to IP
  },
  handler: (req, res) => {
    res.set("Retry-After", "60");
    return res.status(429).json({ ok: false, error: "rate_limited", message: "Too many requests. Try again in a minute." });
  }
});

// -------- Routes --------

// POST /submitScore { txHash, address, score:number }
app.post("/submitScore", submitLimiter, async (req, res) => {
  try {
    let { txHash, address, score } = req.body || {};
    if (!txHash || !address || typeof score !== "number") {
      return res.status(400).send("txHash, address, score required");
    }

    address = String(address).toUpperCase();
    if (!/^G[A-Z2-7]{55}$/.test(address)) {
      return res.status(400).send("bad address");
    }

    if (await txAlreadyUsed(txHash)) {
      return res.status(409).send("tx already used");
    }

    const normScore = clampScore(score);

    // 1) transaction must be successful, recent, and have NO memo
    const tx = await getJson(`${HORIZON}/transactions/${txHash}`);
    if (tx.successful !== true) return res.status(400).send("tx not successful");
    if (tx.memo_type && tx.memo_type !== "none") return res.status(400).send("memos not allowed");
    if (!isRecent(tx.created_at, 30)) return res.status(400).send("tx too old");

    // 2) exactly one 1 KALE payment from address -> TREASURY
    const opsPage = await getJson(`${HORIZON}/transactions/${txHash}/operations?limit=200&order=asc`);
    const ops = opsPage?._embedded?.records || [];
    const validPays = ops.filter(o =>
      o.type === "payment" &&
      o.to === TREASURY &&
      (o.asset_type === "credit_alphanum4" || o.asset_type === "credit_alphanum12") &&
      o.asset_code === KALE_CODE &&
      o.asset_issuer === KALE_ISSUER &&
      o.amount === "1.0000000" &&
      o.from === address
    );
    if (validPays.length !== 1) {
      return res.status(400).send("no valid KALE payment op to treasury from address");
    }

    // 3) insert (unique tx_hash prevents replays)
    await pool.query(
      `INSERT INTO scores (address, score, tx_hash, paid_at, ip, ua)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [address, normScore, txHash, tx.created_at, req.ip || null, req.get("user-agent") || null]
    );

    // 4) auto-trim to best 100
    await pool.query(`
      DELETE FROM scores
      WHERE id NOT IN (
        SELECT id FROM scores
        ORDER BY score DESC, created_at ASC, id ASC
        LIMIT 100
      )
    `);

    return res.json({ ok: true, top10: await topN(10) });
  } catch (e) {
    console.error(e);
    return res.status(500).send(e.message || "server error");
  }
});

// GET /leaderboard?limit=100
app.get("/leaderboard", async (req, res) => {
  const lim = Math.max(1, Math.min(Number(req.query.limit) || 50, 100));
  res.json({ top: await topN(lim) });
});

// -------- Start server --------
const PORT = process.env.PORT || 8787; // Render injects PORT
app.listen(PORT, () => console.log(`KGR leaderboard API on :${PORT}`));
