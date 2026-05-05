import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json({ limit: "64kb" }));

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const HIT_AI_APP_SECRET = process.env.HIT_AI_APP_SECRET;
const PORT = process.env.PORT || 3000;

const FREE_MONTHLY_LIMIT = 50;
const BASIC_MONTHLY_LIMIT = 500;
const PREMIUM_MONTHLY_LIMIT = 1200;

// Anti-fraud guardrails. These are intentionally conservative to avoid blocking normal users.
const FREE_MAX_USER_IDS_PER_IP_MONTH = 5;
const FREE_MAX_REQUESTS_PER_IP_MONTH = 160;
const USER_MAX_REQUESTS_PER_MINUTE = 8;


if (!OPENAI_API_KEY) {
  console.warn("WARNING: OPENAI_API_KEY is missing.");
}

if (!DATABASE_URL) {
  console.warn("WARNING: DATABASE_URL is missing. Quotas cannot be secured without a database.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
    })
  : null;

function currentMonthKey() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function currentMinuteKey() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const day = String(now.getUTCDate()).padStart(2, "0");
  const hour = String(now.getUTCHours()).padStart(2, "0");
  const minute = String(now.getUTCMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

function cleanUserId(userId) {
  if (typeof userId !== "string") return null;
  const trimmed = userId.trim();
  if (trimmed.length < 8 || trimmed.length > 120) return null;
  return trimmed;
}

function cleanQuestion(question) {
  if (typeof question !== "string") return null;
  const trimmed = question.trim();
  if (trimmed.length < 1 || trimmed.length > 4000) return null;
  return trimmed;
}

function normalizePlan(plan) {
  if (plan === "premium") return "premium";
  if (plan === "basic") return "basic";
  return "free";
}

function limitForPlan(plan) {
  switch (plan) {
    case "premium":
      return PREMIUM_MONTHLY_LIMIT;
    case "basic":
      return BASIC_MONTHLY_LIMIT;
    default:
      return FREE_MONTHLY_LIMIT;
  }
}

function requireAppSecret(req, res) {
  if (!HIT_AI_APP_SECRET) return true;

  const receivedSecret = req.header("x-hit-ai-secret");
  if (receivedSecret !== HIT_AI_APP_SECRET) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }

  return true;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function hashValue(value) {
  const secretSalt = HIT_AI_APP_SECRET || "hit-ai-local-salt";
  return crypto.createHash("sha256").update(`${secretSalt}:${value}`).digest("hex");
}

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}


async function initDatabase() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS hit_ai_users (
      user_id TEXT PRIMARY KEY,
      plan TEXT NOT NULL DEFAULT 'free',
      usage_month TEXT NOT NULL,
      used_count INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS hit_ai_user_rate_limits (
      user_id TEXT NOT NULL,
      minute_key TEXT NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, minute_key)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS hit_ai_ip_monthly_guard (
      ip_hash TEXT NOT NULL,
      usage_month TEXT NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      user_ids TEXT[] NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (ip_hash, usage_month)
    );
  `);
}

async function getOrCreateUser(userId) {
  const monthKey = currentMonthKey();

  const result = await pool.query(
    `
      INSERT INTO hit_ai_users (user_id, usage_month, used_count)
      VALUES ($1, $2, 0)
      ON CONFLICT (user_id) DO UPDATE
      SET updated_at = NOW()
      RETURNING user_id, plan, usage_month, used_count;
    `,
    [userId, monthKey]
  );

  const user = result.rows[0];

  if (user.usage_month !== monthKey) {
    const resetResult = await pool.query(
      `
        UPDATE hit_ai_users
        SET usage_month = $2,
            used_count = 0,
            updated_at = NOW()
        WHERE user_id = $1
        RETURNING user_id, plan, usage_month, used_count;
      `,
      [userId, monthKey]
    );

    return resetResult.rows[0];
  }

  return user;
}

async function incrementUsage(userId) {
  const result = await pool.query(
    `
      UPDATE hit_ai_users
      SET used_count = used_count + 1,
          updated_at = NOW()
      WHERE user_id = $1
      RETURNING user_id, plan, usage_month, used_count;
    `,
    [userId]
  );

  return result.rows[0];
}

async function checkUserBurstLimit(userId) {
  const minuteKey = currentMinuteKey();

  const result = await pool.query(
    `
      INSERT INTO hit_ai_user_rate_limits (user_id, minute_key, request_count)
      VALUES ($1, $2, 1)
      ON CONFLICT (user_id, minute_key) DO UPDATE
      SET request_count = hit_ai_user_rate_limits.request_count + 1,
          updated_at = NOW()
      RETURNING request_count;
    `,
    [userId, minuteKey]
  );

  const count = safeNumber(result.rows[0]?.request_count);
  return count <= USER_MAX_REQUESTS_PER_MINUTE;
}

async function checkFreeIpMonthlyGuard(req, userId, plan) {
  if (plan !== "free") {
    return { allowed: true };
  }

  const ipHash = hashValue(getClientIp(req));
  const monthKey = currentMonthKey();

  const result = await pool.query(
    `
      INSERT INTO hit_ai_ip_monthly_guard (ip_hash, usage_month, request_count, user_ids)
      VALUES ($1, $2, 1, ARRAY[$3]::TEXT[])
      ON CONFLICT (ip_hash, usage_month) DO UPDATE
      SET request_count = hit_ai_ip_monthly_guard.request_count + 1,
          user_ids = CASE
            WHEN NOT ($3 = ANY(hit_ai_ip_monthly_guard.user_ids))
            THEN array_append(hit_ai_ip_monthly_guard.user_ids, $3)
            ELSE hit_ai_ip_monthly_guard.user_ids
          END,
          updated_at = NOW()
      RETURNING request_count, cardinality(user_ids) AS user_count;
    `,
    [ipHash, monthKey, userId]
  );

  const requestCount = safeNumber(result.rows[0]?.request_count);
  const userCount = safeNumber(result.rows[0]?.user_count);

  if (userCount > FREE_MAX_USER_IDS_PER_IP_MONTH) {
    return {
      allowed: false,
      reason: "Too many free installations detected on this network this month. Please upgrade or try again later."
    };
  }

  if (requestCount > FREE_MAX_REQUESTS_PER_IP_MONTH) {
    return {
      allowed: false,
      reason: "Free network limit reached this month. Please upgrade to continue."
    };
  }

  return { allowed: true };
}

app.get("/health", async (req, res) => {
  res.json({
    ok: true,
    database: Boolean(pool),
    month: currentMonthKey(),
    antiFraud: true
  });
});

app.post("/ask", async (req, res) => {
  try {
    if (!requireAppSecret(req, res)) return;

    if (!pool) {
      return res.status(500).json({
        error: "Database not configured",
        message: "DATABASE_URL is required to secure the free quota."
      });
    }

    const userId = cleanUserId(req.body.userId);
    const question = cleanQuestion(req.body.question);
    const mode = req.body.mode === "step" ? "step" : "short";

    if (!userId) {
      return res.status(400).json({ error: "Missing or invalid userId" });
    }

    if (!question) {
      return res.status(400).json({ error: "Missing or invalid question" });
    }

    const userBefore = await getOrCreateUser(userId);
    const plan = normalizePlan(userBefore.plan);
    const monthlyLimit = limitForPlan(plan);

    if (userBefore.used_count >= monthlyLimit) {
      return res.status(402).json({
        error: "Monthly limit reached",
        plan,
        used: userBefore.used_count,
        limit: monthlyLimit,
        remaining: 0
      });
    }

    const burstAllowed = await checkUserBurstLimit(userId);
    if (!burstAllowed) {
      return res.status(429).json({
        error: "Too many requests. Please wait a moment before asking again.",
        plan,
        used: userBefore.used_count,
        limit: monthlyLimit,
        remaining: Math.max(monthlyLimit - userBefore.used_count, 0)
      });
    }

    const ipGuard = await checkFreeIpMonthlyGuard(req, userId, plan);
    if (!ipGuard.allowed) {
      return res.status(429).json({
        error: ipGuard.reason,
        plan,
        used: userBefore.used_count,
        limit: monthlyLimit,
        remaining: Math.max(monthlyLimit - userBefore.used_count, 0)
      });
    }

    const systemPrompt =
      mode === "step"
        ? "You are Hit AI on Apple Watch. Answer in the user's language. Be clear, useful, and structured in short numbered steps. Keep it compact for a small screen, but do not omit essential information."
        : "You are Hit AI on Apple Watch. Answer in the user's language. Be direct, accurate, and concise. Prefer 2-5 short sentences or compact bullets when useful. Do not add filler.";

    const maxTokens = mode === "step" ? 520 : 220;

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: question }
        ],
        max_tokens: maxTokens,
        temperature: 0.3
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("OpenAI error:", data);
      return res.status(502).json({ error: "AI provider error" });
    }

    const answer = data.choices?.[0]?.message?.content || "No answer";
    const userAfter = await incrementUsage(userId);

    res.json({
      answer,
      plan,
      used: userAfter.used_count,
      limit: monthlyLimit,
      remaining: Math.max(monthlyLimit - userAfter.used_count, 0),
      month: userAfter.usage_month
    });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/subscription/update", async (req, res) => {
  try {
    if (!requireAppSecret(req, res)) return;

    if (!pool) {
      return res.status(500).json({ error: "Database not configured" });
    }

    const userId = cleanUserId(req.body.userId);
    const plan = normalizePlan(req.body.plan);

    if (!userId) {
      return res.status(400).json({ error: "Missing or invalid userId" });
    }

    const monthKey = currentMonthKey();

    const result = await pool.query(
      `
        INSERT INTO hit_ai_users (user_id, plan, usage_month, used_count)
        VALUES ($1, $2, $3, 0)
        ON CONFLICT (user_id) DO UPDATE
        SET plan = $2,
            updated_at = NOW()
        RETURNING user_id, plan, usage_month, used_count;
      `,
      [userId, plan, monthKey]
    );

    const user = result.rows[0];
    const limit = limitForPlan(user.plan);

    res.json({
      ok: true,
      plan: user.plan,
      used: user.used_count,
      limit,
      remaining: Math.max(limit - user.used_count, 0),
      month: user.usage_month
    });
  } catch (error) {
    console.error("Subscription update error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
