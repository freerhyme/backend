
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");
const { Pool } = require("pg");

const app = express();

app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: "20kb" }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) {
  throw new Error("ADMIN_API_KEY must be at least 32 characters");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// ----------------------------------------------------
// DATABASE INITIALIZATION
// ----------------------------------------------------

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id UUID PRIMARY KEY,
      installation_id TEXT UNIQUE NOT NULL,
      manufacturer TEXT,
      model TEXT,
      serial_last4 TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACTIVE', 'BLOCKED')),
      device_token_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id UUID PRIMARY KEY,
      device_id UUID NOT NULL REFERENCES devices(id),
      request_id TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      currency TEXT NOT NULL,
      protocol TEXT NOT NULL,
      card_brand TEXT NOT NULL,
      card_last4 TEXT NOT NULL,
      status TEXT NOT NULL,
      response_code TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (device_id, request_id)
    )
  `);

  console.log("Database initialized");
}

// ----------------------------------------------------
// HELPERS
// ----------------------------------------------------

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const left = Buffer.from(a);
  const right = Buffer.from(b);

  if (left.length !== right.length) return false;

  return crypto.timingSafeEqual(left, right);
}

function generateDeviceToken() {
  return crypto.randomBytes(32).toString("hex");
}

function publicDevice(device) {
  return {
    id: device.id,
    manufacturer: device.manufacturer,
    model: device.model,
    serialLast4: device.serial_last4,
    status: device.status,
    createdAt: device.created_at,
  };
}

function formatTransaction(row) {
  return {
    txnId: `SIM-${row.id}`,
    amount: Number(row.amount).toFixed(2),
    currency: row.currency,
    protocol: row.protocol,
    cardBrand: row.card_brand,
    cardLast4: row.card_last4,
    status: row.status,
    responseCode: row.response_code,
    timestamp: row.created_at,
    simulation: true,
  };
}

// ----------------------------------------------------
// ADMIN AUTHENTICATION
// ----------------------------------------------------

function requireAdmin(req, res, next) {
  const key = req.get("x-admin-key");

  if (!safeEqual(key, ADMIN_API_KEY)) {
    return res.status(401).json({
      ok: false,
      error: "Unauthorized administrator",
    });
  }

  next();
}

// ----------------------------------------------------
// DEVICE AUTHENTICATION
// ----------------------------------------------------

async function requireActiveDevice(req, res, next) {
  try {
    const token = req.get("x-device-token");

    if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(401).json({
        ok: false,
        error: "Device authentication required",
      });
    }

    const tokenHash = hashToken(token);

    const result = await pool.query(
      `
      SELECT *
      FROM devices
      WHERE device_token_hash = $1
      LIMIT 1
      `,
      [tokenHash]
    );

    const device = result.rows[0];

    if (!device) {
      return res.status(401).json({
        ok: false,
        error: "Unknown device",
      });
    }

    if (device.status !== "ACTIVE") {
      return res.status(403).json({
        ok: false,
        error: "Device is not activated",
        deviceStatus: device.status,
      });
    }

    req.device = device;
    next();
  } catch (error) {
    next(error);
  }
}

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/healthz", async (req, res, next) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "SWIFT POS Simulator API",
      mode: "SIMULATION",
      database: "connected",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------
// REGISTER DEVICE
// ----------------------------------------------------

app.post("/devices/register", async (req, res, next) => {
  try {
    const {
      installationId,
      manufacturer,
      model,
      serialLast4,
    } = req.body || {};

    if (
      typeof installationId !== "string" ||
      !/^[a-zA-Z0-9_-]{16,128}$/.test(installationId)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid installation ID",
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM devices
      WHERE installation_id = $1
      `,
      [installationId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        ok: false,
        error: "Device already registered",
        code: "DEVICE_ALREADY_REGISTERED",
      });
    }

    const token = generateDeviceToken();
    const id = crypto.randomUUID();

    const result = await pool.query(
      `
      INSERT INTO devices (
        id,
        installation_id,
        manufacturer,
        model,
        serial_last4,
        status,
        device_token_hash
      )
      VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)
      RETURNING *
      `,
      [
        id,
        installationId,
        String(manufacturer || "").slice(0, 100),
        String(model || "").slice(0, 100),
        String(serialLast4 || "").slice(0, 4),
        hashToken(token),
      ]
    );

    res.status(201).json({
      ok: true,
      message: "Device registration submitted",
      device: publicDevice(result.rows[0]),
      deviceToken: token,
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        ok: false,
        error: "Device already registered",
      });
    }

    next(error);
  }
});

// ----------------------------------------------------
// DEVICE STATUS
// ----------------------------------------------------

app.get("/devices/status", async (req, res, next) => {
  try {
    const token = req.get("x-device-token");

    if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(401).json({
        ok: false,
        error: "Device token required",
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM devices
      WHERE device_token_hash = $1
      LIMIT 1
      `,
      [hashToken(token)]
    );

    const device = result.rows[0];

    if (!device) {
      return res.status(404).json({
        ok: false,
        error: "Device not registered",
      });
    }

    res.json({
      ok: true,
      device: publicDevice(device),
    });
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------
// ADMIN: LIST DEVICES
// ----------------------------------------------------

app.get(
  "/admin/devices",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          manufacturer,
          model,
          serial_last4,
          status,
          created_at,
          updated_at
        FROM devices
        ORDER BY created_at DESC
      `);

      res.json({
        ok: true,
        devices: result.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ----------------------------------------------------
// ADMIN: APPROVE DEVICE
// ----------------------------------------------------

app.post(
  "/admin/devices/:id/approve",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `
        UPDATE devices
        SET status = 'ACTIVE',
            updated_at = NOW()
        WHERE id = $1
          AND status = 'PENDING'
        RETURNING *
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          error: "Pending device not found",
        });
      }

      res.json({
        ok: true,
        message: "Device activated",
        device: publicDevice(result.rows[0]),
      });
    } catch (error) {
      next(error);
    }
  }
);

// ----------------------------------------------------
// ADMIN: BLOCK DEVICE
// ----------------------------------------------------

app.post(
  "/admin/devices/:id/block",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `
        UPDATE devices
        SET status = 'BLOCKED',
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          error: "Device not found",
        });
      }

      res.json({
        ok: true,
        message: "Device blocked",
        device: publicDevice(result.rows[0]),
      });
    } catch (error) {
      next(error);
    }
  }
);

// ----------------------------------------------------
// PROCESS SIMULATED PAYMENT
// ----------------------------------------------------

app.post(
  "/process-payment",
  requireActiveDevice,
  async (req, res, next) => {
    try {
      const {
        amount,
        currency,
        protocol,
        testCardId,
      } = req.body || {};

      const requestId = req.get("x-request-id");

      if (
        !requestId ||
        !/^[a-zA-Z0-9_-]{8,128}$/.test(requestId)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Valid request ID required",
        });
      }

      const value = Number(amount);

      if (
        !Number.isFinite(value) ||
        value <= 0 ||
        value > 1000000 ||
        !["USD", "EUR"].includes(currency) ||
        !["visa", "mastercard"].includes(testCardId) ||
        typeof protocol !== "string" ||
        protocol.length > 100
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid test payment details",
        });
      }

      const normalizedAmount = value.toFixed(2);
      const approved = testCardId === "visa";

      const transactionId = crypto.randomUUID();

      const result = await pool.query(
        `
        INSERT INTO transactions (
          id,
          device_id,
          request_id,
          amount,
          currency,
          protocol,
          card_brand,
          card_last4,
          status,
          response_code
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )
        ON CONFLICT (device_id, request_id)
        DO NOTHING
        RETURNING *
        `,
        [
          transactionId,
          req.device.id,
          requestId,
          normalizedAmount,
          currency,
          protocol,
          approved ? "VISA" : "MASTERCARD",
          approved ? "1111" : "4444",
          approved ? "APPROVED" : "DECLINED",
          approved ? "00" : "05",
        ]
      );

      let transaction = result.rows[0];

      if (!transaction) {
        const existing = await pool.query(
          `
          SELECT *
          FROM transactions
          WHERE device_id = $1
            AND request_id = $2
          `,
          [req.device.id, requestId]
        );

        transaction = existing.rows[0];

        if (!transaction) {
          throw new Error("Could not retrieve existing transaction");
        }

        if (
          Number(transaction.amount).toFixed(2) !==
            normalizedAmount ||
          transaction.currency !== currency ||
          transaction.protocol !== protocol ||
          transaction.card_brand !==
            (approved ? "VISA" : "MASTERCARD")
        ) {
          return res.status(409).json({
            ok: false,
            error: "Request ID reused with different payment details",
          });
        }
      }

      res.json({
        ok: true,
        transaction: formatTransaction(transaction),
        message:
          "Simulated response only. No funds transferred.",
      });
    } catch (error) {
      next(error);
    }
  }
);

// ----------------------------------------------------
// DEVICE TRANSACTION HISTORY
// ----------------------------------------------------

app.get(
  "/transactions",
  requireActiveDevice,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM transactions
        WHERE device_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        `,
        [req.device.id]
      );

      res.json({
        ok: true,
        transactions: result.rows.map(formatTransaction),
      });
    } catch (error) {
      next(error);
    }
  }
);

// ----------------------------------------------------
// ERROR HANDLING
// ----------------------------------------------------

app.use((error, req, res, next) => {
  console.error("API error:", error.message);

  if (error instanceof SyntaxError && error.status === 400) {
    return res.status(400).json({
      ok: false,
      error: "Invalid JSON",
    });
  }

  if (error.code === "22P02") {
    return res.status(400).json({
      ok: false,
      error: "Invalid identifier",
    });
  }

  res.status(500).json({
    ok: false,
    error: "Internal server error",
  });
});

// ----------------------------------------------------
// START SERVER
// ----------------------------------------------------

async function start() {
  await initializeDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SWIFT POS Simulator API running on ${PORT}`);
  });
}

start().catch((error) => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
