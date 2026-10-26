
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

const ENFORCE_KEY_AUTH =
  process.env.ENFORCE_KEY_AUTH === "true";

const CHALLENGE_TTL_SECONDS = 120;
const SESSION_TTL_SECONDS = 900;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) {
  throw new Error(
    "ADMIN_API_KEY must be at least 32 characters"
  );
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// ====================================================
// DATABASE INITIALIZATION
// ====================================================

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

  // Preserve existing device records and approved keys.
  await pool.query(`
    ALTER TABLE devices
      ADD COLUMN IF NOT EXISTS public_key TEXT,
      ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT,
      ADD COLUMN IF NOT EXISTS pending_public_key TEXT,
      ADD COLUMN IF NOT EXISTS pending_key_fingerprint TEXT
  `);

  // One-time authentication challenges.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_auth_challenges (
      id UUID PRIMARY KEY,
      device_id UUID NOT NULL REFERENCES devices(id),
      nonce_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Short-lived authenticated sessions.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_auth_sessions (
      token_hash TEXT PRIMARY KEY,
      device_id UUID NOT NULL REFERENCES devices(id),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      idx_device_auth_challenges_device
    ON device_auth_challenges(device_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      idx_device_auth_sessions_device
    ON device_auth_sessions(device_id)
  `);

  console.log("Database initialized");
}

// ====================================================
// CRYPTOGRAPHIC HELPERS
// ====================================================

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string"
  ) {
    return false;
  }

  const left = Buffer.from(a);
  const right = Buffer.from(b);

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function validToken(token) {
  return (
    typeof token === "string" &&
    /^[a-f0-9]{64}$/i.test(token)
  );
}

function generateDeviceToken() {
  return crypto.randomBytes(32).toString("hex");
}

function fingerprintPublicKey(der) {
  return crypto
    .createHash("sha256")
    .update(der)
    .digest("hex");
}

function decodeBase64(value, maxLength = 256) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error("Invalid Base64 encoding");
  }

  const decoded = Buffer.from(value, "base64");

  if (decoded.toString("base64") !== value) {
    throw new Error("Invalid Base64 encoding");
  }

  return decoded;
}

function parseP256PublicKey(encoded) {
  const der = decodeBase64(encoded);

  if (der.length < 70 || der.length > 150) {
    throw new Error("Invalid public key length");
  }

  const key = crypto.createPublicKey({
    key: der,
    format: "der",
    type: "spki",
  });

  if (
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !==
      "prime256v1"
  ) {
    throw new Error("Expected P-256 public key");
  }

  return { key, der };
}

function parseSignature(encoded) {
  const signature = decodeBase64(encoded);

  if (
    signature.length < 64 ||
    signature.length > 80
  ) {
    throw new Error("Invalid signature length");
  }

  return signature;
}

// ====================================================
// RESPONSE HELPERS
// ====================================================

function publicDevice(device) {
  return {
    id: device.id,
    manufacturer: device.manufacturer,
    model: device.model,
    serialLast4: device.serial_last4,
    status: device.status,
    keyFingerprint:
      device.public_key_fingerprint || null,
    pendingKeyFingerprint:
      device.pending_key_fingerprint || null,
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

async function findDeviceByToken(token) {
  if (!validToken(token)) {
    return null;
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

  return result.rows[0] || null;
}

// ====================================================
// ADMIN AUTHENTICATION
// ====================================================

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

// ====================================================
// DEVICE AUTHENTICATION
// ====================================================

async function requireActiveDevice(req, res, next) {
  try {
    const sessionToken =
      req.get("x-device-session");

    // Prefer cryptographically authenticated sessions.
    if (sessionToken) {
      if (!validToken(sessionToken)) {
        return res.status(401).json({
          ok: false,
          error: "Invalid device session",
        });
      }

      const result = await pool.query(
        `
        SELECT d.*
        FROM device_auth_sessions s
        JOIN devices d
          ON d.id = s.device_id
        WHERE s.token_hash = $1
          AND s.expires_at > NOW()
          AND d.status = 'ACTIVE'
          AND d.public_key IS NOT NULL
        LIMIT 1
        `,
        [hashToken(sessionToken)]
      );

      if (!result.rows.length) {
        return res.status(401).json({
          ok: false,
          error: "Device session expired or revoked",
          code: "SESSION_EXPIRED",
        });
      }

      req.device = result.rows[0];
      return next();
    }

    // Legacy authentication remains available
    // during the migration.
    const token = req.get("x-device-token");

    if (!validToken(token)) {
      return res.status(401).json({
        ok: false,
        error: "Device authentication required",
      });
    }

    const device = await findDeviceByToken(token);

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

    // Once enforcement is enabled, enrolled devices
    // must authenticate using their approved key.
    if (ENFORCE_KEY_AUTH && device.public_key) {
      return res.status(401).json({
        ok: false,
        code: "KEY_AUTH_REQUIRED",
        error:
          "Cryptographic device session required",
      });
    }

    req.device = device;
    next();
  } catch (error) {
    next(error);
  }
}

// ====================================================
// HEALTH CHECK
// ====================================================

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

// ====================================================
// REGISTER DEVICE
// ====================================================

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
      !/^[a-zA-Z0-9_-]{16,128}$/.test(
        installationId
      )
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
      VALUES (
        $1, $2, $3, $4, $5, 'PENDING', $6
      )
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

// ====================================================
// DEVICE STATUS
// ====================================================

app.get("/devices/status", async (req, res, next) => {
  try {
    const token = req.get("x-device-token");

    if (!validToken(token)) {
      return res.status(401).json({
        ok: false,
        error: "Device token required",
      });
    }

    const device = await findDeviceByToken(token);

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

// ====================================================
// KEY ENROLLMENT
// ====================================================

app.post(
  "/devices/key-enrollment",
  async (req, res, next) => {
    try {
      const token = req.get("x-device-token");

      if (!validToken(token)) {
        return res.status(401).json({
          ok: false,
          error: "Device token required",
        });
      }

      const device = await findDeviceByToken(token);

      if (!device) {
        return res.status(401).json({
          ok: false,
          error: "Unknown device",
        });
      }

      if (device.status !== "ACTIVE") {
        return res.status(403).json({
          ok: false,
          error: "Device not active",
        });
      }

      if (device.public_key) {
        return res.status(409).json({
          ok: false,
          error:
            "A public key is already approved. " +
            "Administrator-controlled rotation required.",
        });
      }

      const { publicKey, signature } =
        req.body || {};

      let parsedKey;
      let signatureBytes;

      try {
        parsedKey = parseP256PublicKey(publicKey);
        signatureBytes = parseSignature(signature);
      } catch (error) {
        return res.status(400).json({
          ok: false,
          error: error.message,
        });
      }

      const message =
        `SWIFT_POS_KEY_ENROLL_V1\n` +
        `${device.id}\n` +
        `${publicKey}`;

      const verified = crypto.verify(
        "sha256",
        Buffer.from(message, "utf8"),
        parsedKey.key,
        signatureBytes
      );

      if (!verified) {
        return res.status(403).json({
          ok: false,
          error: "Signature verification failed",
        });
      }

      const fingerprint = fingerprintPublicKey(
        parsedKey.der
      );

      const result = await pool.query(
        `
        UPDATE devices
        SET pending_public_key = $1,
            pending_key_fingerprint = $2,
            updated_at = NOW()
        WHERE id = $3
          AND status = 'ACTIVE'
          AND public_key IS NULL
          AND (
            pending_public_key IS NULL
            OR pending_key_fingerprint = $2
          )
        RETURNING id
        `,
        [publicKey, fingerprint, device.id]
      );

      if (!result.rows.length) {
        return res.status(409).json({
          ok: false,
          error:
            "A different key enrollment is pending",
        });
      }

      res.json({
        ok: true,
        status: "PENDING_KEY_APPROVAL",
        fingerprint,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ====================================================
// CHALLENGE-RESPONSE AUTHENTICATION
// ====================================================

// STEP 1: Generate a one-time challenge.

app.post(
  "/devices/auth/challenge",
  async (req, res, next) => {
    try {
      const token = req.get("x-device-token");

      if (!validToken(token)) {
        return res.status(401).json({
          ok: false,
          error: "Device token required",
        });
      }

      const device = await findDeviceByToken(token);

      if (!device) {
        return res.status(401).json({
          ok: false,
          error: "Unknown device",
        });
      }

      if (
        device.status !== "ACTIVE" ||
        !device.public_key
      ) {
        return res.status(403).json({
          ok: false,
          error: "Approved device key required",
        });
      }

      const challengeId = crypto.randomUUID();

      const nonce = crypto
        .randomBytes(32)
        .toString("base64");

      const expiresAt = new Date(
        Date.now() + CHALLENGE_TTL_SECONDS * 1000
      );

      await pool.query(
        `
        INSERT INTO device_auth_challenges (
          id,
          device_id,
          nonce_hash,
          expires_at
        )
        VALUES ($1, $2, $3, $4)
        `,
        [
          challengeId,
          device.id,
          hashToken(nonce),
          expiresAt,
        ]
      );

      res.json({
        ok: true,
        deviceId: device.id,
        challengeId,
        nonce,
        expiresAt: expiresAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  }
);

// STEP 2: Verify the signed challenge.
//
// Android must sign exactly:
//
// SWIFT_POS_AUTH_V1
// <deviceId>
// <challengeId>
// <nonce>
//
// Lines are separated by "\n".
// There is no trailing newline.
//
// Signature algorithm: SHA256withECDSA.
// Signature encoding: Base64 DER.

app.post(
  "/devices/auth/verify",
  async (req, res, next) => {
    const token = req.get("x-device-token");

    const {
      challengeId,
      nonce,
      signature,
    } = req.body || {};

    if (
      !validToken(token) ||
      typeof challengeId !== "string" ||
      !/^[0-9a-f-]{36}$/i.test(challengeId) ||
      typeof nonce !== "string" ||
      nonce.length > 128
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid authentication request",
      });
    }

    let signatureBytes;

    try {
      signatureBytes = parseSignature(signature);
    } catch (error) {
      return res.status(400).json({
        ok: false,
        error: "Invalid signature",
      });
    }

    let client;

    try {
      client = await pool.connect();

      await client.query("BEGIN");

      // Lock the challenge row so concurrent requests
      // cannot consume it more than once.
      const result = await client.query(
        `
        SELECT
          c.*,
          d.status,
          d.public_key,
          d.device_token_hash
        FROM device_auth_challenges c
        JOIN devices d
          ON d.id = c.device_id
        WHERE c.id = $1
        FOR UPDATE OF c
        `,
        [challengeId]
      );

      const challenge = result.rows[0];

      if (
        !challenge ||
        challenge.consumed_at ||
        new Date(
          challenge.expires_at
        ).getTime() <= Date.now() ||
        challenge.status !== "ACTIVE" ||
        !challenge.public_key ||
        !safeEqual(
          challenge.device_token_hash,
          hashToken(token)
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(401).json({
          ok: false,
          error: "Challenge invalid or expired",
        });
      }

      if (
        !safeEqual(
          hashToken(nonce),
          challenge.nonce_hash
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(401).json({
          ok: false,
          error: "Challenge mismatch",
        });
      }

      const message =
        `SWIFT_POS_AUTH_V1\n` +
        `${challenge.device_id}\n` +
        `${challengeId}\n` +
        `${nonce}`;

      const { key } = parseP256PublicKey(
        challenge.public_key
      );

      const verified = crypto.verify(
        "sha256",
        Buffer.from(message, "utf8"),
        key,
        signatureBytes
      );

      if (!verified) {
        await client.query("ROLLBACK");

        return res.status(401).json({
          ok: false,
          error: "Signature verification failed",
        });
      }

      // Consume the challenge.
      await client.query(
        `
        UPDATE device_auth_challenges
        SET consumed_at = NOW()
        WHERE id = $1
        `,
        [challengeId]
      );

      // Create a short-lived authenticated session.
      const sessionToken = crypto
        .randomBytes(32)
        .toString("hex");

      const expiresAt = new Date(
        Date.now() + SESSION_TTL_SECONDS * 1000
      );

      await client.query(
        `
        INSERT INTO device_auth_sessions (
          token_hash,
          device_id,
          expires_at
        )
        VALUES ($1, $2, $3)
        `,
        [
          hashToken(sessionToken),
          challenge.device_id,
          expiresAt,
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        sessionToken,
        expiresAt: expiresAt.toISOString(),
        expiresIn: SESSION_TTL_SECONDS,
      });
    } catch (error) {
      if (client) {
        try {
          await client.query("ROLLBACK");
        } catch (_) {}
      }

      next(error);
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);

// ====================================================
// ADMIN: LIST DEVICES
// ====================================================

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
          public_key_fingerprint,
          pending_key_fingerprint,
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

// ====================================================
// ADMIN: APPROVE DEVICE
// ====================================================

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

// ====================================================
// ADMIN: APPROVE PUBLIC KEY
// ====================================================

app.post(
  "/admin/devices/:id/approve-key",
  requireAdmin,
  async (req, res, next) => {
    try {
      const { fingerprint } = req.body || {};

      if (
        typeof fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/.test(fingerprint)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Full lowercase SHA-256 fingerprint required",
        });
      }

      const result = await pool.query(
        `
        UPDATE devices
        SET public_key = pending_public_key,
            public_key_fingerprint =
              pending_key_fingerprint,
            pending_public_key = NULL,
            pending_key_fingerprint = NULL,
            updated_at = NOW()
        WHERE id = $1
          AND status = 'ACTIVE'
          AND public_key IS NULL
          AND pending_public_key IS NOT NULL
          AND pending_key_fingerprint = $2
        RETURNING *
        `,
        [req.params.id, fingerprint]
      );

      if (!result.rows.length) {
        return res.status(409).json({
          ok: false,
          error: "No matching pending key",
        });
      }

      res.json({
        ok: true,
        message: "Device public key approved",
        device: publicDevice(result.rows[0]),
      });
    } catch (error) {
      next(error);
    }
  }
);

// ====================================================
// ADMIN: BLOCK DEVICE
// ====================================================

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

      // Revoke outstanding authenticated sessions.
      await pool.query(
        `
        DELETE FROM device_auth_sessions
        WHERE device_id = $1
        `,
        [req.params.id]
      );

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


 // ====================================================
 // ADMIN: REACTIVATE BLOCKED DEVICE
 // ====================================================

app.post(
  "/admin/devices/:id/reactivate",
  requireAdmin,
  async (req, res, next) => {
    const deviceId = req.params.id;

    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        deviceId
      )
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid device ID",
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const result = await client.query(
        `
        UPDATE devices
        SET status = 'ACTIVE',
            updated_at = NOW()
        WHERE id = $1
          AND status = 'BLOCKED'
          AND public_key IS NOT NULL
          AND public_key_fingerprint IS NOT NULL
        RETURNING *
        `,
        [deviceId]
      );

      if (!result.rows.length) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          error:
            "Device is not blocked or has no approved public key",
        });
      }

      // Remove any old sessions and challenges.
      // The reactivated device must sign a fresh
      // challenge before accessing protected APIs.
      await client.query(
        `
        DELETE FROM device_auth_sessions
        WHERE device_id = $1
        `,
        [deviceId]
      );

      await client.query(
        `
        DELETE FROM device_auth_challenges
        WHERE device_id = $1
        `,
        [deviceId]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        message: "Device reactivated successfully",
        device: publicDevice(result.rows[0]),
        requiresFreshAuthentication: true,
      });
    } catch (error) {
      if (client) {
        try {
          await client.query("ROLLBACK");
        } catch (_) {}
      }

      next(error);
    } finally {
      client?.release();
    }
  }
);

// ====================================================
// PROCESS SIMULATED PAYMENT
// ====================================================

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

      // SIMULATION ONLY.
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
          $1, $2, $3, $4, $5,
          $6, $7, $8, $9, $10
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
          throw new Error(
            "Could not retrieve existing transaction"
          );
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
            error:
              "Request ID reused with different payment details",
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

// ====================================================
// TRANSACTION HISTORY
// ====================================================

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
        transactions: result.rows.map(
          formatTransaction
        ),
      });
    } catch (error) {
      next(error);
    }
  }
);

// ====================================================
// ERROR HANDLING
// ====================================================

app.use((error, req, res, next) => {
  console.error("API error:", error.message);

  if (
    error instanceof SyntaxError &&
    error.status === 400
  ) {
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

// ====================================================
// START SERVER
// ====================================================

async function start() {
  await initializeDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `SWIFT POS Simulator API running on ${PORT}`
    );

    console.log(
      `Key authentication enforcement: ${
        ENFORCE_KEY_AUTH ? "ENABLED" : "DISABLED"
      }`
    );
  });
}

start().catch((error) => {
  console.error(
    "Startup failed:",
    error.message
  );

  process.exit(1);
});
