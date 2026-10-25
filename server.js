
const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");

require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "20kb" }));

app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    service: "SWIFT POS Simulator API",
    mode: "SIMULATION",
    timestamp: new Date().toISOString(),
  });
});

app.post("/process-payment", (req, res) => {
  const { amount, currency, protocol, testCardId } = req.body;

  const validCards = ["visa", "mastercard"];
  const value = Number(amount);

  if (
    !Number.isFinite(value) ||
    value <= 0 ||
    value > 1000000 ||
    !["USD", "EUR"].includes(currency) ||
    !validCards.includes(testCardId) ||
    typeof protocol !== "string" ||
    protocol.length > 100
  ) {
    return res.status(400).json({
      ok: false,
      error: "Invalid test payment details",
    });
  }

  const approved = testCardId === "visa";

  const transaction = {
    txnId: `SIM-${crypto.randomUUID()}`,
    amount: value.toFixed(2),
    currency,
    protocol,
    cardBrand: approved ? "VISA" : "MASTERCARD",
    cardLast4: approved ? "1111" : "4444",
    status: approved ? "APPROVED" : "DECLINED",
    responseCode: approved ? "00" : "05",
    timestamp: new Date().toISOString(),
    simulation: true,
  };

  res.json({
    ok: true,
    transaction,
    message: "Simulated response only. No funds transferred.",
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SWIFT POS simulator listening on ${PORT}`);
});
