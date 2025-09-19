const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// pakai secret yang sama persis dengan yang diisi di Ghost Webhook UI
const GHOST_WEBHOOK_SECRET = process.env.GHOST_WEBHOOK_SECRET || "mysecret123";

// simpan raw body sebelum diparse
app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf; // simpan raw buffer, bukan hasil parse
    },
  })
);

function verifyGhostSignature(req, res, next) {
  const signatureHeader = req.get("X-Ghost-Signature");
  if (!signatureHeader) {
    return res.status(401).send("Missing signature");
  }

  // Parse header: sha256=<hash>, t=<timestamp>
  const parts = signatureHeader.split(",");
  const sigObj = {};
  for (const part of parts) {
    const [k, v] = part.split("=");
    sigObj[k.trim()] = v.trim();
  }

  const receivedHash = sigObj["sha256"];
  const ts = sigObj["t"];
  if (!receivedHash || !ts) {
    return res.status(401).send("Invalid signature format");
  }

  // Catatan: harus pakai raw body + timestamp
  const expectedHash = crypto
    .createHmac("sha256", GHOST_WEBHOOK_SECRET)
    .update(req.rawBody.toString("utf8") + ts)   // 🔑 tambahkan ts
    .digest("hex");

  console.log("Expected:", expectedHash);
  console.log("Received:", receivedHash);
  console.log("Timestamp:", ts);

  const expectedBuffer = Buffer.from(expectedHash, "hex");
  const receivedBuffer = Buffer.from(receivedHash, "hex");

  if (
    expectedBuffer.length !== receivedBuffer.length ||
    !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
  ) {
    return res.status(401).send("Invalid signature");
  }

  next();
}

// Endpoint webhook
app.post("/ghost-webhook", verifyGhostSignature, (req, res) => {
  console.log("✅ Webhook received:", req.body);
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`🚀 Webhook server running at http://0.0.0.0:${PORT}`);
});
