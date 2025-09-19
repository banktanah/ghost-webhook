const crypto = require("crypto");
const express = require("express");
const bodyParser = require("body-parser");

const app = express();

// simpan raw body untuk verifikasi signature
app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

const GHOST_WEBHOOK_SECRET = process.env.GHOST_WEBHOOK_SECRET || "mysecret123";

function verifyGhostSignature(req, res, next) {
  const signatureHeader = req.get("X-Ghost-Signature");
  if (!signatureHeader) {
    return res.status(401).send("Missing signature");
  }

  // contoh header: "sha256=abcdef..., t=123456789"
  const sigParts = signatureHeader.split(",");
  const sigObj = {};
  for (const part of sigParts) {
    const [k, v] = part.split("=");
    sigObj[k.trim()] = v.trim();
  }

  const receivedHash = sigObj["sha256"];
  if (!receivedHash) {
    return res.status(401).send("Invalid signature format");
  }

  // hitung ulang HMAC dari raw body
  const expectedHash = crypto
    .createHmac("sha256", GHOST_WEBHOOK_SECRET)
    .update(req.rawBody, "utf8")
    .digest("hex");

  console.log("Expected:", expectedHash);
  console.log("Received:", receivedHash);

  // gunakan timingSafeEqual untuk mencegah timing attack
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

// contoh endpoint webhook
app.post("/ghost-webhook", verifyGhostSignature, (req, res) => {
  console.log("Webhook received:", req.body);
  res.sendStatus(200);
});

app.listen(3000, () => {
  console.log("Webhook server running on port 3000");
});
