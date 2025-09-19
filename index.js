import express from "express";
import crypto from "crypto";

const app = express();

// simpan raw body
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Buffer, bukan JSON
  }
}));

function verifyGhostSignature(req, res, next) {
  const signatureHeader = req.get("X-Ghost-Signature");
  if (!signatureHeader) {
    return res.status(401).send("Missing signature");
  }

  // signature Ghost bentuknya: sha256=<hash>, t=<timestamp>
  const [hashPart] = signatureHeader.split(",");
  const received = hashPart.split("=")[1];

  const expected = crypto
    .createHmac("sha256", process.env.GHOST_WEBHOOK_SECRET)
    .update(req.rawBody) // pakai raw body, bukan JSON.stringify
    .digest("hex");

  console.log("Expected:", expected);
  console.log("Received:", received);

  if (expected !== received) {
    return res.status(401).send("Invalid signature");
  }
  next();
}

app.post("/ghost-webhook", verifyGhostSignature, (req, res) => {
  console.log("Webhook verified & received:", req.body);
  res.sendStatus(200);
});
