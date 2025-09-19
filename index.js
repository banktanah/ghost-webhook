import express from "express";
import crypto from "crypto";

const app = express();

// simpan raw body buat verifikasi
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

const GHOST_WEBHOOK_SECRET = process.env.GHOST_SECRET || "mysecret123";

function verifyGhostSignature(req, res, next) {
  const signature = req.get("X-Ghost-Signature");
  if (!signature) return res.status(401).send("Missing signature");

  // hapus prefix sha256= kalau ada
  const sig = signature.replace(/^sha256=/, "");

  const expected = crypto
    .createHmac("sha256", GHOST_WEBHOOK_SECRET)
    .update(req.rawBody, "utf8")
    .digest("hex");

  console.log("Expected:", expected);
  console.log("Received:", sig);

  if (expected !== sig) {
    return res.status(401).send("Invalid signature");
  }
  next();
}

app.post("/ghost-webhook", verifyGhostSignature, (req, res) => {
  console.log("Webhook verified ✅", req.body);
  res.status(200).send("OK");
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Webhook listener running on port 3000");
});
