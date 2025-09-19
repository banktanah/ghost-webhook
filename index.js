import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// SECRET dari Ghost Webhook
const GHOST_WEBHOOK_SECRET = process.env.GHOST_SECRET || "mysecret123";

// Middleware verifikasi signature dari Ghost
function verifyGhostSignature(req, res, next) {
  const signature = req.get("X-Ghost-Signature");
  if (!signature) return res.status(401).send("Missing signature");

  const body = JSON.stringify(req.body);
  const expected = crypto
    .createHmac("sha256", GHOST_WEBHOOK_SECRET)
    .update(body, "utf8")
    .digest("hex");

  if (expected !== signature) {
    return res.status(401).send("Invalid signature");
  }
  next();
}

// Endpoint webhook Ghost
app.post("/ghost-webhook", verifyGhostSignature, (req, res) => {
  const event = req.body;

  if (event?.post?.current && event.post.current.status === "published") {
    console.log("✅ Post published!");
    console.log("Title:", event.post.current.title);
    console.log("Slug:", event.post.current.slug);
    console.log("URL:", event.post.current.url);

    // TODO: Bisa tambahin notifikasi ke Telegram/Slack/DB di sini
  }

  res.status(200).send("OK");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Ghost webhook listener running on port ${PORT}`);
});
