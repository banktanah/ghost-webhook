const crypto = require("crypto");

const secret = "mysecret123"; // sama persis dengan yang di Ghost
const payload = JSON.stringify({
  event: "post.updated",
  data: { id: 123 },
});

// Generate hash
const hash = crypto
  .createHmac("sha256", secret)
  .update(payload, "utf8")
  .digest("hex");

const header = `sha256=${hash}, t=${Date.now()}`;

console.log("Payload:", payload);
console.log("X-Ghost-Signature:", header);
