require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

const PORT = process.env.PORT || 3000;

const OTP_TTL = 300;
const otpStore = new Map();

function genOtp() {
  return "" + Math.floor(100000 + Math.random() * 900000);
}

function hashOtp(otp, salt) {
  return crypto.createHmac("sha256", salt).update(otp).digest("hex");
}

// ========== SEND OTP ==========
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  const otp = genOtp();
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = hashOtp(otp, salt);

  otpStore.set(email, { hash, salt, expiresAt: Date.now() + OTP_TTL * 1000 });

  console.log("Sending OTP to:", email);

  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { name: "Raees OTP", email: process.env.FROM_EMAIL },
        to: [{ email }],
        subject: "Your OTP Code",
        htmlContent: `<h2>Your OTP: <b>${otp}</b></h2>`
      },
      {
        headers: {
          "Content-Type": "application/json",
          "api-key": process.env.BREVO_API_KEY,
        },
      }
    );

    res.json({ ok: true, message: "OTP sent!" });
  } catch (err) {
    console.error("Email sending failed:", err.response?.data || err);
    res.status(500).json({ ok: false, message: "Failed to send OTP" });
  }
});

// ========== VERIFY OTP ==========
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  const data = otpStore.get(email);
  if (!data) return res.status(400).json({ ok: false, message: "OTP not found" });

  if (Date.now() > data.expiresAt)
    return res.status(400).json({ ok: false, message: "OTP expired" });

  const hash = hashOtp(otp, data.salt);
  if (hash !== data.hash)
    return res.status(400).json({ ok: false, message: "Invalid OTP" });

  otpStore.delete(email);
  const token = jwt.sign({ email }, "SECRETJWTKEY");

  res.json({ ok: true, token });
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
