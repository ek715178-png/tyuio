require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const OTP_TTL = 300; // 5 minutes

const otpStore = new Map();

// Gmail App Password + Render fix
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,     // smtp.gmail.com
  port: 587,                       // IMPORTANT: 587 for Render
  secure: false,                   // IMPORTANT
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false,     // Render TLS Fix
  }
});

// Generate OTP
function genOtp() {
  return '' + Math.floor(100000 + Math.random() * 900000);
}

// Hash OTP
function hashOtp(otp, salt) {
  return crypto.createHmac('sha256', salt).update(otp).digest('hex');
}

// ---------------------------------
// SEND OTP
// ---------------------------------
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ ok: false, message: "Email required" });

  const otp = genOtp();

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashOtp(otp, salt);

  otpStore.set(email, {
    hash,
    salt,
    expiresAt: Date.now() + OTP_TTL * 1000
  });

  try {
    console.log("Sending OTP to:", email);

    await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: email,
      subject: "Your OTP Code",
      html: `<h2>Your OTP: <b>${otp}</b></h2>`
    });

    return res.json({ ok: true, message: "OTP sent successfully" });

  } catch (err) {
    console.error("Email sending failed:", err);
    return res.status(500).json({ ok: false, message: "Failed to send OTP" });
  }
});

// ---------------------------------
// VERIFY OTP
// ---------------------------------
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  const data = otpStore.get(email);
  if (!data) {
    return res.status(400).json({ ok: false, message: "OTP not found" });
  }

  if (Date.now() > data.expiresAt) {
    return res.status(400).json({ ok: false, message: "OTP expired" });
  }

  const hash = hashOtp(otp, data.salt);

  if (hash !== data.hash) {
    return res.status(400).json({ ok: false, message: "Invalid OTP" });
  }

  otpStore.delete(email);

  const token = jwt.sign({ email }, "SECRET_JWT_KEY");

  return res.json({ ok: true, token });
});

// ---------------------------------
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
