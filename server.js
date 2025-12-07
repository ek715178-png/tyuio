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
const OTP_TTL = 300;

const otpStore = new Map();

// 🔥 Brevo SMTP Transport
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

function genOtp() {
  return '' + Math.floor(100000 + Math.random() * 900000);
}

function hashOtp(otp, salt) {
  return crypto.createHmac('sha256', salt).update(otp).digest('hex');
}

app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = genOtp();

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashOtp(otp, salt);

  otpStore.set(email, { hash, salt, expiresAt: Date.now() + OTP_TTL * 1000 });

  console.log("Sending OTP to:", email);

  try {
    await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: email,
      subject: "Your OTP Code",
      html: `<h2>Your OTP: <b>${otp}</b></h2>`,
    });

    res.json({ ok: true, message: "OTP sent!" });
  } catch (err) {
    console.error("Email sending failed:", err);
    res.status(500).json({ ok: false, message: "Error sending email" });
  }
});

app.post('/verify-otp', (req, res) => {
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

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
