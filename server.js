require('dotenv').config();
const express = require('express');
const twilio = require('twilio');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// In-memory store for verification codes (use Redis/DB in production)
const codes = {};

// Send SMS verification code
app.post('/send-code', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number is required' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  codes[phone] = { code, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 min expiry

  try {
    await client.messages.create({
      body: `Your Microsoft verification code is: ${code}. It expires in 5 minutes.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone,
    });
    console.log(`Code sent to ${phone}`);
    res.json({ success: true, message: 'Verification code sent' });
  } catch (err) {
    console.error('Twilio error:', err.message);
    res.status(500).json({ error: 'Failed to send SMS', details: err.message });
  }
});

// Verify the code
app.post('/verify-code', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) return res.status(400).json({ error: 'Phone and code are required' });

  const entry = codes[phone];
  if (!entry) return res.status(400).json({ error: 'No code found for this number' });
  if (Date.now() > entry.expiresAt) {
    delete codes[phone];
    return res.status(400).json({ error: 'Code has expired' });
  }
  if (entry.code !== code) return res.status(400).json({ error: 'Invalid code' });

  delete codes[phone];
  res.json({ success: true, message: 'Phone verified successfully' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));