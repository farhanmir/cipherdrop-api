const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { encryptSecret, decryptSecret, hashPin } = require('./utils/cryptoHelper');
const { apiLimiter } = require('./middleware/rateLimiter');

const app = express();
app.use(cors());
app.use(express.json());

// Apply rate limiting to all /api routes
app.use('/api/', apiLimiter);

const secretsDb = new Map();

// POST: Create a secret (Now with optional PIN)
app.post('/api/secrets', (req, res) => {
  const { secret, ttlMinutes = 60, pin } = req.body;

  if (!secret || typeof ttlMinutes !== 'number' || ttlMinutes <= 0) {
    return res.status(400).json({ error: 'Valid secret and ttlMinutes required' });
  }

  const id = crypto.randomUUID();
  const { iv, encryptedSecret } = encryptSecret(secret);
  const hashedPin = hashPin(pin); // Will be null if no pin provided
  const expiresAt = Date.now() + ttlMinutes * 60 * 1000;

  secretsDb.set(id, { encryptedSecret, iv, expiresAt, hashedPin });

  res.status(201).json({ id, requiresPin: !!hashedPin });
});

// GET: Retrieve and burn
app.post('/api/secrets/:id/read', (req, res) => {
  // We use POST here instead of GET because the user might need to send a PIN in the body
  const { id } = req.params;
  const { pin } = req.body;
  
  const data = secretsDb.get(id);

  if (!data || Date.now() > data.expiresAt) {
    if (data) secretsDb.delete(id);
    return res.status(404).json({ error: 'Secret not found, expired, or already burned.' });
  }

  // Validate PIN if the secret requires one
  if (data.hashedPin && data.hashedPin !== hashPin(pin)) {
    // Note: We DO NOT burn the secret on a wrong PIN guess, just reject it.
    return res.status(401).json({ error: 'Incorrect PIN.' });
  }

  // Burn on read
  secretsDb.delete(id);

  const decryptedText = decryptSecret(data.encryptedSecret, data.iv);
  res.json({ secret: decryptedText });
});

// Garbage Collection
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of secretsDb.entries()) {
    if (now > data.expiresAt) {
      secretsDb.delete(id);
    }
  }
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CipherDrop Enterprise Vault running on port ${PORT}`);
});
