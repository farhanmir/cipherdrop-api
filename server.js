const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// In-memory Map to store data
const secretsDb = new Map();

// Generate a random 256-bit (32-byte) server key on startup
const SERVER_KEY = crypto.randomBytes(32);

// POST /api/secrets: Create a new burn-after-reading secret
app.post('/api/secrets', (req, res) => {
  const { secret, ttlMinutes } = req.body;

  if (!secret || typeof ttlMinutes !== 'number' || ttlMinutes <= 0) {
    return res.status(400).json({ error: 'Valid secret and ttlMinutes required' });
  }

  const id = crypto.randomUUID();
  const iv = crypto.randomBytes(16);
  
  // Encrypt the secret
  const cipher = crypto.createCipheriv('aes-256-ctr', SERVER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);

  const expiresAt = Date.now() + ttlMinutes * 60 * 1000;

  // Store the encrypted payload, IV, and expiration timestamp
  secretsDb.set(id, {
    encryptedSecret: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    expiresAt
  });

  res.status(201).json({ id });
});

// GET /api/secrets/:id: Read and burn a secret
app.get('/api/secrets/:id', (req, res) => {
  const { id } = req.params;
  const data = secretsDb.get(id);

  if (!data || Date.now() > data.expiresAt) {
    if (data) {
      secretsDb.delete(id); // Delete if found but expired
    }
    return res.status(404).json({ error: 'Secret not found or expired' });
  }

  // Burn on read: MUST immediately delete it from the Map before responding
  secretsDb.delete(id);

  // Decrypt the secret
  const decipher = crypto.createDecipheriv('aes-256-ctr', SERVER_KEY, Buffer.from(data.iv, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(data.encryptedSecret, 'hex')), 
    decipher.final()
  ]);

  res.json({ secret: decrypted.toString('utf8') });
});

// Garbage Collection: Automatically delete expired secrets every 60 seconds
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
  console.log(`Server listening on port ${PORT}`);
});
