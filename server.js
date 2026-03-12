require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Configuration
const DATA_DIR = path.join(__dirname, 'data');
const SECRETS_FILE = path.join(DATA_DIR, 'secrets.json');
const SERVER_KEY_HEX = process.env.CIPHERDROP_SERVER_KEY;

// Securely load the server key
if (!SERVER_KEY_HEX || SERVER_KEY_HEX.length !== 64) {
  console.error('CRITICAL ERROR: CIPHERDROP_SERVER_KEY (32-byte hex) is missing or invalid.');
  process.exit(1);
}
const SERVER_KEY = Buffer.from(SERVER_KEY_HEX, 'hex');

// Helper: Ensure the data store exists
async function initDb() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    try {
      await fs.access(SECRETS_FILE);
    } catch {
      await fs.writeFile(SECRETS_FILE, JSON.stringify({}));
    }
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// Helper: Read and lock/write could be simplified for this scale
async function getSecrets() {
  const data = await fs.readFile(SECRETS_FILE, 'utf8');
  return JSON.parse(data);
}

async function saveSecrets(secrets) {
  await fs.writeFile(SECRETS_FILE, JSON.stringify(secrets, null, 2));
}

// POST /api/secrets: Create a new burn-after-reading secret
app.post('/api/secrets', async (req, res) => {
  let { secret, ttlMinutes } = req.body;

  // Provide a default TTL if missing (backward compatibility with simple clients)
  if (typeof ttlMinutes !== 'number' || ttlMinutes <= 0) {
    ttlMinutes = 60; 
  }

  if (!secret) {
    return res.status(400).json({ error: 'Secret is required' });
  }

  const id = crypto.randomUUID();
  const iv = crypto.randomBytes(16);
  
  // Encrypt the secret
  const cipher = crypto.createCipheriv('aes-256-ctr', SERVER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);

  const expiresAt = Date.now() + ttlMinutes * 60 * 1000;

  // Persist to file
  const secrets = await getSecrets();
  secrets[id] = {
    encryptedSecret: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    expiresAt
  };
  await saveSecrets(secrets);

  res.status(201).json({ id });
});

// GET /api/secrets/:id: Read and burn a secret
app.get('/api/secrets/:id', async (req, res) => {
  const { id } = req.params;
  const secrets = await getSecrets();
  const data = secrets[id];

  if (!data || Date.now() > data.expiresAt) {
    if (data) {
      delete secrets[id];
      await saveSecrets(secrets);
    }
    return res.status(404).json({ error: 'Secret not found or expired' });
  }

  // Burn on read: Delete immediately
  delete secrets[id];
  await saveSecrets(secrets);

  // Decrypt the secret
  const decipher = crypto.createDecipheriv('aes-256-ctr', SERVER_KEY, Buffer.from(data.iv, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(data.encryptedSecret, 'hex')), 
    decipher.final()
  ]);

  res.json({ secret: decrypted.toString('utf8') });
});

// Periodic Garbage Collection
setInterval(async () => {
  try {
    const secrets = await getSecrets();
    let changed = false;
    const now = Date.now();
    
    for (const id in secrets) {
      if (now > secrets[id].expiresAt) {
        delete secrets[id];
        changed = true;
      }
    }

    if (changed) {
      await saveSecrets(secrets);
    }
  } catch (err) {
    console.error('Garbage collection error:', err);
  }
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`CipherDrop Persistent Server listening on port ${PORT}`);
  });
});
