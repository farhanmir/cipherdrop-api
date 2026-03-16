const express = require('express');
const cors = require('cors');
const crypto = require('node:crypto');

const app = express();

const PORT = 3000;
const GC_INTERVAL_MS = 60 * 1000;
const MAX_SECRET_BYTES = 64 * 1024;
const MIN_TTL_MINUTES = 1;
const MAX_TTL_MINUTES = 24 * 60;
const BOOT_TIME_MS = Date.now();

// Ephemeral in-memory state (resets on process restart).
const secretsStore = new Map();
const SERVER_KEY = crypto.randomBytes(32);
const metrics = {
  created: 0,
  readSuccess: 0,
  notFoundOrExpired: 0,
  decryptFailures: 0,
  gcDeleted: 0
};

app.use(cors());
app.use(express.json({ limit: '100kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Request-Id', crypto.randomUUID());
  next();
});

function isExpired(expiresAt, now = Date.now()) {
  return now >= expiresAt;
}

function cleanupExpiredSecrets(now = Date.now()) {
  let deletedCount = 0;

  for (const [id, entry] of secretsStore.entries()) {
    if (isExpired(entry.expiresAt, now)) {
      secretsStore.delete(id);
      deletedCount += 1;
    }
  }

  return deletedCount;
}

function encryptSecret(plaintext, iv) {
  const cipher = crypto.createCipheriv('aes-256-ctr', SERVER_KEY, iv);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}

function decryptSecret(ciphertextHex, ivHex) {
  const decipher = crypto.createDecipheriv(
    'aes-256-ctr',
    SERVER_KEY,
    Buffer.from(ivHex, 'hex')
  );

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

function parseAndValidateCreateSecretRequest(body) {
  const secret = body?.secret;
  const ttlMinutes = body?.ttlMinutes;

  if (typeof secret !== 'string' || secret.length === 0) {
    return { error: 'secret must be a non-empty string' };
  }

  const secretByteLength = Buffer.byteLength(secret, 'utf8');
  if (secretByteLength > MAX_SECRET_BYTES) {
    return { error: `secret must be <= ${MAX_SECRET_BYTES} bytes` };
  }

  if (!Number.isInteger(ttlMinutes)) {
    return { error: 'ttlMinutes must be an integer' };
  }

  if (ttlMinutes < MIN_TTL_MINUTES || ttlMinutes > MAX_TTL_MINUTES) {
    return {
      error: `ttlMinutes must be between ${MIN_TTL_MINUTES} and ${MAX_TTL_MINUTES}`
    };
  }

  return { secret, ttlMinutes };
}

app.post('/api/secrets', (req, res) => {
  const parsed = parseAndValidateCreateSecretRequest(req.body);
  if (parsed.error) {
    return res.status(400).json({ error: parsed.error });
  }

  const id = crypto.randomUUID();
  const iv = crypto.randomBytes(16);
  const encryptedSecret = encryptSecret(parsed.secret, iv).toString('hex');
  const expiresAt = Date.now() + parsed.ttlMinutes * 60 * 1000;

  secretsStore.set(id, {
    encryptedSecret,
    iv: iv.toString('hex'),
    expiresAt,
    createdAt: Date.now()
  });
  metrics.created += 1;

  return res.status(201).json({ id });
});

app.get('/api/secrets/:id', (req, res) => {
  const { id } = req.params;
  const record = secretsStore.get(id);

  if (!record || isExpired(record.expiresAt)) {
    if (record) {
      secretsStore.delete(id);
    }
    metrics.notFoundOrExpired += 1;
    return res.status(404).json({ error: 'Secret not found or expired' });
  }

  // Burn-on-read: remove from memory before sending the plaintext response.
  secretsStore.delete(id);

  try {
    const secret = decryptSecret(record.encryptedSecret, record.iv);
    metrics.readSuccess += 1;
    return res.status(200).json({ secret });
  } catch {
    metrics.decryptFailures += 1;
    return res.status(500).json({ error: 'Failed to decrypt secret' });
  }
});

app.get('/health', (req, res) => {
  const now = Date.now();
  return res.status(200).json({
    status: 'ok',
    uptimeSeconds: Math.floor((now - BOOT_TIME_MS) / 1000),
    inMemorySecrets: secretsStore.size,
    serverTime: new Date(now).toISOString()
  });
});

app.get('/metrics', (req, res) => {
  const now = Date.now();
  return res.status(200).json({
    uptimeSeconds: Math.floor((now - BOOT_TIME_MS) / 1000),
    inMemorySecrets: secretsStore.size,
    counters: {
      created: metrics.created,
      readSuccess: metrics.readSuccess,
      notFoundOrExpired: metrics.notFoundOrExpired,
      decryptFailures: metrics.decryptFailures,
      gcDeleted: metrics.gcDeleted
    }
  });
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  return next(err);
});

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  if (res.headersSent) {
    return next(err);
  }
  return res.status(500).json({ error: 'Internal server error' });
});

const gcHandle = setInterval(() => {
  const deletedCount = cleanupExpiredSecrets();
  if (deletedCount > 0) {
    metrics.gcDeleted += deletedCount;
    console.log(`GC removed ${deletedCount} expired secret(s)`);
  }
}, GC_INTERVAL_MS);

gcHandle.unref();

app.listen(PORT, () => {
  console.log(`CipherDrop API listening on port ${PORT}`);
});
