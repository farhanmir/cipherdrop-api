const crypto = require('crypto');

// Generate a random 256-bit server key on startup
const SERVER_KEY = crypto.randomBytes(32);

module.exports = {
  encryptSecret: (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', SERVER_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return { iv: iv.toString('hex'), encryptedSecret: encrypted.toString('hex') };
  },
  
  decryptSecret: (encryptedHex, ivHex) => {
    const decipher = crypto.createDecipheriv('aes-256-ctr', SERVER_KEY, Buffer.from(ivHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, 'hex')), 
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  },

  // Hashes an optional user PIN so we don't store it in plaintext
  hashPin: (pin) => {
    if (!pin) return null;
    return crypto.pbkdf2Sync(pin, 'cipherdrop-salt', 100000, 64, 'sha512').toString('hex');
  }
};
