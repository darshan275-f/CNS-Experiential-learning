const crypto = require('crypto');
const {
  AES_ALGORITHM,
  AES_KEY_BYTES,
  AES_IV_BYTES,
  DES_ALGORITHM,
  DES_KEY_BYTES,
  DES_IV_BYTES,
  PAYLOAD_VERSION,
} = require('./constants');

/**
 * Derive a symmetric key from a user password using scrypt.
 * scrypt is memory-hard and resists GPU/ASIC brute-force better than plain PBKDF2.
 * A server-side pepper (from env) is mixed in so offline rainbow tables against
 * leaked DB salts alone are less useful if env secrets stay protected.
 */
function deriveKey(password, salt, keyLen) {
  const pepper = process.env.ENCRYPTION_PEPPER;
  if (!pepper) {
    throw new Error('ENCRYPTION_PEPPER is not configured');
  }

  const N = parseInt(process.env.SCRYPT_N || '16384', 10);
  const r = parseInt(process.env.SCRYPT_R || '8', 10);
  const p = parseInt(process.env.SCRYPT_P || '1', 10);

  const material = `${password}${pepper}`;
  return crypto.scryptSync(material, salt, keyLen, { N, r, p });
}

function generateSalt(byteLength) {
  const len = byteLength || parseInt(process.env.SCRYPT_SALT_BYTES || '16', 10);
  return crypto.randomBytes(len);
}

function generateIv(byteLength) {
  return crypto.randomBytes(byteLength);
}

/**
 * AES-256-GCM encrypt.
 * Flow: random salt → scrypt key → random IV → encrypt → auth tag verifies integrity.
 */
function encryptAes(plaintext, password) {
  const salt = generateSalt();
  const key = deriveKey(password, salt, AES_KEY_BYTES);
  const iv = generateIv(AES_IV_BYTES);

  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    version: PAYLOAD_VERSION,
    algorithm: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    encoding: 'base64',
  };
}

/**
 * AES-256-GCM decrypt.
 * Auth tag must match or decipher throws — detects tampering.
 */
function decryptAes(payload, password) {
  const salt = Buffer.from(payload.salt, 'base64');
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const key = deriveKey(password, salt, AES_KEY_BYTES);
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString('utf8');
}

/**
 * DES-CBC encrypt (INSECURE — educational demonstration only).
 * 56-bit effective key space is trivially brute-forced today.
 */
function encryptDes(plaintext, password) {
  const salt = generateSalt(8);
  const key = deriveKey(password, salt, DES_KEY_BYTES);
  const iv = generateIv(DES_IV_BYTES);

  const cipher = crypto.createCipheriv(DES_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  return {
    version: PAYLOAD_VERSION,
    algorithm: 'des-cbc',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: null,
    ciphertext: ciphertext.toString('base64'),
    encoding: 'base64',
    warning: 'DES is deprecated and insecure — use AES for production data',
  };
}

function decryptDes(payload, password) {
  const salt = Buffer.from(payload.salt, 'base64');
  const iv = Buffer.from(payload.iv, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const key = deriveKey(password, salt, DES_KEY_BYTES);
  const decipher = crypto.createDecipheriv(DES_ALGORITHM, key, iv);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString('utf8');
}

/** Pack text payload into a single portable string: version|algo|salt|iv|tag|ciphertext */
function packTextPayload(payload) {
  const algo = payload.algorithm === 'aes-256-gcm' ? 'aes' : 'des';
  const tag = payload.authTag || '';
  return [
    payload.version,
    algo,
    payload.salt,
    payload.iv,
    tag,
    payload.ciphertext,
  ].join(':');
}

/** Unpack colon-delimited encrypted text */
function unpackTextPayload(packed) {
  const parts = packed.split(':');
  if (parts.length < 6) {
    throw new Error('Invalid encrypted text format');
  }

  const [version, algo, salt, iv, tagOrEmpty, ...rest] = parts;
  const ciphertext = rest.join(':'); // ciphertext may contain colons if base64

  if (parseInt(version, 10) !== PAYLOAD_VERSION) {
    throw new Error('Unsupported payload version');
  }

  if (algo === 'aes') {
    return {
      version: parseInt(version, 10),
      algorithm: 'aes-256-gcm',
      salt,
      iv,
      authTag: tagOrEmpty,
      ciphertext,
    };
  }

  if (algo === 'des') {
    return {
      version: parseInt(version, 10),
      algorithm: 'des-cbc',
      salt,
      iv,
      ciphertext,
    };
  }

  throw new Error('Unknown algorithm in payload');
}

/** SHA-256 hash (integrity / fingerprinting) */
function sha256(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/** Constant-time-ish string compare for hashes */
function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  deriveKey,
  generateSalt,
  generateIv,
  encryptAes,
  decryptAes,
  encryptDes,
  decryptDes,
  packTextPayload,
  unpackTextPayload,
  sha256,
  secureCompare,
};
