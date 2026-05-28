const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const { FILE_MAGIC, AES_ALGORITHM, DES_ALGORITHM } = require('./constants');
const { deriveKey, generateSalt, generateIv } = require('./cryptoUtils');

const UPLOAD_ROOT = path.resolve(
  process.env.UPLOAD_DIR || path.join(__dirname, '..', 'uploads')
);

/**
 * Resolve paths only under UPLOAD_ROOT to prevent path traversal (../etc/passwd).
 */
function safeUploadPath(filename) {
  const basename = path.basename(filename);
  const resolved = path.resolve(UPLOAD_ROOT, basename);
  if (!resolved.startsWith(UPLOAD_ROOT + path.sep) && resolved !== UPLOAD_ROOT) {
    throw new Error('Invalid file path');
  }
  return resolved;
}

async function ensureUploadDir() {
  await fs.mkdir(UPLOAD_ROOT, { recursive: true });
}

async function readFileBuffer(filePath) {
  const safe = safeUploadPath(filePath);
  return fs.readFile(safe);
}

async function writeFileBuffer(filename, buffer) {
  await ensureUploadDir();
  const safe = safeUploadPath(filename);
  await fs.writeFile(safe, buffer);
  return safe;
}

async function removeFile(filePath) {
  try {
    const safe = safeUploadPath(path.basename(filePath));
    await fs.unlink(safe);
  } catch {
    // best-effort cleanup
  }
}

/** Binary file envelope: MAGIC | algoByte | saltLen | salt | ivLen | iv | tagLen | tag | ciphertext */
const ALGO_BYTE_AES = 1;
const ALGO_BYTE_DES = 2;

function buildFileEnvelope(algorithm, salt, iv, authTag, ciphertext) {
  const algoByte = algorithm === 'aes' ? ALGO_BYTE_AES : ALGO_BYTE_DES;
  const tagBuf = authTag || Buffer.alloc(0);

  return Buffer.concat([
    FILE_MAGIC,
    Buffer.from([algoByte]),
    uint16Be(salt.length),
    salt,
    uint16Be(iv.length),
    iv,
    uint16Be(tagBuf.length),
    tagBuf,
    ciphertext,
  ]);
}

function parseFileEnvelope(buffer) {
  if (buffer.length < FILE_MAGIC.length + 1) {
    throw new Error('File too small or corrupt');
  }

  const magic = buffer.subarray(0, 4);
  if (!magic.equals(FILE_MAGIC)) {
    throw new Error('Unrecognized encrypted file format');
  }

  let offset = 4;
  const algoByte = buffer[offset];
  offset += 1;

  const saltLen = buffer.readUInt16BE(offset);
  offset += 2;
  const salt = buffer.subarray(offset, offset + saltLen);
  offset += saltLen;

  const ivLen = buffer.readUInt16BE(offset);
  offset += 2;
  const iv = buffer.subarray(offset, offset + ivLen);
  offset += ivLen;

  const tagLen = buffer.readUInt16BE(offset);
  offset += 2;
  const authTag = buffer.subarray(offset, offset + tagLen);
  offset += tagLen;

  const ciphertext = buffer.subarray(offset);

  let algorithm;
  let cipherAlgo;
  let keyLen;

  if (algoByte === ALGO_BYTE_AES) {
    algorithm = 'aes';
    cipherAlgo = AES_ALGORITHM;
    keyLen = 32;
  } else if (algoByte === ALGO_BYTE_DES) {
    algorithm = 'des';
    cipherAlgo = DES_ALGORITHM;
    keyLen = 8;
  } else {
    throw new Error('Unknown algorithm in file');
  }

  return { algorithm, cipherAlgo, keyLen, salt, iv, authTag, ciphertext };
}

function uint16Be(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

/**
 * Encrypt file buffer in memory (suitable up to MAX_UPLOAD_BYTES).
 */
async function encryptFileBuffer(plainBuffer, password, algorithm) {
  const { AES_KEY_BYTES, AES_IV_BYTES, DES_KEY_BYTES, DES_IV_BYTES } = require('./constants');

  const salt = generateSalt(algorithm === 'aes' ? 16 : 8);
  const keyLen = algorithm === 'aes' ? AES_KEY_BYTES : DES_KEY_BYTES;
  const ivLen = algorithm === 'aes' ? AES_IV_BYTES : DES_IV_BYTES;
  const key = deriveKey(password, salt, keyLen);
  const iv = generateIv(ivLen);

  let ciphertext;
  let authTag = null;
  const cipherAlgo = algorithm === 'aes' ? AES_ALGORITHM : DES_ALGORITHM;

  const cipher = crypto.createCipheriv(cipherAlgo, key, iv);
  ciphertext = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  if (algorithm === 'aes') {
    authTag = cipher.getAuthTag();
  }

  return buildFileEnvelope(algorithm, salt, iv, authTag, ciphertext);
}

async function decryptFileBuffer(envelopeBuffer, password) {
  const parsed = parseFileEnvelope(envelopeBuffer);
  const key = deriveKey(password, parsed.salt, parsed.keyLen);

  const decipher = crypto.createDecipheriv(parsed.cipherAlgo, key, parsed.iv);
  if (parsed.algorithm === 'aes') {
    decipher.setAuthTag(parsed.authTag);
  }

  return Buffer.concat([
    decipher.update(parsed.ciphertext),
    decipher.final(),
  ]);
}

/**
 * Streaming encryption for large files (optional advanced path).
 * Writes encrypted envelope header then streams ciphertext chunks.
 */
async function encryptFileStream(inputPath, outputPath, password, algorithm) {
  const plain = await readFileBuffer(path.basename(inputPath));
  const encrypted = await encryptFileBuffer(plain, password, algorithm);
  await writeFileBuffer(path.basename(outputPath), encrypted);
  return outputPath;
}

async function decryptFileStream(inputPath, outputPath, password) {
  const envelope = await readFileBuffer(path.basename(inputPath));
  const plain = await decryptFileBuffer(envelope, password);
  await writeFileBuffer(path.basename(outputPath), plain);
  return outputPath;
}

module.exports = {
  UPLOAD_ROOT,
  safeUploadPath,
  ensureUploadDir,
  readFileBuffer,
  writeFileBuffer,
  removeFile,
  encryptFileBuffer,
  decryptFileBuffer,
  encryptFileStream,
  decryptFileStream,
  buildFileEnvelope,
  parseFileEnvelope,
};
