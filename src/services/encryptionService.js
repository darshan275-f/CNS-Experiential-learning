const path = require('path');
const {
  encryptAes,
  decryptAes,
  encryptDes,
  decryptDes,
  packTextPayload,
  unpackTextPayload,
  sha256,
} = require('../utils/cryptoUtils');
const {
  encryptFileBuffer,
  decryptFileBuffer,
  writeFileBuffer,
  removeFile,
} = require('../utils/fileUtils');

/**
 * Encryption service — orchestrates algorithm choice and output formatting.
 * Controllers stay thin; all crypto semantics live here and in utils.
 */

function normalizeAlgorithm(algo) {
  const a = String(algo || '').toLowerCase();
  if (a === 'aes' || a === 'aes-256-gcm') return 'aes';
  if (a === 'des' || a === 'des-cbc') return 'des';
  throw new Error('algorithm must be "aes" or "des"');
}

function buildMetadata(algorithm, extra = {}) {
  const base = {
    algorithm: algorithm === 'aes' ? 'aes' : 'des',
    mode: algorithm === 'aes' ? 'AES-256-GCM' : 'DES-CBC',
    keyDerivation: 'scrypt',
    ivStrategy: 'random-per-operation',
    timestamp: new Date().toISOString(),
  };

  if (algorithm === 'des') {
    base.securityNotice =
      'DES is deprecated and cryptographically weak — for education only';
  }

  return { ...base, ...extra };
}

async function encryptText(algorithm, password, text, options = {}) {
  const algo = normalizeAlgorithm(algorithm);
  const payload =
    algo === 'aes' ? encryptAes(text, password) : encryptDes(text, password);

  const packed = packTextPayload(payload);
  const hash = sha256(text);

  const result = {
    encrypted: options.outputFormat === 'json' ? payload : packed,
    encoding: options.outputFormat === 'json' ? 'json' : 'packed-base64',
    plaintextHash: hash,
  };

  return {
    success: true,
    data: result,
    metadata: buildMetadata(algo, {
      payloadVersion: payload.version,
      hasAuthTag: algo === 'aes',
    }),
  };
}

async function decryptText(algorithm, password, encryptedInput, options = {}) {
  const algo = normalizeAlgorithm(algorithm);

  let payload;
  if (typeof encryptedInput === 'object' && encryptedInput !== null) {
    payload = encryptedInput;
  } else {
    payload = unpackTextPayload(String(encryptedInput));
  }

  const plaintext =
    algo === 'aes' ? decryptAes(payload, password) : decryptDes(payload, password);

  const result = {
    decrypted: plaintext,
    encoding: 'utf8',
  };

  if (options.expectedHash) {
    result.integrityVerified = sha256(plaintext) === options.expectedHash;
  }

  return {
    success: true,
    data: result,
    metadata: buildMetadata(algo),
  };
}

async function encryptFile(algorithm, password, fileBuffer, originalName) {
  const algo = normalizeAlgorithm(algorithm);
  const envelope = await encryptFileBuffer(fileBuffer, password, algo);

  const outName = `enc_${Date.now()}_${sanitizeFilename(originalName)}.enc`;
  const outPath = await writeFileBuffer(outName, envelope);

  return {
    success: true,
    data: {
      filename: outName,
      downloadPath: `/download/${outName}`,
      sizeBytes: envelope.length,
      sha256: sha256(envelope),
      encoding: 'binary-envelope',
    },
    metadata: buildMetadata(algo, {
      originalFilename: originalName,
      fileFormat: 'CNS1-binary-envelope',
    }),
    filePath: outPath,
  };
}

async function decryptFile(password, fileBuffer, originalName) {
  const plain = await decryptFileBuffer(fileBuffer, password);

  const outName = `dec_${Date.now()}_${sanitizeFilename(originalName)}`;
  const outPath = await writeFileBuffer(outName, plain);

  const parsed = require('../utils/fileUtils').parseFileEnvelope(fileBuffer);

  return {
    success: true,
    data: {
      filename: outName,
      downloadPath: `/download/${outName}`,
      sizeBytes: plain.length,
      sha256: sha256(plain),
    },
    metadata: buildMetadata(parsed.algorithm, {
      decryptedFrom: originalName,
    }),
    filePath: outPath,
  };
}

function sanitizeFilename(name) {
  return String(name || 'file')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 120);
}

async function cleanupTempFile(filePath) {
  if (filePath) await removeFile(path.basename(filePath));
}

module.exports = {
  encryptText,
  decryptText,
  encryptFile,
  decryptFile,
  sha256,
  cleanupTempFile,
};
