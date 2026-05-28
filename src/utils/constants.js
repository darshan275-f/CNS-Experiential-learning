/**
 * Cryptographic and application constants.
 * Keys are never stored here — only algorithm parameters loaded from env.
 */

const AES_ALGORITHM = 'aes-256-gcm';
const AES_KEY_BYTES = 32;
const AES_IV_BYTES = 12; // 96-bit IV recommended for GCM
const AES_AUTH_TAG_BYTES = 16;

/**
 * DES-CBC (legacy / educational only).
 * DES is cryptographically broken — 56-bit effective key, vulnerable to brute force.
 * Do not use DES for real data protection.
 */
const DES_ALGORITHM = 'des-cbc';
const DES_KEY_BYTES = 8;
const DES_IV_BYTES = 8;

const PAYLOAD_VERSION = 1;
const FILE_MAGIC = Buffer.from('CNS1', 'ascii');

const ALLOWED_ALGORITHMS = ['aes', 'des'];

/** MIME types accepted for file encrypt/decrypt uploads */
const ALLOWED_MIME_TYPES = new Set([
  'text/plain',
  'application/json',
  'application/octet-stream',
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/gif',
  'text/csv',
  'application/xml',
  'text/xml',
]);

module.exports = {
  AES_ALGORITHM,
  AES_KEY_BYTES,
  AES_IV_BYTES,
  AES_AUTH_TAG_BYTES,
  DES_ALGORITHM,
  DES_KEY_BYTES,
  DES_IV_BYTES,
  PAYLOAD_VERSION,
  FILE_MAGIC,
  ALLOWED_ALGORITHMS,
  ALLOWED_MIME_TYPES,
};
