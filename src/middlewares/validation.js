const { ALLOWED_ALGORITHMS } = require('../utils/constants');

function validateAlgorithm(algorithm) {
  const a = String(algorithm || '').toLowerCase();
  if (!ALLOWED_ALGORITHMS.includes(a)) {
    const err = new Error('algorithm must be "aes" or "des"');
    err.statusCode = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  return a;
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    const err = new Error('password is required');
    err.statusCode = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  if (password.length < 8) {
    const err = new Error('password must be at least 8 characters');
    err.statusCode = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  if (password.length > 256) {
    const err = new Error('password exceeds maximum length');
    err.statusCode = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  return password;
}

function validateTextBody(req, res, next) {
  try {
    req.validated = req.validated || {};
    req.validated.algorithm = validateAlgorithm(req.body.algorithm);
    req.validated.password = validatePassword(req.body.password);

    if (req.path.includes('/encrypt/')) {
      if (!req.body.text || typeof req.body.text !== 'string') {
        const err = new Error('text is required for encryption');
        err.statusCode = 400;
        err.code = 'VALIDATION_ERROR';
        throw err;
      }
      req.validated.text = req.body.text;
    }

    if (req.path.includes('/decrypt/')) {
      const encrypted = req.body.text || req.body.encrypted;
      if (!encrypted) {
        const err = new Error('text or encrypted field is required for decryption');
        err.statusCode = 400;
        err.code = 'VALIDATION_ERROR';
        throw err;
      }
      req.validated.encrypted = encrypted;
      req.validated.expectedHash = req.body.expectedHash;
    }

    req.validated.outputFormat =
      req.body.outputFormat === 'json' ? 'json' : 'packed';

    next();
  } catch (err) {
    next(err);
  }
}

function validateFileBody(req, res, next) {
  try {
    req.validated = req.validated || {};
    req.validated.algorithm = validateAlgorithm(
      req.body.algorithm || req.query.algorithm
    );
    req.validated.password = validatePassword(req.body.password);

    if (!req.file) {
      const err = new Error('file is required (multipart field name: file)');
      err.statusCode = 400;
      err.code = 'VALIDATION_ERROR';
      throw err;
    }

    next();
  } catch (err) {
    next(err);
  }
}

function validateDecryptFileBody(req, res, next) {
  try {
    req.validated = req.validated || {};
    req.validated.password = validatePassword(req.body.password);

    if (!req.file) {
      const err = new Error('encrypted file is required');
      err.statusCode = 400;
      err.code = 'VALIDATION_ERROR';
      throw err;
    }

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = {
  validateTextBody,
  validateFileBody,
  validateDecryptFileBody,
};
