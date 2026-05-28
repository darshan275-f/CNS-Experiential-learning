/**
 * Centralized error handler — avoids leaking stack traces or crypto internals in production.
 */
function notFoundHandler(req, res, next) {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found',
    },
  });
}

function errorHandler(err, req, res, next) {
  const isProd = process.env.NODE_ENV === 'production';

  let status = err.statusCode || err.status || 500;
  let code = err.code || 'INTERNAL_ERROR';
  let message = err.message || 'An unexpected error occurred';

  // Crypto / auth failures — generic client message
  if (
    message.includes('bad decrypt') ||
    message.includes('Unsupported state') ||
    message.includes('auth') ||
    message.includes('decipher')
  ) {
    status = 400;
    code = 'DECRYPTION_FAILED';
    message = 'Decryption failed — incorrect password or corrupted data';
  }

  if (err.code === 'ERR_OSSL_EVP_UNSUPPORTED') {
    status = 503;
    code = 'LEGACY_CIPHER_UNAVAILABLE';
    message =
      'DES-CBC requires OpenSSL legacy provider — run via npm start (includes --openssl-legacy-provider)';
  }

  if (err.name === 'MulterError') {
    status = 400;
    code = 'UPLOAD_ERROR';
    if (err.code === 'LIMIT_FILE_SIZE') {
      message = 'File exceeds maximum upload size';
    } else {
      message = 'File upload failed';
    }
  }

  if (status >= 500) {
    console.error('[ERROR]', err);
  }

  res.status(status).json({
    success: false,
    error: {
      code,
      message,
      ...(isProd ? {} : { detail: err.message }),
    },
  });
}

module.exports = { notFoundHandler, errorHandler };
