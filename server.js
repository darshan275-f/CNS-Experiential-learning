require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const encryptionRoutes = require('./src/routes/encryptionRoutes');
const { requestLogger } = require('./src/middlewares/logger');
const { notFoundHandler, errorHandler } = require('./src/middlewares/errorHandler');
const { ensureUploadDir } = require('./src/utils/fileUtils');
const { signToken } = require('./src/middlewares/auth');

const app = express();
const PORT = parseInt(process.env.PORT || '5000', 10);

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(requestLogger);

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: { code: 'RATE_LIMIT', message: 'Too many requests' },
  },
});


app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'cns-encryption-api',
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

/** Dev-only token endpoint when JWT is enabled */
app.post('/auth/token', (req, res, next) => {
  try {
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        success: false,
        error: { message: 'JWT_SECRET not set' },
      });
    }
    const token = signToken({ sub: req.body.subject || 'api-client' });
    res.json({ success: true, token, expiresIn: process.env.JWT_EXPIRES_IN });
  } catch (err) {
    next(err);
  }
});

app.use('/', encryptionRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

/** OpenSSL 3 (Node 17+) disables DES unless legacy provider is enabled */
function checkDesAvailability() {
  try {
    const crypto = require('crypto');
    const key = crypto.randomBytes(8);
    const iv = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    cipher.update('probe');
    cipher.final();
    return true;
  } catch {
    return false;
  }
}

async function start() {
  await ensureUploadDir();

  if (!checkDesAvailability()) {
    console.warn(
      '[WARN] DES-CBC is unavailable in this Node/OpenSSL build. ' +
        'Use "npm start" (includes --openssl-legacy-provider) for legacy DES demos.'
    );
  }

  app.listen(PORT, () => {
    console.log(`CNS Encryption API listening on http://localhost:${PORT}`);
    console.log(`JWT required: ${process.env.REQUIRE_JWT === 'true'}`);
    console.log(`DES-CBC available: ${checkDesAvailability()}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = app;
