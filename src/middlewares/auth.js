const jwt = require('jsonwebtoken');

/**
 * Optional JWT gate — enable with REQUIRE_JWT=true in .env
 */
function jwtAuth(req, res, next) {
  if (process.env.REQUIRE_JWT !== 'true') {
    return next();
  }

  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: { code: 'UNAUTHORIZED', message: 'Bearer token required' },
    });
  }

  const token = header.slice(7);
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({
      success: false,
      error: { code: 'CONFIG_ERROR', message: 'JWT not configured' },
    });
  }

  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' },
    });
  }
}

/** Issue a dev token (optional helper route) */
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1h',
  });
}

module.exports = { jwtAuth, signToken };
