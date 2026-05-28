/**
 * Request logging middleware — method, path, duration, status (no passwords/bodies).
 */
function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const line = [
      new Date().toISOString(),
      req.method,
      req.originalUrl,
      res.statusCode,
      `${duration}ms`,
      req.ip,
    ].join(' ');

    if (res.statusCode >= 500) {
      console.error(`[ERROR] ${line}`);
    } else if (res.statusCode >= 400) {
      console.warn(`[WARN] ${line}`);
    } else {
      console.log(`[INFO] ${line}`);
    }
  });

  next();
}

module.exports = { requestLogger };
