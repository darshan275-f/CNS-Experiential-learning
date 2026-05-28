const path = require('path');
const multer = require('multer');
const { ALLOWED_MIME_TYPES } = require('../utils/constants');
const { UPLOAD_ROOT, ensureUploadDir } = require('../utils/fileUtils');

const maxBytes = parseInt(process.env.MAX_UPLOAD_BYTES || '10485760', 10);

const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      await ensureUploadDir();
      cb(null, UPLOAD_ROOT);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    const safe = `${Date.now()}_${path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    cb(null, safe);
  },
});

function mimeFilter(req, file, cb) {
  if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
    cb(null, true);
    return;
  }
  const err = new Error(`MIME type not allowed: ${file.mimetype}`);
  err.statusCode = 400;
  err.code = 'INVALID_MIME';
  cb(err, false);
}

const upload = multer({
  storage,
  limits: { fileSize: maxBytes, files: 1 },
  fileFilter: mimeFilter,
});

module.exports = { upload, maxBytes };
