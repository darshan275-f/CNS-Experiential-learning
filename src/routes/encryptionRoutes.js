const express = require('express');
const {
  encryptText,
  decryptText,
  encryptFile,
  decryptFile,
  downloadFile,
  hashText,
} = require('../controllers/encryptionController');
const {
  validateTextBody,
  validateFileBody,
  validateDecryptFileBody,
} = require('../middlewares/validation');
const { upload } = require('../middlewares/upload');
const { jwtAuth } = require('../middlewares/auth');

const router = express.Router();

router.use(jwtAuth);

router.post('/encrypt/text', validateTextBody, encryptText);
router.post('/decrypt/text', validateTextBody, decryptText);
router.post(
  '/encrypt/file',
  upload.single('file'),
  validateFileBody,
  encryptFile
);
router.post(
  '/decrypt/file',
  upload.single('file'),
  validateDecryptFileBody,
  decryptFile
);

router.get('/download/:filename', downloadFile);
router.post('/hash/text', hashText);

module.exports = router;
