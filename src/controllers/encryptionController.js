const fs = require('fs/promises');
const path = require('path');
const encryptionService = require('../services/encryptionService');
const { safeUploadPath, removeFile } = require('../utils/fileUtils');
const { sha256 } = require('../utils/cryptoUtils');

async function encryptText(req, res, next) {
  try {
    const { algorithm, password, text, outputFormat } = req.validated;
    const result = await encryptionService.encryptText(
      algorithm,
      password,
      text,
      { outputFormat }
    );
    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

async function decryptText(req, res, next) {
  try {
    const { algorithm, password, encrypted, expectedHash } = req.validated;
    const result = await encryptionService.decryptText(
      algorithm,
      password,
      encrypted,
      { expectedHash }
    );
    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
}

async function encryptFile(req, res, next) {
  let tempPath;
  try {
    const { algorithm, password } = req.validated;
    tempPath = req.file.path;
    const buffer = await fs.readFile(tempPath);
    const originalName = req.file.originalname;

    const result = await encryptionService.encryptFile(
      algorithm,
      password,
      buffer,
      originalName
    );

    res.status(200).json({
      success: result.success,
      data: result.data,
      metadata: result.metadata,
    });
  } catch (err) {
    next(err);
  } finally {
    if (tempPath) await removeFile(path.basename(tempPath));
  }
}

async function decryptFile(req, res, next) {
  let tempPath;
  try {
    const { password } = req.validated;
    tempPath = req.file.path;
    const buffer = await fs.readFile(tempPath);
    const originalName = req.file.originalname;

    const result = await encryptionService.decryptFile(
      password,
      buffer,
      originalName
    );

    res.status(200).json({
      success: result.success,
      data: result.data,
      metadata: result.metadata,
    });
  } catch (err) {
    next(err);
  } finally {
    if (tempPath) await removeFile(path.basename(tempPath));
  }
}

/** Secure download — basename only, resolved under uploads */
async function downloadFile(req, res, next) {
  try {
    const filename = path.basename(req.params.filename);
    const filePath = safeUploadPath(filename);
    res.download(filePath, filename, (err) => {
      if (err && !res.headersSent) next(err);
    });
  } catch (err) {
    err.statusCode = 400;
    err.code = 'INVALID_PATH';
    next(err);
  }
}

/** SHA-256 hash of text or file for integrity checks */
async function hashText(req, res, next) {
  try {
    const { text } = req.body;
    if (!text) {
      const err = new Error('text is required');
      err.statusCode = 400;
      throw err;
    }
    res.json({
      success: true,
      data: { sha256: sha256(text), encoding: 'hex' },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  encryptText,
  decryptText,
  encryptFile,
  decryptFile,
  downloadFile,
  hashText,
};
