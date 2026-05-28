# Screen Shots of output is in folder output_png 



# CNS Encryption API

Production-oriented Node.js backend for **text and file encryption** using **AES-256-GCM** (recommended) and **DES-CBC** (legacy demonstration only).

No frontend — REST APIs only.

## Features

| Feature | AES-256-GCM | DES-CBC (legacy) |
|--------|-------------|------------------|
| Encrypt text | ✅ | ✅ |
| Decrypt text | ✅ | ✅ |
| Encrypt file | ✅ | ✅ |
| Decrypt file | ✅ | ✅ |

**Security highlights**

- Random IV per operation (12-byte IV for GCM)
- scrypt key derivation with server pepper
- Auth tag (GCM) for integrity
- No hardcoded keys — `.env` only
- Upload size limits, MIME validation, path traversal protection
- Helmet, rate limiting, optional JWT
- SHA-256 hashing endpoint for integrity checks

> **Warning:** DES is cryptographically broken. It is included for education only. Use **aes** in production.

## Project structure

```
CNS/
├── server.js
├── package.json
├── .env
├── .env.example
├── postman/
│   └── CNS-Encryption-API.postman_collection.json
└── src/
    ├── controllers/
    ├── routes/
    ├── services/
    ├── utils/
    ├── middlewares/
    └── uploads/
```

## Setup

```bash
cd CNS
npm install
cp .env.example .env   # if .env missing — edit secrets
npm start
```

Server: `http://localhost:3000`

## Environment variables

| Variable | Description |
|----------|-------------|
| `PORT` | HTTP port (default `3000`) |
| `ENCRYPTION_PEPPER` | Server secret mixed into scrypt (required) |
| `MAX_UPLOAD_BYTES` | Max upload size (default 10MB) |
| `REQUIRE_JWT` | `true` to require Bearer token on crypto routes |
| `JWT_SECRET` | Secret for JWT when enabled |

See `.env.example` for full list.

## API reference

### `POST /encrypt/text`

```json
{
  "algorithm": "aes",
  "password": "SecurePass123!",
  "text": "Hello, secure world!",
  "outputFormat": "packed"
}
```

- `algorithm`: `aes` | `des`
- `outputFormat`: `packed` (default) or `json` (structured fields)

**Sample response (AES):**

```json
{
  "success": true,
  "data": {
    "encrypted": "1:aes:AbCdEfGh...:XyZIv...:AuthTagBase64...:CipherBase64...",
    "encoding": "packed-base64",
    "plaintextHash": "2ef597bd4f3e08f1e9880d9774d29b371dd364bdab3c9980ee909ac6cb044e6"
  },
  "metadata": {
    "algorithm": "aes",
    "mode": "AES-256-GCM",
    "keyDerivation": "scrypt",
    "ivStrategy": "random-per-operation",
    "hasAuthTag": true
  }
}
```

**Packed format:** `version:algo:salt:iv:authTag:ciphertext` (base64 segments; authTag empty for DES)

### `POST /decrypt/text`

```json
{
  "algorithm": "aes",
  "password": "SecurePass123!",
  "text": "1:aes:...packed payload from encrypt..."
}
```

Optional: `expectedHash` — SHA-256 of original plaintext for verification.

### `POST /encrypt/file`

`multipart/form-data`:

| Field | Value |
|-------|--------|
| `algorithm` | `aes` or `des` |
| `password` | min 8 chars |
| `file` | binary file |

Returns `downloadPath` e.g. `/download/enc_1730000000000_document.pdf.enc`

### `POST /decrypt/file`

`multipart/form-data`:

| Field | Value |
|-------|--------|
| `password` | encryption password |
| `file` | `.enc` file from encrypt |

Algorithm is read from the file envelope (magic `CNS1`).

### `GET /download/:filename`

Download encrypted or decrypted files from `src/uploads` (basename only — no traversal).

### `POST /hash/text`

```json
{ "text": "Hello" }
```

Returns SHA-256 hex digest.

### `GET /health`

Service status.

## Sample encrypted output (illustrative)

**AES packed text** (truncated):

```
1:aes:K7pQ2mN8vR1xW4yZ9aB3cD6eF0gH2jL5nM8pQ1rS4tU7vW0xY3zA6bC9dE2fG5h:7nM9pQ2rS5tU8vW1xY4zA7b:3kL6nP9qR2sT5uV8wX1yZ4aB7cD0eF3gH6jK9lM2nO5p:8qR1sT4uV7wX0yZ3aB6cD9eF2gH5jK8lM1nO4pQ7rS0tU3vW6xY9zA2bC5dE8fG1hJ4kL7mN0pQ3rS6tU9vW2xY5zA8bC1dE4fG7hJ0kL3nO6pQ9rS2tU5vW8xY1zA4bC7dE0fG3hJ6kL9mN2pQ5rS8tU1vW4xY7zA0bC3dE6fG9hJ2kL5nO8pQ1rS4tU7vW0xY3zA6bC9dE2fG5hI8jK1lM4nO7pQ0rS3tU6vW9xY2zA5bC8dE1fG4hJ7kL0mN3pQ6rS9tU2vW5xY8zA1bC4dE7fG0hJ3kL6nO9pQ2rS5tU8vW1xY4zA7bC0dE3fG6hJ9kL2mN5pQ8rS1tU4vW7xY0zA3bC6dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9bC2dE5fG8hJ1kL4mN7pQ0rS3tU6vW9xY2zA5b
```

**AES JSON** (`outputFormat: "json"`):

```json
{
  "version": 1,
  "algorithm": "aes-256-gcm",
  "salt": "base64...",
  "iv": "base64...",
  "authTag": "base64...",
  "ciphertext": "base64..."
}
```

**Encrypted file:** binary header `CNS1` + algorithm byte + length-prefixed salt, IV, auth tag, ciphertext.

## cURL examples

```bash
# Encrypt text (AES)
curl -s -X POST http://localhost:3000/encrypt/text \
  -H "Content-Type: application/json" \
  -d "{\"algorithm\":\"aes\",\"password\":\"SecurePass123!\",\"text\":\"Hello\"}"

# Decrypt text
curl -s -X POST http://localhost:3000/decrypt/text \
  -H "Content-Type: application/json" \
  -d "{\"algorithm\":\"aes\",\"password\":\"SecurePass123!\",\"text\":\"PASTE_ENCRYPTED_HERE\"}"

# Encrypt file
curl -s -X POST http://localhost:3000/encrypt/file \
  -F "algorithm=aes" \
  -F "password=SecurePass123!" \
  -F "file=@./sample.txt"
```

## Postman

Import `postman/CNS-Encryption-API.postman_collection.json`. Run **Encrypt Text (AES)** first — it saves `encryptedText` for **Decrypt Text (AES)**.

## npm scripts

| Script | Command |
|--------|---------|
| `npm start` | Run server (enables OpenSSL legacy provider for DES demos) |
| `npm run start:modern-only` | AES-only — no legacy OpenSSL flag |
| `npm run dev` | Run with `--watch` and legacy provider |

> **Node 17+ / OpenSSL 3:** DES-CBC requires `--openssl-legacy-provider` (included in `npm start`). AES works without it.

## Cryptography flow (AES text)

1. Generate random 16-byte salt and 12-byte IV.
2. Derive 32-byte key: `scrypt(password + pepper, salt)`.
3. Encrypt with `aes-256-gcm`; obtain 16-byte auth tag.
4. Return packed base64 segments (salt, IV, tag, ciphertext stored with output).

Decryption reverses the steps; GCM rejects tampered ciphertext.

## License

MIT
