# finalvaultkey

## Project Overview

finalvaultkey is a Flask-based secure authentication and document signing application.
It uses PKI to issue X.509 certificates, supports login with email/password or certificate PEM,
stores encrypted private keys on disk, and verifies signed document hashes.

## Features

- PKI-based user registration and certificate issuance
- Email/password and certificate PEM login
- JWT authentication with token revocation support
- Document signing and verification
- Encrypted private key storage for users

## Requirements

- Python 3.11+ (or compatible Python 3.10+)
- Git
- Virtual environment support

## Setup

1. Create a virtual environment:

```bash
python -m venv venv
```

2. Activate it:

- Windows:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- Linux/macOS:
  ```bash
  source venv/bin/activate
  ```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Required Environment Variables

Set these before running the application:

```bash
export VAULTKEY_JWT_SECRET="your-strong-jwt-secret"
export VAULTKEY_PRIVATE_KEY_PASSPHRASE="your-encryption-passphrase"
```

On Windows PowerShell:

```powershell
$env:VAULTKEY_JWT_SECRET = "your-strong-jwt-secret"
$env:VAULTKEY_PRIVATE_KEY_PASSPHRASE = "your-encryption-passphrase"
```

For local development, you can also create a `.env` file in the project root. Copy the example file:

```powershell
copy .env.example .env
```

Then edit `.env` with your values.

Optional environment variables:

```bash
export VAULTKEY_DATABASE_URI="sqlite:///vaultkey.db"
export VAULTKEY_CA_CERT_PATH="keys/ca_cert.pem"
export VAULTKEY_CA_KEY_PATH="keys/ca_key.pem"
export VAULTKEY_PRIVATE_KEY_STORAGE_PATH="keys/{user_id}_private.pem"
```

## Run

```bash
python run.py
```

Then open: `http://127.0.0.1:5000`

## API Endpoints

- `POST /api/auth/register` — register a new user
- `POST /api/auth/login` — login with email/password or certificate PEM
- `POST /api/auth/logout` — revoke JWT
- `GET /api/auth/me` — current user profile
- `POST /api/documents/sign` — sign a document hash
- `POST /api/documents/verify` — verify document signature

## Important Notes

- Private keys are stored encrypted on disk using the configured passphrase.
- Do not expose `VAULTKEY_JWT_SECRET` or `VAULTKEY_PRIVATE_KEY_PASSPHRASE` in public source control.
- The current code no longer returns private keys in API responses.

## Security Improvements Applied

- Removed private key PEM from registration response
- Enforced required environment variables for JWT secret and private key passphrase
- Maintains encrypted private key storage for user keys

