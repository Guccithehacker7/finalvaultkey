import os


class Config:
    # ── Database ──────────────────────────────────────────────
    # Defaults to SQLite for local dev. Set VAULTKEY_DATABASE_URI to a
    # PostgreSQL URL for staging/production.
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "VAULTKEY_DATABASE_URI",
        "sqlite:///vaultkey.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── JWT ───────────────────────────────────────────────────
    JWT_SECRET_KEY = os.getenv("VAULTKEY_JWT_SECRET", "dev-secret-key-change-this-in-production-32b")
    JWT_ALGORITHM = os.getenv("VAULTKEY_JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("VAULTKEY_JWT_ACCESS_TOKEN_EXPIRES", "3600"))

    # ── PKI / Key storage ─────────────────────────────────────
    CA_CERT_PATH = os.getenv("VAULTKEY_CA_CERT_PATH", "keys/ca_cert.pem")
    CA_KEY_PATH = os.getenv("VAULTKEY_CA_KEY_PATH", "keys/ca_key.pem")
    PRIVATE_KEY_STORAGE_PATH = os.getenv("VAULTKEY_PRIVATE_KEY_STORAGE_PATH", "keys/{user_id}_private.pem")
    PRIVATE_KEY_PASSPHRASE = os.getenv("VAULTKEY_PRIVATE_KEY_PASSPHRASE", "dev-passphrase-change-in-prod")

    # ── Vault encryption ──────────────────────────────────────
    VAULT_MASTER_PASSWORD = os.getenv("VAULTKEY_VAULT_PASSWORD", "dev-vault-password-change-in-prod")
    AES_KEY_LENGTH = 32
