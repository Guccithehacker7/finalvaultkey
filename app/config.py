import os


class Config:
    """Application configuration loaded from environment variables."""

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "VAULTKEY_DATABASE_URI",
        "postgresql://vaultkey:change_me@localhost:5432/vaultkey",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv("VAULTKEY_JWT_SECRET", "replace-with-strong-secret")
    JWT_ALGORITHM = os.getenv("VAULTKEY_JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("VAULTKEY_JWT_ACCESS_TOKEN_EXPIRES", "3600"))

    CA_CERT_PATH = os.getenv("VAULTKEY_CA_CERT_PATH", "keys/ca_cert.pem")
    CA_KEY_PATH = os.getenv("VAULTKEY_CA_KEY_PATH", "keys/ca_key.pem")

    VAULT_MASTER_PASSWORD = os.getenv("VAULTKEY_VAULT_PASSWORD", "replace-with-strong-password")
    PRIVATE_KEY_PASSPHRASE = os.getenv("VAULTKEY_PRIVATE_KEY_PASSPHRASE", "replace-with-strong-passphrase")
    PRIVATE_KEY_STORAGE_PATH = os.getenv("VAULTKEY_PRIVATE_KEY_STORAGE_PATH", "keys/{user_id}_private.pem")
    AES_KEY_LENGTH = 32

    # In production, ensure the JWT secret, DB URI, and master secrets are injected through secure environment variables.
