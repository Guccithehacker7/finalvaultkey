import os
import warnings
from pathlib import Path


def load_dotenv(dotenv_path: Path | str | None = None) -> None:
    path = Path(dotenv_path or Path.cwd())
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and os.getenv(key) is None:
                os.environ[key] = value

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


def _get_env(key: str, default: str, warning: str) -> str:
    value = os.getenv(key, default)
    if value == default:
        warnings.warn(
            f"{warning} Using a development fallback. "
            "Set the environment variable or create a .env file for production.",
            UserWarning,
            stacklevel=2,
        )
    return value


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
    JWT_SECRET_KEY = _get_env(
        "VAULTKEY_JWT_SECRET",
        "dev-jwt-secret-change-me",
        "VAULTKEY_JWT_SECRET is not set.",
    )
    JWT_ALGORITHM = os.getenv("VAULTKEY_JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("VAULTKEY_JWT_ACCESS_TOKEN_EXPIRES", "3600"))

    # ── PKI / Key storage ─────────────────────────────────────
    CA_CERT_PATH = os.getenv("VAULTKEY_CA_CERT_PATH", "keys/ca_cert.pem")
    CA_KEY_PATH = os.getenv("VAULTKEY_CA_KEY_PATH", "keys/ca_key.pem")
    PRIVATE_KEY_STORAGE_PATH = os.getenv("VAULTKEY_PRIVATE_KEY_STORAGE_PATH", "keys/{user_id}_private.pem")
    PRIVATE_KEY_PASSPHRASE = _get_env(
        "VAULTKEY_PRIVATE_KEY_PASSPHRASE",
        "dev-private-passphrase-change-me",
        "VAULTKEY_PRIVATE_KEY_PASSPHRASE is not set.",
    )

    # ── Vault encryption ──────────────────────────────────────
    VAULT_MASTER_PASSWORD = os.getenv("VAULTKEY_VAULT_PASSWORD", "dev-vault-password-change-in-prod")
    AES_KEY_LENGTH = 32
