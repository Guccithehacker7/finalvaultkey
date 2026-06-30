import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from . import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Cross-database UUID type ──────────────────────────────────────────────────
# Uses native UUID on PostgreSQL; VARCHAR(36) on SQLite / everything else.
class GUID(TypeDecorator):
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import UUID
            return dialect.type_descriptor(UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


# ── Enums ─────────────────────────────────────────────────────────────────────
class CertificateStatus(Enum):
    ACTIVE  = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


# ── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "user"

    id           = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    username     = db.Column(db.String(150), unique=True, nullable=False)
    email        = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role         = db.Column(db.String(32),  nullable=False, default="user")
    created_at   = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    certificates       = db.relationship("Certificate",      back_populates="user", cascade="all, delete-orphan", lazy="select")
    vault_entries      = db.relationship("VaultEntry",       back_populates="user", cascade="all, delete-orphan", lazy="select")
    document_signatures = db.relationship("DocumentSignature", back_populates="user", cascade="all, delete-orphan", lazy="select")
    stored_documents    = db.relationship("StoredDocument",   back_populates="user", cascade="all, delete-orphan", lazy="select")
    audit_logs         = db.relationship("AuditLog",         back_populates="user", cascade="all, delete-orphan", lazy="select")

    def __repr__(self):
        return f"<User {self.username} role={self.role}>"


class Certificate(db.Model):
    __tablename__ = "certificate"

    id              = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id         = db.Column(GUID(), db.ForeignKey("user.id"), nullable=False)
    serial_number   = db.Column(db.String(128), unique=True, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=True)
    public_key_pem  = db.Column(db.Text, nullable=False)
    status          = db.Column(
        db.Enum(CertificateStatus, native_enum=False, name="certificate_status"),
        nullable=False,
        default=CertificateStatus.ACTIVE,
    )
    expiry_date     = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship("User", back_populates="certificates")

    def __repr__(self):
        return f"<Certificate serial={self.serial_number} status={self.status.value}>"


class VaultEntry(db.Model):
    __tablename__ = "vault_entry"

    id                = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id           = db.Column(GUID(), db.ForeignKey("user.id"), nullable=False)
    site_name         = db.Column(db.String(256), nullable=False)
    username_hint     = db.Column(db.String(256), nullable=True)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    created_at        = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="vault_entries")

    def __repr__(self):
        return f"<VaultEntry site={self.site_name}>"


class DocumentSignature(db.Model):
    __tablename__ = "document_signature"

    id         = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id    = db.Column(GUID(), db.ForeignKey("user.id"), nullable=False)
    file_name  = db.Column(db.String(256), nullable=False)
    file_hash  = db.Column(db.String(128), nullable=False)
    signature  = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="document_signatures")
    stored_document = db.relationship("StoredDocument", back_populates="signature", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DocumentSignature file={self.file_name}>"


class StoredDocument(db.Model):
    __tablename__ = "stored_document"

    id           = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id      = db.Column(GUID(), db.ForeignKey("user.id"), nullable=False)
    signature_id = db.Column(GUID(), db.ForeignKey("document_signature.id"), nullable=False, unique=True)
    original_name = db.Column(db.String(256), nullable=False)
    content_type = db.Column(db.String(128), nullable=False, default="application/octet-stream")
    file_data    = db.Column(db.LargeBinary, nullable=False)
    created_at   = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="stored_documents")
    signature = db.relationship("DocumentSignature", back_populates="stored_document")

    def __repr__(self):
        return f"<StoredDocument file={self.original_name}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id         = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id    = db.Column(GUID(), db.ForeignKey("user.id"), nullable=True)
    action     = db.Column(db.String(128), nullable=False)
    timestamp  = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    status     = db.Column(db.String(32), nullable=False)

    user = db.relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} {self.status}>"


class RevokedToken(db.Model):
    __tablename__ = "revoked_token"

    id         = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    jti        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id    = db.Column(GUID(), db.ForeignKey("user.id"), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    def __repr__(self):
        return f"<RevokedToken jti={self.jti}>"
