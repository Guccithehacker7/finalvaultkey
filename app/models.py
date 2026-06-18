import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy.dialects.postgresql import UUID

from . import db


def utcnow() -> datetime:
    """Return the current time in UTC for timestamp defaults."""
    return datetime.now(timezone.utc)


class CertificateStatus(Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    role = db.Column(db.String(32), nullable=False, default="user")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    certificates = db.relationship(
        "Certificate",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    vault_entries = db.relationship(
        "VaultEntry",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    document_signatures = db.relationship(
        "DocumentSignature",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    audit_logs = db.relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<User username={self.username} email={self.email} role={self.role}>"


class Certificate(db.Model):
    __tablename__ = "certificate"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=False)
    serial_number = db.Column(db.String(128), unique=True, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.Enum(CertificateStatus, native_enum=False, name="certificate_status"),
        nullable=False,
        default=CertificateStatus.ACTIVE,
    )
    expiry_date = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship("User", back_populates="certificates")

    def __repr__(self) -> str:
        return f"<Certificate serial={self.serial_number} status={self.status.value}>"


class VaultEntry(db.Model):
    __tablename__ = "vault_entry"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=False)
    site_name = db.Column(db.String(256), nullable=False)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="vault_entries")

    def __repr__(self) -> str:
        return f"<VaultEntry site_name={self.site_name} user_id={self.user_id}>"


class DocumentSignature(db.Model):
    __tablename__ = "document_signature"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=False)
    file_name = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="document_signatures")

    def __repr__(self) -> str:
        return f"<DocumentSignature file_name={self.file_name} user_id={self.user_id}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(128), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(32), nullable=False)

    user = db.relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action} status={self.status} ip={self.ip_address}>"
