import uuid as _uuid
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from .. import db
from app.crypto import (
    generate_user_keypair,
    initialize_root_ca,
    issue_user_certificate,
    validate_certificate,
)
from app.models import (
    AuditLog,
    Certificate,
    CertificateStatus,
    DocumentSignature,
    RevokedToken,
    User,
    VaultEntry,
)
from app.utils.audit_logger import log_audit

auth_bp = Blueprint("auth", __name__)


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _cert_expiry(certificate):
    try:
        return certificate.not_valid_after_utc
    except AttributeError:
        return certificate.not_valid_after.replace(tzinfo=timezone.utc)


def _jwt_payload(user: User) -> dict:
    return {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "jti": str(_uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]),
    }


def generate_token(user: User) -> str:
    return jwt.encode(
        _jwt_payload(user),
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def token_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"message": "Missing authorization header"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=[current_app.config["JWT_ALGORITHM"]],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.PyJWTError:
            return jsonify({"message": "Invalid token"}), 401

        jti = payload.get("jti")
        if jti and RevokedToken.query.filter_by(jti=jti).first():
            return jsonify({"message": "Token has been revoked. Please log in again."}), 401

        user = User.query.filter_by(id=payload.get("sub")).first()
        if not user:
            return jsonify({"message": "User not found"}), 401

        g.current_user = user
        g.token_jti = jti
        g.token_exp = payload.get("exp")
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    @token_required
    def wrapper(*args, **kwargs):
        if g.current_user.role != "admin":
            return jsonify({"message": "Admin privileges required"}), 403
        return view_func(*args, **kwargs)

    return wrapper


def _store_user_private_key(private_key, user_id: str) -> str:
    private_key_template = current_app.config["PRIVATE_KEY_STORAGE_PATH"]
    storage_path = Path(private_key_template.format(user_id=user_id))
    storage_path.parent.mkdir(parents=True, exist_ok=True)
    passphrase = current_app.config["PRIVATE_KEY_PASSPHRASE"].encode("utf-8")
    with storage_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
        )
    return str(storage_path)


# ── Register ─────────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"message": "username, email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"message": "Password must be at least 8 characters"}), 400

    ca_private_key, ca_certificate = initialize_root_ca(
        current_app.config["CA_KEY_PATH"], current_app.config["CA_CERT_PATH"]
    )

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
    )
    db.session.add(user)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Username or email already exists"}), 409

    private_key, public_key = generate_user_keypair()
    certificate = issue_user_certificate(user, public_key, ca_private_key, ca_certificate)
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    certificate_record = Certificate(
        user_id=user.id,
        serial_number=str(certificate.serial_number),
        certificate_pem=cert_pem.decode("utf-8"),
        public_key_pem=public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        status=CertificateStatus.ACTIVE,
        expiry_date=_cert_expiry(certificate),
    )

    _store_user_private_key(private_key, str(user.id))
    db.session.add(certificate_record)
    db.session.commit()

    user_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    log_audit(action="REGISTER", status="SUCCESS", user_id=user.id, ip_address=_get_client_ip())

    return jsonify({
        "username": username,
        "email": email,
        "certificate_pem": cert_pem.decode("utf-8"),
        "public_key_pem": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        "private_key_pem": user_private_pem.decode("utf-8"),
    }), 201


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    cert_pem = data.get("certificate_pem") or ""

    # ── Method 1: email + password ────────────────────────────────────────────
    if email and password:
        user = User.query.filter_by(email=email).first()
        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            log_audit(
                action="LOGIN_FAILURE", status="FAILURE",
                user_id=user.id if user else None,
                ip_address=_get_client_ip(),
            )
            return jsonify({"message": "Invalid email or password"}), 401

        token = generate_token(user)
        log_audit(action="LOGIN_SUCCESS", status="SUCCESS", user_id=user.id, ip_address=_get_client_ip())
        return jsonify({"access_token": token}), 200

    # ── Method 2: certificate PEM ─────────────────────────────────────────────
    if cert_pem:
        try:
            _, root_ca_certificate = initialize_root_ca(
                current_app.config["CA_KEY_PATH"], current_app.config["CA_CERT_PATH"]
            )
            certificate = validate_certificate(cert_pem.encode("utf-8"), root_ca_certificate)
        except ValueError as exc:
            log_audit(action="LOGIN_FAILURE", status="FAILURE", user_id=None, ip_address=_get_client_ip())
            return jsonify({"message": str(exc)}), 401

        cert_record = Certificate.query.filter_by(serial_number=str(certificate.serial_number)).first()
        if not cert_record or cert_record.status != CertificateStatus.ACTIVE:
            log_audit(
                action="LOGIN_FAILURE", status="FAILURE",
                user_id=cert_record.user_id if cert_record else None,
                ip_address=_get_client_ip(),
            )
            return jsonify({"message": "Certificate is not active or not registered"}), 401

        user = db.session.get(User, cert_record.user_id)
        token = generate_token(user)
        log_audit(action="LOGIN_SUCCESS", status="SUCCESS", user_id=user.id, ip_address=_get_client_ip())
        return jsonify({"access_token": token}), 200

    return jsonify({"message": "email + password, or certificate_pem is required"}), 400


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/logout", methods=["POST"])
@token_required
def logout():
    jti = g.token_jti
    exp = g.token_exp
    if jti:
        expires_at = (
            datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp
            else datetime.now(timezone.utc) + timedelta(seconds=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"])
        )
        db.session.add(RevokedToken(jti=jti, user_id=g.current_user.id, expires_at=expires_at))
        db.session.commit()

    log_audit(action="LOGOUT", status="SUCCESS", user_id=g.current_user.id, ip_address=_get_client_ip())
    return jsonify({"message": "Logged out successfully"}), 200


# ── Me / Dashboard data ────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/me", methods=["GET"])
@token_required
def me():
    user = g.current_user

    cert = (
        Certificate.query
        .filter_by(user_id=user.id, status=CertificateStatus.ACTIVE)
        .order_by(Certificate.expiry_date.desc())
        .first()
    )

    vault_count = VaultEntry.query.filter_by(user_id=user.id).count()
    doc_count = DocumentSignature.query.filter_by(user_id=user.id).count()

    recent_logs = (
        AuditLog.query
        .filter_by(user_id=user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(8)
        .all()
    )

    return jsonify({
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "certificate": {
            "serial_number": cert.serial_number,
            "certificate_pem": cert.certificate_pem,
            "public_key_pem": cert.public_key_pem,
            "status": cert.status.value,
            "expiry_date": cert.expiry_date.isoformat(),
        } if cert else None,
        "stats": {
            "vault_entries": vault_count,
            "signed_documents": doc_count,
        },
        "recent_activity": [
            {
                "action": log.action,
                "status": log.status,
                "timestamp": log.timestamp.isoformat(),
                "ip_address": log.ip_address,
            }
            for log in recent_logs
        ],
    }), 200
