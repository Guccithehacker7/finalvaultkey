import jwt
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import IntegrityError

from .. import db
from app.crypto import (
    generate_user_keypair,
    initialize_root_ca,
    issue_user_certificate,
    validate_certificate,
)
from app.models import Certificate, CertificateStatus, User
from app.utils.audit_logger import log_audit

auth_bp = Blueprint("auth", __name__)


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _jwt_payload(user: User) -> dict:
    return {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(seconds=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]),
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

        user = User.query.filter_by(id=payload.get("sub")).first()
        if not user:
            return jsonify({"message": "User not found"}), 401

        g.current_user = user
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    @token_required
    def wrapper(*args, **kwargs):
        user = g.current_user
        if user.role != "admin":
            return jsonify({"message": "Admin privileges required"}), 403
        return view_func(*args, **kwargs)

    return wrapper


def _store_user_private_key(private_key, user_id: str) -> str:
    private_key_template = current_app.config["PRIVATE_KEY_STORAGE_PATH"]
    storage_path = Path(private_key_template.format(user_id=user_id))
    storage_path.parent.mkdir(parents=True, exist_ok=True)
    passphrase = current_app.config["PRIVATE_KEY_PASSPHRASE"].encode("utf-8")

    with storage_path.open("wb") as key_fd:
        key_fd.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
        )

    return str(storage_path)


@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    payload = request.get_json(force=True)
    username = payload.get("username")
    email = payload.get("email")

    if not username or not email:
        return jsonify({"message": "username and email are required"}), 400

    ca_private_key, ca_certificate = initialize_root_ca(
        current_app.config["CA_KEY_PATH"], current_app.config["CA_CERT_PATH"]
    )

    user = User(username=username, email=email)
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
        public_key_pem=public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        status=CertificateStatus.ACTIVE,
        expiry_date=certificate.not_valid_after,
    )

    private_key_path = _store_user_private_key(private_key, str(user.id))
    db.session.add(certificate_record)
    db.session.commit()

    user_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    log_audit(
        action="REGISTER",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify(
        {
            "username": username,
            "email": email,
            "certificate_pem": cert_pem.decode("utf-8"),
            "public_key_pem": public_pem.decode("utf-8"),
            "private_key_pem": user_private_pem.decode("utf-8"),
        }
    ), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    payload = request.get_json(force=True)
    cert_pem = payload.get("certificate_pem")

    if not cert_pem:
        return jsonify({"message": "certificate_pem is required"}), 400

    try:
        root_ca_private_key, root_ca_certificate = initialize_root_ca(
            current_app.config["CA_KEY_PATH"], current_app.config["CA_CERT_PATH"]
        )
        certificate = validate_certificate(cert_pem.encode("utf-8"), root_ca_certificate)
    except ValueError as exc:
        log_audit(
            action="LOGIN_FAILURE",
            status="FAILURE",
            user_id=None,
            ip_address=_get_client_ip(),
        )
        return jsonify({"message": str(exc)}), 401

    serial_number = str(certificate.serial_number)
    certificate_record = Certificate.query.filter_by(serial_number=serial_number).first()
    if not certificate_record or certificate_record.status != CertificateStatus.ACTIVE:
        log_audit(
            action="LOGIN_FAILURE",
            status="FAILURE",
            user_id=certificate_record.user_id if certificate_record else None,
            ip_address=_get_client_ip(),
        )
        return jsonify({"message": "Certificate is not active or registered"}), 401

    user = User.query.get(certificate_record.user_id)
    token = generate_token(user)

    log_audit(
        action="LOGIN_SUCCESS",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify({"access_token": token}), 200
