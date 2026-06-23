from flask import Blueprint, current_app, g, jsonify, request

from .. import db
from app.crypto import decrypt_payload, encrypt_payload
from app.models import VaultEntry
from app.routes.auth import token_required
from app.utils.audit_logger import log_audit

vault_bp = Blueprint("vault", __name__)


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@vault_bp.route("/api/vault", methods=["GET"])
@token_required
def list_vault_entries():
    user = g.current_user
    entries = (
        VaultEntry.query.filter_by(user_id=user.id)
        .order_by(VaultEntry.created_at.desc())
        .all()
    )
    results = [
        {
            "id": str(entry.id),
            "site_name": entry.site_name,
            "username_hint": entry.username_hint or "",
            "created_at": entry.created_at.isoformat(),
        }
        for entry in entries
    ]
    log_audit(
        action="VAULT_ACCESS",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )
    return jsonify({"vault_entries": results}), 200


@vault_bp.route("/api/vault/<entry_id>", methods=["GET"])
@token_required
def get_vault_entry(entry_id):
    user = g.current_user
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({"message": "Vault entry not found"}), 404

    try:
        plaintext = decrypt_payload(
            payload=entry.encrypted_payload,
            master_password=current_app.config["VAULT_MASTER_PASSWORD"],
        )
    except Exception:
        return jsonify({"message": "Failed to decrypt vault entry"}), 500

    log_audit(
        action="VAULT_RETRIEVE",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify(
        {
            "id": str(entry.id),
            "site_name": entry.site_name,
            "password": plaintext.decode("utf-8"),
            "created_at": entry.created_at.isoformat(),
        }
    ), 200


@vault_bp.route("/api/vault", methods=["POST"])
@token_required
def create_vault_entry():
    user = g.current_user
    payload = request.get_json(force=True)
    site_name = payload.get("site_name")
    password = payload.get("password")
    username_hint = payload.get("username_hint") or ""

    if not site_name or not password:
        return jsonify({"message": "site_name and password are required"}), 400

    encrypted_payload = encrypt_payload(
        plaintext=password.encode("utf-8"),
        master_password=current_app.config["VAULT_MASTER_PASSWORD"],
    )

    vault_entry = VaultEntry(
        user_id=user.id,
        site_name=site_name,
        username_hint=username_hint,
        encrypted_payload=encrypted_payload,
    )
    db.session.add(vault_entry)
    db.session.commit()

    log_audit(
        action="VAULT_CREATE",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify({"message": "Vault entry stored securely", "entry_id": str(vault_entry.id)}), 201


@vault_bp.route("/api/vault/<entry_id>", methods=["DELETE"])
@token_required
def delete_vault_entry(entry_id):
    user = g.current_user
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({"message": "Vault entry not found"}), 404

    db.session.delete(entry)
    db.session.commit()

    log_audit(
        action="VAULT_DELETE",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify({"message": "Vault entry deleted"}), 200
