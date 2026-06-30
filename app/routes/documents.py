import base64
import io
import uuid

from flask import Blueprint, current_app, g, jsonify, request, send_file

from .. import db
from app.crypto import (
    initialize_root_ca,
    load_user_private_key,
    sign_bytes,
    validate_certificate,
    verify_signature,
)
from app.models import Certificate, DocumentSignature, StoredDocument
from app.routes.auth import token_required
from app.utils.audit_logger import log_audit


documents_bp = Blueprint("documents", __name__)


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@documents_bp.route("/api/documents/sign", methods=["POST"])
@token_required
def sign_document():
    user = g.current_user
    payload = request.get_json(force=True)
    file_name = payload.get("file_name")
    document_hash = payload.get("document_hash")
    file_content_b64 = payload.get("file_content_base64")
    content_type = payload.get("content_type") or "application/octet-stream"

    if not file_name or not document_hash:
        return jsonify({"message": "file_name and document_hash are required"}), 400

    file_bytes = None
    if file_content_b64:
        try:
            file_bytes = base64.b64decode(file_content_b64)
        except Exception:
            return jsonify({"message": "Invalid file_content_base64"}), 400

    private_key_path = current_app.config["PRIVATE_KEY_STORAGE_PATH"].format(user_id=user.id)
    passphrase = current_app.config["PRIVATE_KEY_PASSPHRASE"].encode("utf-8")
    private_key = load_user_private_key(private_key_path, passphrase)
    signature = sign_bytes(private_key, document_hash.encode("utf-8"))
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    document_record = DocumentSignature(
        user_id=user.id,
        file_name=file_name,
        file_hash=document_hash,
        signature=signature,
    )
    db.session.add(document_record)
    db.session.flush()

    if file_bytes:
        db.session.add(
            StoredDocument(
                user_id=user.id,
                signature_id=document_record.id,
                original_name=file_name,
                content_type=content_type,
                file_data=file_bytes,
            )
        )

    db.session.commit()

    log_audit(
        action="DOCUMENT_SIGN",
        status="SUCCESS",
        user_id=user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify({
        "signature": signature_b64,
        "document_id": str(document_record.id),
        "download_available": bool(file_bytes),
        "download_url": f"/api/documents/{document_record.id}/download",
    }), 200


@documents_bp.route("/api/documents/<document_id>/download", methods=["GET"])
@token_required
def download_document(document_id):
    user = g.current_user

    try:
        doc_uuid = uuid.UUID(document_id)
    except ValueError:
        return jsonify({"message": "Invalid document id"}), 400

    document_record = DocumentSignature.query.filter_by(id=doc_uuid, user_id=user.id).first()
    if not document_record:
        return jsonify({"message": "Document not found"}), 404

    if document_record.stored_document:
        stored = document_record.stored_document
        return send_file(
            io.BytesIO(stored.file_data),
            download_name=stored.original_name or document_record.file_name,
            as_attachment=True,
            mimetype=stored.content_type or "application/octet-stream",
        )

    signature_text = "\n".join([
        f"File Name: {document_record.file_name}",
        f"Document Hash (SHA-256): {document_record.file_hash}",
        f"Signature (Base64): {base64.b64encode(document_record.signature).decode('utf-8')}",
    ])
    filename = (document_record.file_name.rsplit('.', 1)[0] if '.' in document_record.file_name else document_record.file_name) or "document"
    return send_file(
        io.BytesIO(signature_text.encode("utf-8")),
        download_name=f"{filename}_signature.txt",
        as_attachment=True,
        mimetype="text/plain",
    )


@documents_bp.route("/api/documents/verify", methods=["POST"])
def verify_document():
    payload = request.get_json(force=True)
    document_hash = payload.get("document_hash")
    signature_b64 = payload.get("signature")
    certificate_pem = payload.get("certificate_pem")

    if not document_hash or not signature_b64 or not certificate_pem:
        return jsonify({"message": "document_hash, signature, and certificate_pem are required"}), 400

    try:
        root_ca_private_key, root_ca_certificate = initialize_root_ca(
            current_app.config["CA_KEY_PATH"], current_app.config["CA_CERT_PATH"]
        )
        certificate = validate_certificate(certificate_pem.encode("utf-8"), root_ca_certificate)
    except Exception as exc:
        return jsonify({"message": f"Certificate validation failed: {exc}"}), 400

    signature = base64.b64decode(signature_b64)
    valid = verify_signature(certificate.public_key(), signature, document_hash.encode("utf-8"))
    certificate_record = Certificate.query.filter_by(serial_number=str(certificate.serial_number)).first()

    log_audit(
        action="DOCUMENT_VERIFY",
        status="SUCCESS" if valid else "FAILURE",
        user_id=certificate_record.user_id if certificate_record else None,
        ip_address=_get_client_ip(),
    )

    return jsonify({"valid": valid}), 200
