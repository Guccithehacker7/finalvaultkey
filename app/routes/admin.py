from flask import Blueprint, g, jsonify, request

from app.models import AuditLog, Certificate, CertificateStatus
from app.routes.auth import admin_required
from app.utils.audit_logger import log_audit

admin_bp = Blueprint("admin", __name__)


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@admin_bp.route("/api/admin/revoke", methods=["POST"])
@admin_required
def revoke_certificate():
    payload = request.get_json(force=True)
    serial_number = payload.get("serial_number")

    if not serial_number:
        return jsonify({"message": "serial_number is required"}), 400

    certificate = Certificate.query.filter_by(serial_number=serial_number).first()
    if not certificate:
        return jsonify({"message": "Certificate not found"}), 404

    certificate.status = CertificateStatus.REVOKED

    from app import db

    db.session.commit()

    log_audit(
        action="CERT_REVOKED",
        status="SUCCESS",
        user_id=g.current_user.id,
        ip_address=_get_client_ip(),
    )

    return jsonify({"message": "Certificate revoked successfully"}), 200


@admin_bp.route("/api/admin/audit-logs", methods=["GET"])
@admin_required
def list_audit_logs():
    limit = request.args.get("limit", default=100, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    results = [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "action": log.action,
            "status": log.status,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]
    return jsonify({"audit_logs": results}), 200
