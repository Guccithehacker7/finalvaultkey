from .. import db
from app.models import AuditLog


def log_audit(action: str, status: str, user_id, ip_address: str) -> None:
    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        status=status,
        ip_address=ip_address or "unknown",
    )
    db.session.add(audit_entry)
    db.session.commit()
