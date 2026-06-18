from .auth import auth_bp
from .vault import vault_bp
from .documents import documents_bp
from .admin import admin_bp
from .frontend import frontend_bp


def register_blueprints(app):
    app.register_blueprint(frontend_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
