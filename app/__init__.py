from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from .config import Config

db = SQLAlchemy()
migrate = Migrate()

from .routes import register_blueprints


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    register_blueprints(app)

    # Auto-create tables on first run (works for both SQLite and PostgreSQL)
    with app.app_context():
        from . import models  # ensure all models are registered
        db.create_all()

    @app.route("/health")
    def health_check():
        return {"status": "ok", "message": "VaultKey is running"}, 200

    return app
