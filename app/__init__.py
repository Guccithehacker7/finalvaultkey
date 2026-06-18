from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from .config import Config

# Initialize extensions without binding to an app. This supports the app factory pattern.
db = SQLAlchemy()
migrate = Migrate()

from .routes import register_blueprints


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    register_blueprints(app)

    @app.route("/health")
    def health_check():
        return "VaultKey Running Successfully 🔐", 200

    return app
