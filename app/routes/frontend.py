from flask import Blueprint, render_template

frontend_bp = Blueprint("frontend", __name__, template_folder="../templates", static_folder="../static")


@frontend_bp.route("/")
def home():
    return render_template("index.html")


@frontend_bp.route("/register")
def register_page():
    return render_template("register.html")


@frontend_bp.route("/login")
def login_page():
    return render_template("login.html")


@frontend_bp.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@frontend_bp.route("/vault")
def vault_page():
    return render_template("vault.html")


@frontend_bp.route("/documents")
def documents_page():
    return render_template("documents.html")


@frontend_bp.route("/admin")
def admin_page():
    return render_template("admin.html")
