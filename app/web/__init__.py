import json

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    app.jinja_env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

    from .routes import bp
    app.register_blueprint(bp)

    return app