"""A deliberately small task-tracking API used to demonstrate a DevSecOps pipeline.

The application itself applies several secure-coding practices that the pipeline
then verifies:

* parameterised SQL (no string concatenation)
* strict input validation and a request-size limit
* API-key authentication with constant-time comparison; the key comes from the
  environment and is never stored in code
* security response headers and no stack traces in error responses
* debug mode is never enabled
"""

from __future__ import annotations

import hmac
import os
import sqlite3
from typing import Any, Dict, Optional

from flask import Flask, g, jsonify, request

MAX_TITLE = 100
MAX_DESCRIPTION = 1000

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        # Default next to the code, not in a shared, predictable /tmp location
        # (a symlink-attack risk that Bandit rule B108 flags). Containers set DB_PATH explicitly.
        DB_PATH=os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "tasks.db")),
        API_KEY=os.environ.get("API_KEY", ""),
        MAX_CONTENT_LENGTH=16 * 1024,  # reject oversized bodies early
    )
    if test_config:
        app.config.update(test_config)

    if not app.config["API_KEY"]:
        # Fail closed: never start an unauthenticated API by accident.
        raise RuntimeError("API_KEY environment variable must be set")

    # ---- database helpers -------------------------------------------------
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc: Optional[BaseException]) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().execute(
            "CREATE TABLE IF NOT EXISTS tasks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '')"
        )
        get_db().commit()

    # ---- cross-cutting concerns ------------------------------------------
    @app.before_request
    def require_api_key():
        if request.path == "/healthz":
            return None
        supplied = request.headers.get("X-API-Key", "")
        # compare_digest avoids leaking information through timing differences
        if not hmac.compare_digest(supplied.encode(), app.config["API_KEY"].encode()):
            return jsonify(error="unauthorized"), 401
        return None

    @app.after_request
    def add_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error="request too large"), 413

    @app.errorhandler(500)
    def server_error(_e):
        # Generic message only: never leak internals to the client.
        return jsonify(error="internal server error"), 500

    # ---- routes -----------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/tasks")
    def list_tasks():
        rows = get_db().execute("SELECT id, title, description FROM tasks ORDER BY id").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/tasks/<int:task_id>")
    def get_task(task_id: int):
        row = get_db().execute(
            "SELECT id, title, description FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            return jsonify(error="not found"), 404
        return jsonify(dict(row))

    @app.post("/tasks")
    def create_task():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="body must be a JSON object"), 400
        title = data.get("title")
        description = data.get("description", "")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= MAX_TITLE:
            return jsonify(error=f"title must be a string of 1-{MAX_TITLE} characters"), 400
        if not isinstance(description, str) or len(description) > MAX_DESCRIPTION:
            return jsonify(error=f"description must be a string up to {MAX_DESCRIPTION} characters"), 400
        db = get_db()
        cur = db.execute(
            "INSERT INTO tasks (title, description) VALUES (?, ?)", (title.strip(), description)
        )
        db.commit()
        return jsonify(id=cur.lastrowid, title=title.strip(), description=description), 201

    @app.delete("/tasks/<int:task_id>")
    def delete_task(task_id: int):
        db = get_db()
        cur = db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify(error="not found"), 404
        return "", 204

    return app
