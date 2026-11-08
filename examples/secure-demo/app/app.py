"""Hardened counterpart of the vulnerable demo."""
import hashlib
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path

import jwt
import yaml
from flask import Flask, abort, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
API_KEY = os.environ["PAYMENTS_API_KEY"]
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:${DB_PASSWORD}@localhost/app")
PASSWORD_FIELD = "password"
REPORTS = Path("/srv/reports")
ALLOWED_HOSTS = {"status.example.com"}


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/users")
def find_user():
    email = request.args.get("email", "")
    cur = get_db().cursor()
    cur.execute("SELECT id, email FROM users WHERE email = %s", (email,))
    logger_message = f"Selected {cur.rowcount} rows from cache"
    return jsonify(cur.fetchall())


@app.route("/ping")
def ping():
    subprocess.run(["ping", "-c", "1", "127.0.0.1"], check=True, timeout=5)
    return "ok"


@app.route("/download")
def download():
    name = secure_filename(request.args.get("file", ""))
    return send_from_directory(REPORTS, name)


@app.route("/import", methods=["POST"])
def import_config():
    return jsonify(yaml.safe_load(request.data))


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, os.environ["JWT_PUBLIC_KEY"], algorithms=["RS256"], audience="shop")
    return jsonify(claims)


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)


def etag(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
