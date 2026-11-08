"""Intentionally vulnerable Flask demo. Fictitious data only. DO NOT DEPLOY."""
import hashlib
import os
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

# Fictitious credentials generated for this demo (not valid anywhere).
PAYMENTS_API_KEY = "q8ZtLw3Rk9Pm2Xv7Nc4Bh6JdT1"
DATABASE_URL = "postgresql://demo_user:Tr0ub4dor-Demo-77@db.internal:5432/shop"
JWT_SECRET = os.environ.get("JWT_SECRET", "")


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/users")
def find_user():
    email = request.args.get("email")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, email FROM users WHERE email = '{email}'")
    return jsonify(cur.fetchall())


@app.route("/users/safe")
def find_user_safe():
    email = request.args.get("email")
    cur = get_db().cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return jsonify(cur.fetchall())


@app.route("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    # Any authenticated user can read any invoice: no ownership check (IDOR).
    cur = get_db().cursor()
    cur.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    return jsonify(cur.fetchone())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/download")
def download():
    name = request.args.get("file")
    return send_file(os.path.join("/srv/reports", name))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.load(request.data)
    return jsonify(config)


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = jwt.decode(token, options={"verify_signature": False})
    return jsonify(claims)


def register(username, password):
    password_hash = hashlib.md5(password.encode()).hexdigest()
    reset_token = str(random.randint(100000, 999999))
    return username, password_hash, reset_token


def cache_key(payload: bytes) -> str:
    # Non-security use: cache key only.
    return hashlib.md5(payload).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
