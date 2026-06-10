import logging
import os
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

VALID_USERNAME = os.environ.get("VALID_USERNAME", "admin")
VALID_PASSWORD = os.environ.get("VALID_PASSWORD", "secret123")


def log_login_attempt(username: str, success: bool, client_ip: str) -> None:
    status = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(
        "%s timestamp=%s username=%s ip=%s",
        status,
        timestamp,
        username,
        client_ip,
    )


@app.route("/")
def home():
    return jsonify(
        {
            "message": "CST8919 Lab 2 - Login Threat Detection Demo",
            "endpoints": {"POST /login": "Submit JSON body with username and password"},
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if username == VALID_USERNAME and password == VALID_PASSWORD:
        log_login_attempt(username, success=True, client_ip=client_ip)
        return jsonify({"message": "Login successful"}), 200

    log_login_attempt(username, success=False, client_ip=client_ip)
    return jsonify({"message": "Invalid credentials"}), 401


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
