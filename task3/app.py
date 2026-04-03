#!/usr/bin/env python3
"""
=============================================================
  TASK 3 — JWT WEB APPLICATION — Flask Backend
  
  Install: pip3 install flask flask-jwt-extended --break-system-packages
  Usage:   python3 app.py
  Open:    http://localhost:5000
=============================================================
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from datetime import timedelta
import datetime
import os
import hashlib
import json

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")

app.config["JWT_SECRET_KEY"]               = "lab-secret-key-CHANGE-IN-PRODUCTION"
app.config["JWT_ACCESS_TOKEN_EXPIRES"]     = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"]    = timedelta(days=7)
app.config["JWT_TOKEN_LOCATION"]           = ["headers"]
app.config["JWT_HEADER_NAME"]              = "Authorization"
app.config["JWT_HEADER_TYPE"]              = "Bearer"

jwt = JWTManager(app)

# ── In-memory stores ─────────────────────────────────────────
# Format: { username: { password_hash, email, role, created_at } }
users_db: dict = {}

# Token blacklist (for logout / revocation)
revoked_tokens: set = set()


# ── Helpers ──────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def make_response(data: dict, status: int = 200):
    resp = jsonify(data)
    resp.status_code = status
    return resp


# ── JWT error handlers ────────────────────────────────────────
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return make_response({"error": "Token has expired", "code": "TOKEN_EXPIRED"}, 401)

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return make_response({"error": f"Invalid token: {reason}", "code": "INVALID_TOKEN"}, 422)

@jwt.unauthorized_loader
def missing_token_callback(reason):
    return make_response({"error": "Authorization token required", "code": "MISSING_TOKEN"}, 401)

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return make_response({"error": "Token has been revoked (logged out)", "code": "TOKEN_REVOKED"}, 401)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload.get("jti") in revoked_tokens


# ════════════════════════════════════════════════════════════
#  FRONTEND ROUTE
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


# ════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/api/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    email    = data.get("email", "").strip()
    role     = data.get("role", "user").strip()

    # Validation
    if not username or not password:
        return make_response({"error": "Username and password are required"}, 400)
    if len(password) < 6:
        return make_response({"error": "Password must be at least 6 characters"}, 400)
    if username in users_db:
        return make_response({"error": f"Username '{username}' already taken"}, 409)
    if role not in ("user", "admin"):
        role = "user"

    users_db[username] = {
        "password_hash": hash_password(password),
        "email":         email or f"{username}@lab.local",
        "role":          role,
        "created_at":    datetime.datetime.utcnow().isoformat(),
    }

    return make_response({
        "message": f"User '{username}' registered successfully",
        "username": username,
        "role": role,
    }, 201)


@app.route("/api/login", methods=["POST"])
def login():
    """Login and receive JWT access + refresh tokens."""
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = users_db.get(username)
    if not user or user["password_hash"] != hash_password(password):
        return make_response({"error": "Invalid username or password"}, 401)

    # Create tokens with extra claims
    additional_claims = {
        "role":  user["role"],
        "email": user["email"],
    }
    access_token  = create_access_token(identity=username, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=username)

    return make_response({
        "message":       f"Welcome back, {username}!",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "Bearer",
        "expires_in":    "15 minutes",
        "user": {
            "username": username,
            "email":    user["email"],
            "role":     user["role"],
        },
    }, 200)


@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Use refresh token to get a new access token."""
    current_user = get_jwt_identity()
    user = users_db.get(current_user, {})
    additional_claims = {
        "role":  user.get("role", "user"),
        "email": user.get("email", ""),
    }
    new_access_token = create_access_token(identity=current_user, additional_claims=additional_claims)
    return make_response({
        "access_token": new_access_token,
        "message":      "Token refreshed",
    }, 200)


@app.route("/api/logout", methods=["DELETE"])
@jwt_required()
def logout():
    """Revoke the current token (add to blocklist)."""
    jti = get_jwt().get("jti")
    revoked_tokens.add(jti)
    return make_response({"message": "Logged out. Token revoked."}, 200)


# ════════════════════════════════════════════════════════════
#  PROTECTED ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/api/protected", methods=["GET"])
@jwt_required()
def protected():
    """Requires any valid JWT token."""
    current_user = get_jwt_identity()
    claims       = get_jwt()
    return make_response({
        "message":      f"Hello {current_user}! You accessed a protected route.",
        "user":         current_user,
        "role":         claims.get("role"),
        "token_issued": claims.get("iat"),
        "token_expiry": claims.get("exp"),
    }, 200)


@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    """Return logged-in user's profile."""
    current_user = get_jwt_identity()
    user = users_db.get(current_user)
    if not user:
        return make_response({"error": "User not found"}, 404)
    return make_response({
        "username":   current_user,
        "email":      user["email"],
        "role":       user["role"],
        "created_at": user["created_at"],
    }, 200)


@app.route("/api/admin", methods=["GET"])
@jwt_required()
def admin_only():
    """Only accessible by admin-role users."""
    claims = get_jwt()
    if claims.get("role") != "admin":
        return make_response({
            "error": "Admin access required",
            "your_role": claims.get("role"),
        }, 403)
    return make_response({
        "message":  "Welcome to the admin panel!",
        "users":    [
            {"username": u, "role": d["role"], "email": d["email"]}
            for u, d in users_db.items()
        ],
        "revoked_tokens_count": len(revoked_tokens),
    }, 200)


# ════════════════════════════════════════════════════════════
#  PUBLIC ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/api/public", methods=["GET"])
def public():
    """No token required."""
    return make_response({
        "message": "This is a PUBLIC endpoint — no token needed.",
        "server_time": datetime.datetime.utcnow().isoformat(),
        "registered_users": len(users_db),
    }, 200)


@app.route("/api/token/decode", methods=["POST"])
def decode_token_info():
    """
    Educational endpoint: decode and explain a JWT token
    (does NOT verify signature — for learning only).
    """
    import base64

    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not token:
        return make_response({"error": "No token provided"}, 400)

    parts = token.split(".")
    if len(parts) != 3:
        return make_response({"error": "Not a valid JWT (needs 3 dot-separated parts)"}, 400)

    def decode_part(part):
        padding = 4 - len(part) % 4
        part   += "=" * (padding % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(part))
        except Exception:
            return {"raw": part}

    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    exp_ts  = payload.get("exp")
    iat_ts  = payload.get("iat")
    is_exp  = False
    if exp_ts:
        is_exp = datetime.datetime.utcfromtimestamp(exp_ts) < datetime.datetime.utcnow()

    return make_response({
        "structure": {
            "header_b64":    parts[0],
            "payload_b64":   parts[1],
            "signature_b64": parts[2],
        },
        "decoded": {
            "header":  header,
            "payload": payload,
        },
        "analysis": {
            "algorithm":  header.get("alg"),
            "type":       header.get("typ"),
            "subject":    payload.get("sub"),
            "identity":   payload.get("sub"),
            "issued_at":  datetime.datetime.utcfromtimestamp(iat_ts).isoformat() if iat_ts else None,
            "expires_at": datetime.datetime.utcfromtimestamp(exp_ts).isoformat() if exp_ts else None,
            "is_expired": is_exp,
            "role":       payload.get("role"),
        },
        "security_note": (
            "This endpoint decodes without verifying the signature. "
            "In production, ALWAYS verify before trusting any JWT claim."
        ),
    }, 200)


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  JWT Web Application — Lab Server")
    print("=" * 55)
    print(f"  URL  : http://localhost:5000")
    print(f"  API  : http://localhost:5000/api/")
    print("=" * 55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)