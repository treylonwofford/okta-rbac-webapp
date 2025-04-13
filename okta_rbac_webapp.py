# okta_rbac_webapp.py
# Author: Treylon Wofford
# Demo Project: Okta + Role-Based Access Control for a Python Web App
# Description: A simple Flask application that integrates with Okta for authentication
#              and uses Role-Based Access Control (RBAC) to secure endpoints.

from flask import Flask, redirect, url_for, session, request, jsonify
from functools import wraps
import os
import jwt
import requests
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev_secret_key")  # Change in production

# === Okta Configuration ===
OKTA_DOMAIN = os.environ.get("OKTA_DOMAIN")  # e.g., "dev-123456.okta.com"
CLIENT_ID = os.environ.get("OKTA_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OKTA_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("OKTA_REDIRECT_URI", "http://localhost:5000/callback")

# OpenID Connect endpoints
AUTHORIZATION_BASE_URL = f"https://{OKTA_DOMAIN}/oauth2/default/v1/authorize"
TOKEN_URL = f"https://{OKTA_DOMAIN}/oauth2/default/v1/token"
USERINFO_URL = f"https://{OKTA_DOMAIN}/oauth2/default/v1/userinfo"

# === Role-Based Access Control Decorator ===
def requires_role(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = session.get("user")
            if not user or role not in user.get("roles", []):
                return jsonify({"error": "Access Denied: Insufficient role"}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

# === Routes ===
@app.route("/")
def index():
    return "<h1>Welcome to the Okta RBAC Demo</h1><a href='/login'>Login</a>"

@app.route("/login")
def login():
    # Redirect to Okta login page
    query_params = urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": "dummy_state",
        "nonce": "dummy_nonce"
    })
    return redirect(f"{AUTHORIZATION_BASE_URL}?{query_params}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    # Exchange code for access token
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(TOKEN_URL, data=data, headers=headers)
    token_json = token_response.json()
    id_token = token_json.get("id_token")

    # Decode ID token
    decoded_token = jwt.decode(id_token, options={"verify_signature": False})

    # Store user info and roles (simulate Okta group claims for demo)
    session["user"] = {
        "name": decoded_token.get("name"),
        "email": decoded_token.get("email"),
        "roles": decoded_token.get("groups", ["viewer"])  # default to viewer role
    }

    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    return f"<h2>Welcome {user['name']}</h2><p>Your roles: {', '.join(user['roles'])}</p>"

@app.route("/admin")
@requires_role("admin")
def admin_panel():
    return "<h1>Admin Panel</h1><p>Only users with 'admin' role can see this.</p>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# === Run App ===
if __name__ == '__main__':
    app.run(debug=True)
