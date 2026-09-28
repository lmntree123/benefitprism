import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

KAISER_AUTHORIZE_URL = (
    "https://kpx-service-bus.kp.org/service/kpx/v1/oauth2/authorize"
)
KAISER_TOKEN_URL = (
    "https://kpx-service-bus.kp.org/service/kpx/v1/oauth2/token"
)

SCOPE = (
    "patient/*.read launch/patient offline_access "
    "ExplanationOfBenefit sandbox"
)


def create_pkce():
    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    return verifier, challenge


@app.route("/")
def home():
    return """
    <h1>BenefitPrism</h1>
    <p>Kaiser Patient Access API sandbox integration.</p>
    <p><a href="/login">Connect to Kaiser Sandbox</a></p>
    """


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/login")
def login():
    client_id = os.environ.get("KAISER_CLIENT_ID")
    redirect_uri = os.environ.get("KAISER_REDIRECT_URI")

    if not client_id or not redirect_uri:
        return "Kaiser OAuth configuration is not complete.", 500

    verifier, challenge = create_pkce()
    state = secrets.token_urlsafe(32)

    session["pkce_verifier"] = verifier
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return redirect(f"{KAISER_AUTHORIZE_URL}?{urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return (
            f"Kaiser authorization returned an error: "
            f"{request.args.get('error')}"
        ), 400

    returned_state = request.args.get("state")
    expected_state = session.get("oauth_state")

    if not returned_state or returned_state != expected_state:
        return "OAuth state validation failed.", 400

    code = request.args.get("code")
    verifier = session.get("pkce_verifier")

    if not code or not verifier:
        return "Authorization code or PKCE verifier is missing.", 400

    client_id = os.environ.get("KAISER_CLIENT_ID")
    client_secret = os.environ.get("KAISER_CLIENT_SECRET")
    redirect_uri = os.environ.get("KAISER_REDIRECT_URI")

    if not client_id or not client_secret or not redirect_uri:
        return "Kaiser OAuth configuration is incomplete.", 500

    token_response = requests.post(
        KAISER_TOKEN_URL,
        auth=(client_id, client_secret),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        timeout=30,
    )

    if not token_response.ok:
        return (
            "Kaiser token exchange failed.<br><br>"
            f"HTTP status: {token_response.status_code}"
        ), 502

    token_data = token_response.json()

    # Do not display or log access/refresh tokens.
    session.pop("pkce_verifier", None)
    session.pop("oauth_state", None)

    return """
    <h1>BenefitPrism</h1>
    <h2>Kaiser authorization succeeded.</h2>
    <p>The sandbox OAuth flow completed successfully.</p>
    <p>No access token or refresh token is displayed.</p>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
