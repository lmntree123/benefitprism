import base64
import hashlib
import html
import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

KAISER_AUTHORIZE_URL = (
    "https://kpx-service-bus.kp.org/service/kpx/v1/oauth2/authorize"
)

KAISER_TOKEN_URL = (
    "https://kpx-service-bus.kp.org/service/kpx/v1/oauth2/token"
)

# Endpoint shown in Kaiser's sample Postman collection
FHIR_API_EOB_URL = (
    "https://kpx-service-bus.kp.org/service/cdo/siae/"
    "healthplankpxv1rc/FHIR/api/ExplanationOfBenefit"
)

# Endpoint pattern documented in Kaiser's resource/search table
HPEOB_EOB_URL = (
    "https://kpx-service-bus.kp.org/service/cdo/siae/"
    "healthplankpxv1rc/FHIR/HPEOB/ExplanationOfBenefit"
)

SCOPE = (
    "patient/*.read launch/patient offline_access "
    "ExplanationOfBenefit sandbox"
)


def create_pkce():
    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = (
        base64.urlsafe_b64encode(digest)
        .decode("ascii")
        .rstrip("=")
    )

    return verifier, challenge


def inspect_fhir_response(response):
    result = {
        "status": response.status_code,
        "resource_type": "Unknown",
        "entries": None,
        "total": None,
    }

    try:
        data = response.json()

        if isinstance(data, dict):
            result["resource_type"] = data.get(
                "resourceType", "Unknown"
            )

            if isinstance(data.get("entry"), list):
                result["entries"] = len(data["entry"])
            elif result["resource_type"] == "Bundle":
                result["entries"] = 0

            if "total" in data:
                result["total"] = data.get("total")

    except ValueError:
        result["resource_type"] = "Non-JSON response"

    return result


def result_html(name, result):
    entries = (
        str(result["entries"])
        if result["entries"] is not None
        else "not provided"
    )

    total = (
        str(result["total"])
        if result["total"] is not None
        else "not provided"
    )

    return f"""
    <div style="margin-bottom:30px;">
      <h3>{html.escape(name)}</h3>
      <p>HTTP status: <b>{result["status"]}</b></p>
      <p>FHIR resource type:
         <b>{html.escape(str(result["resource_type"]))}</b></p>
      <p>Entries returned: <b>{entries}</b></p>
      <p>Bundle total: <b>{total}</b></p>
    </div>
    """


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

    return redirect(
        f"{KAISER_AUTHORIZE_URL}?{urlencode(params)}"
    )


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return (
            "Kaiser authorization returned an error: "
            + html.escape(request.args.get("error"))
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
            "<h1>BenefitPrism</h1>"
            "<h2>Token exchange failed.</h2>"
            f"<p>HTTP status: {token_response.status_code}</p>"
        ), 502

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    patient_id = token_data.get("patient")

    if not access_token:
        return "Kaiser did not return an access token.", 502

    if not patient_id:
        safe_keys = sorted(
            key for key in token_data.keys()
            if key not in {
                "access_token",
                "refresh_token",
                "id_token",
            }
        )

        keys_html = "".join(
            f"<li>{html.escape(str(key))}</li>"
            for key in safe_keys
        )

        return f"""
        <h1>BenefitPrism</h1>
        <h2>Patient context not found.</h2>
        <p>Non-secret token response fields:</p>
        <ul>{keys_html}</ul>
        """

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",
    }

    # Test A:
    # Kaiser's sample Postman request, without patient filter.
    test_a = requests.get(
        FHIR_API_EOB_URL,
        headers=headers,
        params={
            "_include": "*",
            "_count": "5",
        },
        timeout=30,
    )

    # Test B:
    # Same API endpoint, now with the authorized patient FHIR ID.
    test_b = requests.get(
        FHIR_API_EOB_URL,
        headers=headers,
        params={
            "patient": patient_id,
            "_include": "*",
            "_count": "5",
        },
        timeout=30,
    )

    # Test C:
    # HPEOB path documented in Kaiser's EOB search table.
    test_c = requests.get(
        HPEOB_EOB_URL,
        headers=headers,
        params={
            "patient": patient_id,
            "_include": "*",
            "_count": "5",
        },
        timeout=30,
    )

    result_a = inspect_fhir_response(test_a)
    result_b = inspect_fhir_response(test_b)
    result_c = inspect_fhir_response(test_c)

    session.pop("pkce_verifier", None)
    session.pop("oauth_state", None)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>BenefitPrism FHIR Diagnostics</title>
    </head>
    <body style="
        font-family:Arial,sans-serif;
        max-width:760px;
        margin:50px auto;
        line-height:1.5;
    ">

      <h1>BenefitPrism</h1>
      <h2>Kaiser FHIR diagnostics</h2>

      <p>OAuth authorization: <b>successful</b></p>
      <p>Token exchange: <b>successful</b></p>
      <p>Patient context received: <b>yes</b></p>

      <hr>

      {result_html(
          "Test A — FHIR/api/ExplanationOfBenefit",
          result_a
      )}

      {result_html(
          "Test B — FHIR/api + patient filter",
          result_b
      )}

      {result_html(
          "Test C — FHIR/HPEOB + patient filter",
          result_c
      )}

      <hr>

      <p>
        No OAuth tokens, credentials, patient identifiers,
        or raw health data are displayed.
      </p>

    </body>
    </html>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
