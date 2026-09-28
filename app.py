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

KAISER_EOB_URL = (
    "https://kpx-service-bus.kp.org/service/cdo/siae/"
    "healthplankpxv1rc/FHIR/api/ExplanationOfBenefit"
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

    # SMART on FHIR commonly returns the patient launch-context
    # identifier in the token response.
    patient_id = token_data.get("patient")

    if not access_token:
        return "Kaiser did not return an access token.", 502

    # If Kaiser did not return a patient field, show only the SAFE
    # field names from the token response so we can determine
    # where Kaiser placed the patient context.
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
        <h2>OAuth succeeded, but patient ID was not found.</h2>

        <p>Kaiser returned these non-secret token response fields:</p>

        <ul>
            {keys_html}
        </ul>

        <p>No tokens or credentials are displayed.</p>
        """

    # Kaiser documents patient=[FHIR ID] for retrieving all
    # ExplanationOfBenefit resources belonging to the member.
    eob_response = requests.get(
        KAISER_EOB_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/fhir+json",
        },
        params={
            "patient": patient_id,
            "_include": "*",
            "_count": "10",
        },
        timeout=30,
    )

    session.pop("pkce_verifier", None)
    session.pop("oauth_state", None)

    if not eob_response.ok:
        return (
            "<h1>BenefitPrism</h1>"
            "<h2>OAuth succeeded, but the EOB request failed.</h2>"
            f"<p>FHIR HTTP status: {eob_response.status_code}</p>"
            "<p>No OAuth tokens or credentials are displayed.</p>"
        ), 502

    bundle = eob_response.json()
    entries = bundle.get("entry", [])

    resource_types = {}
    eob_count = 0

    for entry in entries:
        resource = entry.get("resource", {})
        resource_type = resource.get("resourceType", "Unknown")

        resource_types[resource_type] = (
            resource_types.get(resource_type, 0) + 1
        )

        if resource_type == "ExplanationOfBenefit":
            eob_count += 1

    types_html = "".join(
        f"<li>{html.escape(str(name))}: {count}</li>"
        for name, count in sorted(resource_types.items())
    )

    return f"""
    <h1>BenefitPrism</h1>
    <h2>Kaiser sandbox EOB retrieval succeeded.</h2>

    <p>OAuth authorization: <b>successful</b></p>
    <p>Token exchange: <b>successful</b></p>
    <p>Patient context received: <b>yes</b></p>
    <p>FHIR request: <b>successful</b></p>

    <h3>Kaiser FHIR response</h3>

    <p>ExplanationOfBenefit resources returned:
       <b>{eob_count}</b></p>

    <p>Total resources returned:
       <b>{len(entries)}</b></p>

    <ul>
        {types_html}
    </ul>

    <p>No OAuth tokens, credentials, patient identifiers,
       or raw health data are displayed.</p>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
