#!/usr/bin/env python3
"""
passkey_server.py -- a REAL browser passkey (WebAuthn) demo.

Unlike webauthn_demo.py (which simulates the authenticator in Python), this one
drives an ACTUAL authenticator through your browser: Touch ID, Windows Hello,
Android screen-lock, or a physical security key (YubiKey etc.). It uses the
industry-standard `py_webauthn` library for the server side and the native
`navigator.credentials` API for the browser side.

Run (inside the lab venv so py_webauthn is on the path):
    cd ~/phishing-resistance-lab
    .venv/bin/python passkey_server.py

Then open  http://localhost:5000  in your browser.
  IMPORTANT: use http://localhost:5000  (NOT 127.0.0.1). The RP ID is
  "localhost", and WebAuthn requires the origin's host to match. localhost is a
  "secure context" even over plain HTTP, so no certificates are needed.

Register a passkey, then authenticate with it. Everything is in-memory; restart
to reset.

Tie-in to the rest of the lab: the browser stamps the real origin
(http://localhost:5000) into the assertion, and py_webauthn's
verify_authentication_response enforces expected_origin. That is the same origin
binding webauthn_demo.py proved defeats the phishing relay -- here running
against real hardware.
"""

import secrets
from flask import Flask, request, session, jsonify, Response

from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor, UserVerificationRequirement,
    AuthenticatorSelectionCriteria, ResidentKeyRequirement,
)

# --- Relying-party identity. The credential is bound to these. --------------
RP_ID = "localhost"
RP_NAME = "Passkey Lab"
ORIGIN = "http://localhost:5000"

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory credential store:  username -> list of {"id": bytes, "pubkey": bytes, "sign_count": int}
CREDENTIALS = {}


# ============================ Browser page ==================================
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Passkey Lab</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
  h1{font-size:1.4rem} input{padding:8px;font-size:1rem}
  button{padding:10px 16px;font-size:1rem;margin:6px 6px 6px 0;cursor:pointer}
  #log{white-space:pre-wrap;background:#111;color:#0f0;padding:12px;border-radius:8px;
       margin-top:16px;min-height:80px;font-family:ui-monospace,monospace;font-size:.9rem}
  .ok{color:#0f0} .err{color:#f55}
</style></head><body>
<h1>Passkey Lab &mdash; real WebAuthn</h1>
<p>Origin: <code>http://localhost:5000</code>. Register a passkey with your
device (Touch ID / Windows Hello / security key), then sign in with it.</p>
<p>Username: <input id="user" value="hoda"></p>
<button onclick="register()">Register passkey</button>
<button onclick="login()">Sign in with passkey</button>
<div id="log"></div>

<script>
// ---- base64url <-> ArrayBuffer helpers (WebAuthn speaks base64url) ----
const b64uToBuf = (s) => {
  s = s.replace(/-/g,'+').replace(/_/g,'/'); s += '='.repeat((4 - s.length%4)%4);
  const bin = atob(s), buf = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i);
  return buf.buffer;
};
const bufToB64u = (buf) => {
  const bytes = new Uint8Array(buf); let bin='';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
};
const log = (msg, cls) => {
  const el = document.getElementById('log');
  el.innerHTML += `<span class="${cls||''}">${msg}</span>\n`;
};
const username = () => document.getElementById('user').value;

async function register(){
  try{
    log('Requesting registration options...');
    let opts = await (await fetch('/register/begin',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:username()})})).json();

    // Decode the base64url fields the server sent into ArrayBuffers.
    opts.challenge = b64uToBuf(opts.challenge);
    opts.user.id   = b64uToBuf(opts.user.id);
    (opts.excludeCredentials||[]).forEach(c => c.id = b64uToBuf(c.id));

    log('Calling navigator.credentials.create() -- approve on your device...');
    const cred = await navigator.credentials.create({publicKey: opts});

    // Serialize the browser's response back to base64url for the server.
    const body = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64u(cred.response.attestationObject),
        clientDataJSON:    bufToB64u(cred.response.clientDataJSON),
      },
    };
    const res = await (await fetch('/register/finish',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:username(), credential:body})})).json();
    log(res.verified ? '✓ Passkey registered.' : ('✗ '+(res.error||'failed')),
        res.verified?'ok':'err');
  }catch(e){ log('✗ '+e, 'err'); }
}

async function login(){
  try{
    log('Requesting authentication options...');
    let opts = await (await fetch('/login/begin',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:username()})})).json();
    if(opts.error){ log('✗ '+opts.error,'err'); return; }

    opts.challenge = b64uToBuf(opts.challenge);
    (opts.allowCredentials||[]).forEach(c => c.id = b64uToBuf(c.id));

    log('Calling navigator.credentials.get() -- approve on your device...');
    const assertion = await navigator.credentials.get({publicKey: opts});

    const body = {
      id: assertion.id,
      rawId: bufToB64u(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufToB64u(assertion.response.authenticatorData),
        clientDataJSON:    bufToB64u(assertion.response.clientDataJSON),
        signature:         bufToB64u(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
      },
    };
    const res = await (await fetch('/login/finish',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:username(), credential:body})})).json();
    log(res.verified ? ('✓ Signed in. new sign count = '+res.sign_count)
                     : ('✗ '+(res.error||'failed')),
        res.verified?'ok':'err');
  }catch(e){ log('✗ '+e, 'err'); }
}
</script></body></html>"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


# ============================ Registration ==================================
@app.route("/register/begin", methods=["POST"])
def register_begin():
    username = request.json.get("username", "").strip() or "user"
    existing = CREDENTIALS.get(username, [])

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_id=username.encode(),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=c["id"]) for c in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    # Remember the challenge to verify against in /register/finish.
    session["reg_challenge"] = bytes_to_base64url(options.challenge)
    session["reg_user"] = username
    return Response(options_to_json(options), mimetype="application/json")


@app.route("/register/finish", methods=["POST"])
def register_finish():
    username = request.json.get("username", "")
    credential = request.json.get("credential")
    challenge = base64url_to_bytes(session.get("reg_challenge", ""))
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,       # <-- origin binding, server side
        )
    except Exception as e:
        return jsonify(verified=False, error=str(e)), 400

    CREDENTIALS.setdefault(username, []).append({
        "id": verification.credential_id,
        "pubkey": verification.credential_public_key,
        "sign_count": verification.sign_count,
    })
    return jsonify(verified=True)


# ============================ Authentication ================================
@app.route("/login/begin", methods=["POST"])
def login_begin():
    username = request.json.get("username", "")
    creds = CREDENTIALS.get(username, [])
    if not creds:
        return jsonify(error=f"no passkey registered for '{username}' -- register first")

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c["id"]) for c in creds],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session["auth_challenge"] = bytes_to_base64url(options.challenge)
    session["auth_user"] = username
    return Response(options_to_json(options), mimetype="application/json")


@app.route("/login/finish", methods=["POST"])
def login_finish():
    username = request.json.get("username", "")
    credential = request.json.get("credential")
    challenge = base64url_to_bytes(session.get("auth_challenge", ""))

    raw_id = base64url_to_bytes(credential["rawId"])
    stored = next((c for c in CREDENTIALS.get(username, []) if c["id"] == raw_id), None)
    if not stored:
        return jsonify(verified=False, error="credential not recognized for this user"), 400

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,       # <-- the check that defeats the relay
            credential_public_key=stored["pubkey"],
            credential_current_sign_count=stored["sign_count"],
        )
    except Exception as e:
        return jsonify(verified=False, error=str(e)), 400

    stored["sign_count"] = verification.new_sign_count
    return jsonify(verified=True, sign_count=verification.new_sign_count)


if __name__ == "__main__":
    print("Passkey Lab on http://localhost:5000  (open it in your browser)")
    print("Use 'localhost', not 127.0.0.1 -- RP ID is 'localhost'.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
