#!/usr/bin/env python3
"""
real_service.py  --  The LEGITIMATE service (the "victim" website).

This simulates a real site (call it "SecureBank") that protects login with
an SMS OTP as a second factor. In this lab there is no real SMS gateway --
the OTP is printed to THIS server's console to stand in for "the code the
user receives on their phone."

Login is a two-step flow, which is exactly what makes OTP phishing possible:
    Step 1:  POST /login       (username + password)  -> issues an OTP
    Step 2:  POST /verify      (the OTP)              -> grants a session

Run:
    python3 attack/real_service.py         # listens on http://127.0.0.1:5000

Everything is in-memory and local. Create your own test user below.
"""

import secrets
from flask import Flask, request, session, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # session signing key for THIS lab only

# ---------------------------------------------------------------------------
# Fake user database. These are YOUR OWN test accounts -- nothing real.
# ---------------------------------------------------------------------------
USERS = {
    "hoda": "correct horse battery staple",   # username -> password
}

# Pending OTP challenges, keyed by a short-lived login ticket.
#   ticket -> {"user": <name>, "otp": <6 digits>}
PENDING = {}


@app.route("/")
def index():
    return (
        "<h2>SecureBank (the legitimate service)</h2>"
        "<p>This is the REAL site. In the lab you log in here directly to see "
        "the honest flow, and you also watch the attacker relay drive it.</p>"
        "<p>API: POST /login {username,password} then POST /verify {ticket,otp}</p>"
    )


@app.route("/login", methods=["POST"])
def login():
    """Step 1: check the password, then 'send' an OTP (print it to console)."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if USERS.get(username) != password:
        return jsonify(ok=False, error="bad credentials"), 401

    ticket = secrets.token_urlsafe(8)
    otp = f"{secrets.randbelow(1_000_000):06d}"
    PENDING[ticket] = {"user": username, "otp": otp}

    # ---- This line stands in for "an SMS is sent to the user's phone." ----
    print(f"\n[SecureBank SMS gateway]  OTP for '{username}': {otp}\n")

    return jsonify(ok=True, ticket=ticket, note="OTP sent to your phone")


@app.route("/verify", methods=["POST"])
def verify():
    """Step 2: exchange a valid OTP for an authenticated session."""
    ticket = request.form.get("ticket", "")
    otp = request.form.get("otp", "")

    challenge = PENDING.get(ticket)
    if not challenge:
        return jsonify(ok=False, error="unknown or expired login ticket"), 400

    if otp != challenge["otp"]:
        return jsonify(ok=False, error="wrong OTP"), 401

    PENDING.pop(ticket, None)
    session["user"] = challenge["user"]
    # A real bank would now show the account. We just confirm the takeover point.
    return jsonify(ok=True, message=f"Logged in as {challenge['user']}. "
                                    "Session cookie issued -> account is now accessible.")


if __name__ == "__main__":
    print("SecureBank (legitimate service) on http://127.0.0.1:5000")
    print("Watch this console -- issued OTPs print here, simulating SMS.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
