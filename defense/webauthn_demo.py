#!/usr/bin/env python3
"""
webauthn_demo.py -- WebAuthn vs. the phishing relay, three scenarios.

Reuses the SAME attacker relay idea from the OTP lab, but the second factor is
now a WebAuthn credential instead of an SMS OTP. Run it and read the verdicts:

  1. Honest login   -> user is really on the RP's page   -> ACCEPTED
  2. Phishing relay -> user is on the attacker's page,    -> REJECTED (origin)
                       attacker forwards the assertion
  3. Origin forgery -> attacker edits the origin to match -> REJECTED (signature)

Scenario 1 vs 2 is the payoff: the OTP lab ended in takeover at this exact
step; here the same relay dies, because the credential is bound to the origin.
"""

import json
import webauthn_core as rp
from soft_authenticator import SoftAuthenticator

REAL_ORIGIN = "http://127.0.0.1:5000"      # the genuine relying party
ATTACKER_ORIGIN = "http://127.0.0.1:8000"  # the phishing relay from the OTP lab

def line(): print("-" * 70)

# --- Enrollment: the user registers a security key with the real service ---
authenticator = SoftAuthenticator()
CRED_ID = "user-hoda-key-1"
rp.register_credential(CRED_ID, authenticator.public_key_pem())
print(f"Enrolled credential {CRED_ID!r} with RP origin {rp.EXPECTED_ORIGIN!r}\n")


# =====================================================================
# Scenario 1 — honest login (user's browser is on the REAL site)
# =====================================================================
line(); print("SCENARIO 1: Honest login (browser is on the real site :5000)")
challenge = rp.new_challenge()
assertion = authenticator.get_assertion(page_origin=REAL_ORIGIN, challenge=challenge)
ok, reason = rp.verify_assertion(CRED_ID, **assertion)
print(f"  signed origin : {REAL_ORIGIN}")
print(f"  verdict       : {'ACCEPTED' if ok else 'REJECTED'} -- {reason}\n")


# =====================================================================
# Scenario 2 — phishing relay (the attack that beat SMS OTP)
# The victim is on the attacker's :8000 page. The browser stamps origin=:8000.
# The attacker faithfully FORWARDS the assertion to the real RP.
# =====================================================================
line(); print("SCENARIO 2: Phishing relay (browser on attacker :8000, assertion forwarded)")
challenge = rp.new_challenge()   # attacker got this from the real /login/begin and showed it to the victim
victim_assertion = authenticator.get_assertion(page_origin=ATTACKER_ORIGIN, challenge=challenge)
# attacker relays victim_assertion verbatim to the real RP:
ok, reason = rp.verify_assertion(CRED_ID, **victim_assertion)
print(f"  signed origin : {ATTACKER_ORIGIN}   <- the victim was on the phishing page")
print(f"  verdict       : {'ACCEPTED' if ok else 'REJECTED'} -- {reason}\n")


# =====================================================================
# Scenario 3 — attacker tries to fix the origin before forwarding
# They edit clientDataJSON so origin says :5000, hoping to pass check #4.
# But the signature covers clientDataJSON, so editing it breaks check #6.
# =====================================================================
line(); print("SCENARIO 3: Attacker rewrites the origin to :5000 before forwarding")
challenge = rp.new_challenge()
victim_assertion = authenticator.get_assertion(page_origin=ATTACKER_ORIGIN, challenge=challenge)
tampered = dict(victim_assertion)
cdata = json.loads(tampered["client_data_json"].decode())
cdata["origin"] = REAL_ORIGIN                                   # forge it
tampered["client_data_json"] = json.dumps(cdata, separators=(",", ":")).encode()
ok, reason = rp.verify_assertion(CRED_ID, **tampered)
print(f"  forged origin : {REAL_ORIGIN}   (but signature was made over :8000 data)")
print(f"  verdict       : {'ACCEPTED' if ok else 'REJECTED'} -- {reason}\n")

line()
print("Takeaway: the credential is cryptographically bound to the origin.")
print("The attacker can neither present the true origin (:8000 is rejected) nor")
print("forge it (:5000 breaks the signature). The relay that defeated SMS OTP")
print("has no move here. THAT is what 'phishing-resistant' means.")
