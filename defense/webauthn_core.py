#!/usr/bin/env python3
"""
webauthn_core.py -- the relying-party (server-side) verification logic.

This is a faithful, minimal slice of how a real WebAuthn/FIDO2 relying party
verifies an authentication assertion. Real crypto (ECDSA P-256 / ES256), real
structures (authenticatorData, clientDataJSON), real checks.

The single check that defeats the phishing relay from the OTP lab is the
ORIGIN check inside verify_assertion(). Everything else is here so that check
is meaningful (you can't skip the signature and just trust the origin string).
"""

import json
import hashlib
import base64
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Relying-party identity. THIS is what the credential gets bound to.
#   rp_id    -> the domain the credential belongs to
#   origin   -> the exact web origin the RP will accept assertions from
# In the phishing lab, the attacker page lives at http://127.0.0.1:8000, which
# is NOT this origin -- that mismatch is the whole defense.
# ---------------------------------------------------------------------------
RP_ID = "127.0.0.1"
EXPECTED_ORIGIN = "http://127.0.0.1:5000"

# In-memory credential store:  credential_id -> {"pubkey": <EC public key>, "sign_count": int}
_CREDENTIALS = {}

# Outstanding challenges we've issued (a real RP ties these to a session).
_CHALLENGES = set()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def new_challenge() -> str:
    """Issue a fresh random challenge (base64url), as /login/begin would."""
    c = b64url(secrets.token_bytes(32))
    _CHALLENGES.add(c)
    return c


def register_credential(credential_id: str, public_key_pem: bytes):
    """Store a newly enrolled credential's public key (the /register/finish step)."""
    pub = serialization.load_pem_public_key(public_key_pem)
    _CREDENTIALS[credential_id] = {"pubkey": pub, "sign_count": 0}


def rp_id_hash() -> bytes:
    return hashlib.sha256(RP_ID.encode()).digest()


def verify_assertion(credential_id: str,
                     authenticator_data: bytes,
                     client_data_json: bytes,
                     signature: bytes):
    """
    Verify a WebAuthn assertion. Returns (ok: bool, reason: str).

    The checks, in the order a real RP does them. Any single failure => reject.
    """
    cred = _CREDENTIALS.get(credential_id)
    if not cred:
        return False, "unknown credential id"

    # 1) Parse clientDataJSON (what the browser signed on the user's behalf).
    try:
        cdata = json.loads(client_data_json.decode())
    except Exception:
        return False, "malformed clientDataJSON"

    # 2) type must be webauthn.get for an authentication assertion.
    if cdata.get("type") != "webauthn.get":
        return False, f"wrong type: {cdata.get('type')!r}"

    # 3) challenge must be one we issued (prevents replay of an old assertion).
    if cdata.get("challenge") not in _CHALLENGES:
        return False, "challenge not recognized (replay or forged)"

    # 4) *** THE ORIGIN CHECK -- this is what kills the phishing relay. ***
    #    The browser stamped clientData.origin with the site the user was
    #    ACTUALLY on. On the attacker page that's http://127.0.0.1:8000.
    if cdata.get("origin") != EXPECTED_ORIGIN:
        return False, (f"origin mismatch: signed for {cdata.get('origin')!r}, "
                       f"but this RP only accepts {EXPECTED_ORIGIN!r}")

    # 5) authenticatorData must be for THIS rp_id.
    if authenticator_data[:32] != rp_id_hash():
        return False, "rpIdHash mismatch (credential is for a different domain)"

    # 6) Verify the signature over authenticatorData || SHA256(clientDataJSON).
    #    Because the signature covers clientDataJSON, the origin above cannot be
    #    edited after the fact without invalidating this signature.
    client_data_hash = hashlib.sha256(client_data_json).digest()
    signed_bytes = authenticator_data + client_data_hash
    try:
        cred["pubkey"].verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "invalid signature (data was tampered or key is wrong)"

    # 7) Signature counter must move forward (clone / replay detection).
    sign_count = int.from_bytes(authenticator_data[33:37], "big")
    if sign_count <= cred["sign_count"] and sign_count != 0:
        return False, "signature counter did not increase (possible clone/replay)"
    cred["sign_count"] = sign_count

    return True, "all checks passed -- assertion is genuine and origin-bound"
