#!/usr/bin/env python3
"""
soft_authenticator.py -- a simulated FIDO2 authenticator + the browser glue.

This models the two honest actors on the user's side:

  * The AUTHENTICATOR (your security key / phone / platform TPM): holds the
    private key, signs challenges. The private key never leaves it.

  * The BROWSER: when a page calls navigator.credentials.get(), the browser
    builds clientDataJSON and stamps it with the origin of the page that is
    actually in the address bar. Web page JavaScript CANNOT change this value
    -- it is set by the browser, not the site. That single fact is why
    phishing-resistant means phishing-resistant.

In this simulation `page_origin` is the parameter that represents "the site
the user's browser is really on." A phishing page can only ever pass its OWN
origin here, exactly as a real browser would stamp it.
"""

import json
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from webauthn_core import RP_ID, b64url


class SoftAuthenticator:
    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._sign_count = 0

    # --- registration: hand the RP our public key ---------------------------
    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # --- authentication: produce an assertion for a given page origin -------
    def get_assertion(self, page_origin: str, challenge: str, rp_id: str = RP_ID):
        """
        Return a WebAuthn assertion exactly as browser+authenticator would.

        `page_origin` is stamped into clientDataJSON by the *browser*. We accept
        it as an argument to model different pages; a real attacker cannot make
        the browser lie about which origin the user is on.
        """
        # The browser builds this. Note origin = the page the user is really on.
        client_data = {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": page_origin,
        }
        client_data_json = json.dumps(client_data, separators=(",", ":")).encode()

        # The authenticator builds authenticatorData: rpIdHash || flags || count.
        self._sign_count += 1
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        flags = b"\x05"  # user present + user verified
        authenticator_data = rp_id_hash + flags + self._sign_count.to_bytes(4, "big")

        # The authenticator signs authenticatorData || SHA256(clientDataJSON).
        client_data_hash = hashlib.sha256(client_data_json).digest()
        signature = self._private_key.sign(
            authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )

        return {
            "authenticator_data": authenticator_data,
            "client_data_json": client_data_json,
            "signature": signature,
        }
