#!/usr/bin/env python3
"""Generate labeled placeholder images for the README.

These are stand-ins so the README renders cleanly before real screenshots
exist. Replace each PNG with a genuine capture (same filename) and the README
needs no changes. See assets/README.md for what to capture.

Run:  python3 assets/_make_placeholders.py
"""
from PIL import Image, ImageDraw, ImageFont
import os

HERE = os.path.dirname(__file__)
W, H = 1200, 675  # 16:9, good for GitHub

def font(size, bold=False):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for c in candidates:
        if os.path.exists(c):
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()

def make(filename, title, subtitle, lines, accent):
    bg = (13, 17, 23)          # GitHub dark
    panel = (22, 27, 34)
    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)

    # top accent bar
    d.rectangle([0, 0, W, 8], fill=accent)

    # "terminal" chrome
    d.rectangle([40, 60, W-40, H-120], fill=panel, outline=(48, 54, 61), width=2)
    for i, col in enumerate([(255,95,86),(255,189,46),(39,201,63)]):
        d.ellipse([70+i*28, 82, 86+i*28, 98], fill=col)
    d.text((170, 80), filename, font=font(18), fill=(139,148,158))

    # body lines (monospace)
    y = 140
    for ln, color in lines:
        d.text((80, y), ln, font=font(22), fill=color)
        y += 40

    # title / subtitle footer
    d.text((40, H-96), title, font=font(34, bold=True), fill=(230,237,243))
    d.text((40, H-50), subtitle, font=font(20), fill=(139,148,158))
    # PLACEHOLDER stamp
    d.text((W-360, H-60), "PLACEHOLDER — replace with a real capture",
           font=font(15), fill=(88,96,105))

    out = os.path.join(HERE, filename)
    img.save(out)
    print("wrote", out)

green=(63,185,80); red=(248,81,73); grey=(139,148,158); white=(230,237,243); cyan=(57,197,187)

make("01-attack-takeover.png",
     "The attack: SMS OTP relayed to account takeover",
     "attack/selftest.py — the phishing relay forwards creds + OTP in real time",
     [("$ python3 attack/selftest.py", white),
      ("=== VICTIM enters creds on the attacker page ===", grey),
      ("  attacker CAPTURED creds: hoda / correct horse ...", red),
      ("=== VICTIM's phone receives real OTP: 020129 ===", grey),
      ("  attacker CAPTURED + relayed OTP: 020129", red),
      ("=== RESULT ===", grey),
      ("  TAKEOVER -- attacker holds a real session", red)],
     accent=red)

make("02-webauthn-demo.png",
     "The defense: WebAuthn binds the credential to the origin",
     "defense/webauthn_demo.py — honest login accepted, relay + forgery rejected",
     [("$ python3 defense/webauthn_demo.py", white),
      ("SCENARIO 1  Honest login", grey),
      ("  verdict: ACCEPTED -- genuine, origin-bound", green),
      ("SCENARIO 2  Phishing relay", grey),
      ("  verdict: REJECTED -- origin mismatch (:8000)", red),
      ("SCENARIO 3  Origin forgery", grey),
      ("  verdict: REJECTED -- invalid signature", red)],
     accent=green)

make("03-passkey-browser.png",
     "Real passkey in the browser (WebAuthn / FIDO2)",
     "defense/passkey_server.py at http://localhost:5000 — register & sign in",
     [("Passkey Lab  --  real WebAuthn", white),
      ("Origin: http://localhost:5000", grey),
      ("Username: [ hoda ]", grey),
      ("[ Register passkey ]   [ Sign in with passkey ]", cyan),
      ("", grey),
      (">> Approve on your device (Touch ID / security key)", grey),
      (":: Signed in. new sign count = 2", green)],
     accent=cyan)
