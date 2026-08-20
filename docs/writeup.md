# Why your SMS 2FA didn't save you — and why a passkey would have

*A build-it-yourself walkthrough of adversary-in-the-middle phishing and the
origin binding that defeats it.*

---

## The myth I wanted to test

There's a comforting belief that shows up in security advice everywhere: *"Turn
on two-factor authentication and phishing can't hurt you — even if they steal
your password, they don't have your code."*

That belief is half true, and the half that's false gets people's accounts
taken over every day. I wanted to prove both halves to myself by building the
attack and the defense from scratch, on my own machine, against accounts I
control. This is what I found.

## Part 1 — Building the attack

A naive phishing page steals a password and stops there. Against 2FA that's
useless: the attacker has a password and a locked door. So real phishing kits
don't stop there — they **relay in real time**. The fake page is a live
man-in-the-middle sitting between the victim and the real site.

I built two small Flask services:

- **`real_service.py`** — a legitimate "SecureBank" with a normal two-step
  login: password first, then a 6-digit OTP. (No real SMS gateway — the code is
  printed to the server console to stand in for the text message.)
- **`phishing_relay.py`** — the attacker's look-alike page. Every value the
  victim types, it immediately forwards to the real bank.

The attack runs like this:

1. Victim lands on the attacker's page and enters username + password.
2. The relay forwards those to the **real** bank.
3. The real bank — seeing a valid password — sends a **real** OTP to the
   victim's phone. This is the clever part: the victim's phone buzzes with a
   genuine code, because a genuine login really is in progress.
4. The victim, expecting a code, types it into the attacker's page.
5. The relay forwards the OTP too. The real bank grants a session — **to the
   attacker.**

```
=== RESULT ===
  TAKEOVER -- attacker holds a real session
```

Every value the victim entered was legitimate. The OTP was real. And it still
ended in takeover. **The reason: an SMS OTP is a shared secret the user types,
and it isn't bound to *who* is logging in. A secret you can type is a secret you
can be tricked into forwarding.**

This is not theoretical. It's exactly how kits like Evilginx and Modlishka work,
and it's why the FBI and CISA have warned that SMS-based 2FA is phishable.

## Part 2 — Building the defense

If the problem is "the secret can be forwarded," the fix has to be a factor that
*can't* be. That's WebAuthn / FIDO2 — the technology behind **passkeys**.

The key idea is **origin binding**. When you authenticate with a passkey, your
device (security key, phone, laptop TPM) signs a challenge — but bundled into
what it signs is the **origin of the page you're actually on**, and the
*browser* stamps that origin. Web page JavaScript cannot change it.

I implemented the relying-party verification with real ECDSA P-256 crypto
(`webauthn_core.py`) and a simulated authenticator (`soft_authenticator.py`),
then ran the same relay against it. Three scenarios:

| Scenario | What happens | Result |
|----------|--------------|--------|
| **Honest login** | Victim is really on `:5000`; signature covers origin `:5000` | ✅ **ACCEPTED** |
| **Phishing relay** | Victim is on the attacker's `:8000`; browser signs origin `:8000`; attacker forwards it to the real `:5000` | ❌ **REJECTED — origin mismatch** |
| **Origin forgery** | Attacker edits the signed data to say `:5000` | ❌ **REJECTED — invalid signature** |

That second row is the whole point. It's the *exact* step where the SMS attack
succeeded — and here it dies. The attacker is caught in a vise:

- Present the **true** origin (`:8000`)? The real service only accepts its own
  origin → rejected.
- **Forge** the origin to `:5000`? The signature was computed over the real
  data, so any edit invalidates it → rejected.

There is no third option. That's what "phishing-resistant" means — not "hard to
phish," but *cryptographically* unphishable by relay.

## Part 3 — Proving it on real hardware

A simulation can hide mistakes, so I built `passkey_server.py`: a real WebAuthn
relying party using the industry-standard `py_webauthn` library, with a browser
front-end calling the native `navigator.credentials` API. You register with an
actual authenticator — Touch ID, Windows Hello, a YubiKey — and sign in.

One detail I learned the hard way: WebAuthn requires a **secure context**, but
browsers treat `http://localhost` as secure — so the whole thing runs with no
TLS certificates, as long as you use `localhost` (not `127.0.0.1`, because the
RP ID must match the origin's host). The server enforces the defense in one
line:

```python
verify_authentication_response(..., expected_origin="http://localhost:5000")
```

That single `expected_origin` check is the entire difference between an account
that can be relayed and one that can't.

## What I took away

1. **"Has 2FA" is not a security property. *Which* 2FA is.** SMS and TOTP both
   fall to real-time relay; only origin-bound factors (passkeys) survive.
2. **The strongest defenses remove human judgment from the loop.** SMS relies on
   the user noticing something wrong. Passkeys don't ask the user to be vigilant
   — the browser and the math handle it.
3. **Building the attack taught me the defense.** I understand *why* passkeys
   are designed the way they are because I watched exactly which step of my own
   attack they break.

## The comparison, in one table

| Factor | SIM-swap risk | Relayable by live MITM? | Verdict |
|--------|:---:|:---:|--------|
| SMS OTP | High | **Yes** | Weakest |
| TOTP app | None | **Yes** | Better, not resistant |
| Push / number-match | None | Partially (human-dependent) | Depends |
| **Passkey / FIDO2** | None | **No** | Phishing-resistant |

## Try it yourself

Everything is in this repo and runs on `localhost` in a few commands — see the
[README](../README.md). Build the attack, watch it win, then watch the passkey
shut it down.

---

*Scope note: this lab is for education and authorized testing only. Every
component runs locally against accounts you own. Using a relay like this against
real users is account-takeover fraud.*
