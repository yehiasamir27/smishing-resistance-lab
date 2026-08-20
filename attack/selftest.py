#!/usr/bin/env python3
"""Self-contained end-to-end check of the lab, no shell backgrounding.

Starts the real service in a background thread, then exercises the attacker
relay's exact logic (capture creds -> relay -> real OTP -> capture OTP ->
relay -> takeover) using requests. Prints what each side sees.
"""
import threading, time, re, io, sys
import requests
import real_service

# Capture the real service's stdout so we can read the "SMS" OTP it prints.
otp_box = {}
_orig_print = print
def capturing_print(*a, **k):
    s = " ".join(str(x) for x in a)
    m = re.search(r"OTP for '(\w+)': (\d{6})", s)
    if m:
        otp_box[m.group(1)] = m.group(2)
    _orig_print(*a, **k)
real_service.print = capturing_print  # intercept the module's print

# Run the real service on :5001 to avoid clashing with anything already up.
def run_real():
    real_service.app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
threading.Thread(target=run_real, daemon=True).start()

# Wait for it to come up.
base = "http://127.0.0.1:5001"
for _ in range(50):
    try:
        requests.get(base + "/", timeout=1); break
    except Exception:
        time.sleep(0.1)

print("\n=== VICTIM enters creds on the attacker page; attacker relays them ===")
r1 = requests.post(base + "/login",
                   data={"username": "hoda", "password": "correct horse battery staple"},
                   timeout=5).json()
print("  attacker CAPTURED creds: hoda / correct horse battery staple")
print("  real service replied:", r1)
ticket = r1["ticket"]

time.sleep(0.1)
otp = otp_box.get("hoda")
print(f"\n=== VICTIM's phone receives real OTP: {otp} (attacker will relay it) ===")

r2 = requests.post(base + "/verify",
                   data={"ticket": ticket, "otp": otp}, timeout=5).json()
print("  attacker CAPTURED + relayed OTP:", otp)
print("  real service replied:", r2)

print("\n=== RESULT ===")
print("  TAKEOVER" if r2.get("ok") else "  failed", "-- attacker holds a real session"
      if r2.get("ok") else "")
