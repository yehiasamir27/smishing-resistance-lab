# Screenshots

The three PNGs here are **labeled placeholders** so the main README renders
cleanly before you capture real screenshots. To swap in a genuine capture,
**save it over the same filename** — the README references these paths, so no
README edits are needed.

| File | What to capture |
|------|-----------------|
| `01-attack-takeover.png` | Terminal running `attack/selftest.py` (or the two-terminal live relay) showing the captured creds/OTP and the `TAKEOVER` result. |
| `02-webauthn-demo.png` | Terminal running `defense/webauthn_demo.py` showing all three scenario verdicts. |
| `03-passkey-browser.png` | The browser at `http://localhost:5000` after registering and signing in with a real passkey (green "Signed in" line visible). |

## Tips for clean captures

- Use a dark terminal theme to match the README diagrams.
- Crop tightly to the relevant output.
- On Kali: `Ctrl+Shift+PrtSc` for a region grab, or use `flameshot gui`
  (`sudo apt install flameshot`).
- Keep images ~1200px wide; PNG is fine.

## Regenerating the placeholders

```bash
python3 assets/_make_placeholders.py
```

You can delete `_make_placeholders.py` once real screenshots are in place.
