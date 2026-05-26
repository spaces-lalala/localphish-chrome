# LocalPhish — Test fixtures

Local-only HTML fixtures and a tiny static server for testing the extension
end-to-end. **None of these files should ever be deployed publicly.** They
imitate phishing pages so we can exercise Stage 2 (DOM) and Stage 3 (LLM)
detectors against realistic content.

## Two ways to test the extension

### A. Stage 1 (URL-only) — open the URL Tester

The Options page is now a URL tester. **chrome://extensions → LocalPhish →
Details → Extension options**. Paste any URL string, or click one of the
preset buttons (typosquat, Punycode, IP-as-host, allow-list hit, etc.).
No navigation happens — the URL is parsed locally and Stage 1 runs.

This is the fastest way to verify the rule engine.

### B. Stage 2 / Stage 3 — serve the fixtures and visit them

The fake HTML pages exhibit DOM-level and content-level phishing patterns
(cross-origin form actions, password + OTP + CVV fields side by side, urgency
text, brand impersonation, seed-phrase prompts). Stage 1 alone won't flag
`http://localhost:8765/...` strongly — these become useful once Stage 2 / 3
land.

```bash
cd test
uv run python serve.py
```

Then open in Chrome (with LocalPhish loaded):

- http://localhost:8765/microsoft-365-login-fake.html
- http://localhost:8765/paypal-verify-fake.html
- http://localhost:8765/crypto-wallet-connect-fake.html

`uv run` works because Python's `http.server` is in the standard library;
no extra deps. If you'd rather use a different runtime:

```bash
python serve.py
# or
npx --yes serve fixtures -p 8765
```

## Fixture inventory

| File | Imitates | Notable signals |
|---|---|---|
| `microsoft-365-login-fake.html` | M365 sign-in | urgency text, cross-origin form action to `.tk`, OTP field |
| `paypal-verify-fake.html` | PayPal recovery | urgency, password + full card + CVV harvest, action to `.zip` |
| `crypto-wallet-connect-fake.html` | MetaMask connect | seed-phrase prompt (12 words), wallet password, action to `.click` |

## What about real phishing URLs?

The plan (§14 verification, step 4) calls for spot-checking a handful of
PhreshPhish samples **in an isolated VM**, not on your daily-driver browser.
For day-to-day development the URL Tester (A) and local fixtures (B) cover
the relevant signals safely.
