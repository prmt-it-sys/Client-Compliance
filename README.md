# PRMT Client Security Status Dashboard

Monthly **Client IT & Identity-Security** dashboard for the PRMT team — posture
scores, MFA coverage, device encryption, account hygiene and SSO usage for every
managed client org, pulled from JumpCloud via PromptQL.

**Live:** https://prmt-it-sys.github.io/Client-Compliance/

## How it works

- `index.html` — single-file dashboard (PRMT-branded, no build step).
- `data.enc.json` — the report data, encrypted **AES-256-GCM** with a key derived
  from the shared team password (PBKDF2-SHA256, 310k iterations). It is decrypted
  in the browser behind the lock screen, so this public repo only ever contains
  ciphertext. Same scheme as the PRMT Client Directory.
- `scripts/build.py` — parses the monthly `PRMT_Client_Security_Reports_*.xlsx`
  workbook (Summary sheet + one detail sheet per client) and writes a fresh
  `data.enc.json`.

Plaintext (`data.json`) and the source workbook are **git-ignored — never commit
them**: the detail sheets contain client user names and email addresses.

## Monthly refresh

1. Export the new workbook from PromptQL (JumpCloud report).
2. From the repo root:

   ```sh
   ./publish.sh ~/Downloads/PRMT_Client_Security_Reports_June_2026.xlsx
   ```

   It rebuilds `data.enc.json` (prompts for the dashboard password unless
   `PRMT_DASH_PASS` is set), commits and pushes. GitHub Pages redeploys in ~1 min.

Requires: `pip3 install openpyxl cryptography`, and `gh auth switch --user prmt-it-sys`.

## Rotating the password

Re-run `./publish.sh` with the new password (it re-encrypts everything with a
fresh salt), then share the new password with the team.

## Data caveats

- **JumpCloud only for now.** Cisco Duo is not yet integrated, so MFA coverage for
  clients that use Duo instead of JumpCloud may be under-reported. The banner in
  the dashboard states this; remove `caveat` in `scripts/build.py` once Duo is in.
- Posture score is a weighted composite (MFA 40%, encryption 25%, check-in health
  15%, password compliance 10%, admin-MFA 10%) — a guide, not a compliance grade.
