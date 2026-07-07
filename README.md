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

## Cisco Duo integration

Some clients use Duo instead of JumpCloud for MFA. `scripts/duo_pull.py` pulls
enrollment straight from the **Duo Admin API** (no PromptQL needed) and the build
merges it in: users are matched by email, each org's "without MFA" list shrinks by
everyone enrolled in Duo, MFA % becomes the JumpCloud ∪ Duo union, and the posture
score's MFA component is re-weighted. Orgs with Duo data get a `＋DUO` tag.

One-time setup:

1. In the **Duo Admin Panel** (as an Owner-role admin): *Applications → Protect an
   Application → Admin API*. Grant only **read information / read resource**.
2. Save the credentials to `.duo.env` in the repo root (git-ignored):

   ```
   DUO_HOST=api-xxxxxxxx.duosecurity.com
   DUO_IKEY=DIXXXXXXXXXXXXXXXXXXXX
   DUO_SKEY=****************************************
   ```

   MSP parents with child accounts per client: also create an **Accounts API**
   application, enable *Admin API for child accounts*, and add
   `DUO_ACCOUNTS_HOST/IKEY/SKEY`. Each child account is pulled separately.
3. If a Duo account name doesn't match the org name in the report, map it in
   `duo_map.json` (git-ignored): `{"Duo account name": "Org name"}`.

`./publish.sh` auto-pulls Duo before every rebuild when `.duo.env` exists.

## Data caveats

- Until `.duo.env` is configured the data is **JumpCloud only**, so MFA coverage
  for clients that use Duo may be under-reported (the dashboard banner says so;
  it switches automatically once Duo data is merged).
- Posture score is a weighted composite (MFA 40%, encryption 25%, check-in health
  15%, password compliance 10%, admin-MFA 10%) — a guide, not a compliance grade.
