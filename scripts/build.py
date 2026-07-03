#!/usr/bin/env python3
"""Build data.enc.json for the PRMT Client Security Status Dashboard.

Parses the monthly PromptQL/JumpCloud security-report workbook (Summary sheet +
one detail sheet per client) into JSON, then encrypts it AES-256-GCM with a
PBKDF2-SHA256 key (310k iterations) — the same "prmt-enc" format the dashboard
decrypts in-browser, so the public repo only ever holds ciphertext.

Usage:
    python3 scripts/build.py "<report.xlsx>" [--out data.enc.json]
                             [--plain data.json] [--password PASS]

Password resolution order: --password, $PRMT_DASH_PASS, interactive prompt.
A fresh random salt is generated on every build (no encrypted side-files
depend on a stable key, unlike the Client Directory's images).
"""
import argparse, base64, getpass, json, os, re, sys, unicodedata
from datetime import date

import openpyxl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

KDF_ITER = 310_000

SUMMARY_KEYS = [
    "name", "score", "totalUsers", "active", "suspended", "mfaEnrolled",
    "mfaPct", "activeNoMfa", "expiredPw", "adminMfa", "newUsers", "devices",
    "encrypted", "notEncrypted", "encUnknown", "notSeen7d", "notSeen30d",
    "mdm", "ssoApps", "unusedSso",
]
TABLE_HEADERS = {("Name", "Email", "Username"), ("SSO Application", "Users Assigned")}
SECTION_RE = re.compile(r"^[A-Z]\. ")


def slugify(s):
    s = unicodedata.normalize("NFKD", s)
    s = re.sub(r"[^\w\s-]", "", s).strip().lower()
    return re.sub(r"\s+", "-", s) or "org"


def cells(row):
    return [c for c in row if c is not None and str(c).strip() != ""]


def parse_pct(v):
    if v is None or v == "N/A":
        return None
    return float(str(v).rstrip("%"))


def parse_summary(ws):
    rows = [list(r) for r in ws.iter_rows(values_only=True)]
    title = rows[0][0]
    meta_line = rows[1][0]
    methodology = rows[2][0]
    period = ""
    m = re.search(r"Reporting period:\s*([^|]+)", meta_line or "")
    if m:
        period = m.group(1).strip()
    hdr_idx = next(i for i, r in enumerate(rows) if r and r[0] == "Organization")
    orgs = []
    for r in rows[hdr_idx + 1:]:
        if not r or r[0] is None:
            continue
        rec = dict(zip(SUMMARY_KEYS, r))
        rec["score"] = parse_pct(rec["score"])
        rec["mfaPct"] = parse_pct(rec["mfaPct"])
        rec["slug"] = slugify(rec["name"])
        orgs.append(rec)
    return title, period, methodology, orgs


def parse_detail(ws):
    """Detail sheet -> {headline, sections:[{title, blocks:[kv|note|table]}]}."""
    rows = [list(r) for r in ws.iter_rows(values_only=True)]
    headline = ""
    if len(rows) > 2 and len(rows[2]) > 1 and rows[2][1]:
        headline = str(rows[2][1]).strip()
    sections, cur, table = [], None, None

    def close_table():
        nonlocal table
        table = None

    def ensure_section(title="General"):
        nonlocal cur
        if cur is None:
            cur = {"title": title, "blocks": []}
            sections.append(cur)
        return cur

    for r in rows[4:]:
        vals = cells(r)
        if not vals:
            close_table()
            continue
        a = str(vals[0]).strip()
        strs = tuple(str(v).strip() for v in vals)
        if SECTION_RE.match(a) and len(vals) == 1:
            close_table()
            cur = {"title": a, "blocks": []}
            sections.append(cur)
        elif strs in TABLE_HEADERS:
            table = {"type": "table", "title": None, "headers": list(strs), "rows": []}
            # attach a preceding standalone label (e.g. "Active users WITHOUT MFA (n)")
            blocks = ensure_section()["blocks"]
            if blocks and blocks[-1]["type"] == "label":
                table["title"] = blocks.pop()["text"]
            blocks.append(table)
        elif table is not None:
            table["rows"].append([str(v).strip() for v in strs])
        elif len(vals) >= 2:
            ensure_section()["blocks"].append(
                {"type": "kv", "k": a, "v": " — ".join(str(v).strip() for v in vals[1:])})
        elif a.startswith("Note:") or a.startswith("Trend"):
            ensure_section()["blocks"].append({"type": "note", "text": a})
        else:
            ensure_section()["blocks"].append({"type": "label", "text": a})
    return headline, sections


def build_data(xlsx_path):
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    title, period, methodology, orgs = parse_summary(wb["Summary"])
    by_name = {o["name"]: o for o in orgs}
    for sheet in wb.sheetnames[1:]:
        headline, sections = parse_detail(wb[sheet])
        org = by_name.get(sheet)
        if org is None:
            org = {"name": sheet, "slug": slugify(sheet)}
            orgs.append(org)
        org["headline"] = headline
        org["sections"] = sections
    return {
        "generatedAt": date.today().isoformat(),
        "title": title,
        "period": period,
        "source": "JumpCloud (live API via PromptQL)",
        "methodology": methodology,
        "caveat": ("Data source: JumpCloud only. Cisco Duo is not yet integrated — "
                   "MFA coverage for clients using Duo may be under-reported."),
        "orgs": orgs,
    }


def encrypt(password, obj):
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=KDF_ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"format": "prmt-enc", "v": 1, "kdf": "PBKDF2-SHA256", "iter": KDF_ITER,
            "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xlsx")
    ap.add_argument("--out", default="data.enc.json")
    ap.add_argument("--plain", default="data.json",
                    help="plaintext copy for local dev (git-ignored); '' to skip")
    ap.add_argument("--password", default=None)
    args = ap.parse_args()

    pw = args.password or os.environ.get("PRMT_DASH_PASS") or getpass.getpass("Dashboard password: ")
    if not pw:
        sys.exit("A password is required.")
    data = build_data(args.xlsx)
    if args.plain:
        with open(args.plain, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        print(f"wrote {args.plain} (plaintext — git-ignored, never commit)")
    with open(args.out, "w") as f:
        json.dump(encrypt(pw, data), f, indent=1)
    print(f"wrote {args.out}  ({len(data['orgs'])} orgs, period: {data['period']})")


if __name__ == "__main__":
    main()
