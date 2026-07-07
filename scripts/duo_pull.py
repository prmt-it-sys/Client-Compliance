#!/usr/bin/env python3
"""Pull MFA enrollment from Cisco Duo (Admin API) into duo.json.

Reads credentials from .duo.env in the repo root (or the environment):

    DUO_HOST=api-xxxxxxxx.duosecurity.com     # Admin API application
    DUO_IKEY=DIXXXXXXXXXXXXXXXXXXXX
    DUO_SKEY=****************************************

    # Optional — MSP parents only: enumerate child accounts via the
    # Accounts API and pull each child's users too. Requires the
    # "Admin API for child accounts" toggle in the parent admin panel.
    DUO_ACCOUNTS_HOST=api-xxxxxxxx.duosecurity.com
    DUO_ACCOUNTS_IKEY=DIXXXXXXXXXXXXXXXXXXXX
    DUO_ACCOUNTS_SKEY=****************************************

Output (duo.json, git-ignored — contains user emails):
    {fetchedAt, accounts:[{name, accountId, users, active, enrolled, bypass,
                           mfaPct, enrolledEmails:[...], noMfaUsers:[{name,email,username}]}]}

The Admin API application needs only "Grant read resource" permission.
"""
import base64, email.utils, hashlib, hmac, json, os, sys, urllib.parse, urllib.request
from datetime import date

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env():
    path = os.path.join(REPO, ".duo.env")
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def signed_request(method, host, path, params, ikey, skey):
    """Duo API signature v2: HMAC-SHA1 over date/method/host/path/params."""
    now = email.utils.formatdate()
    qs = urllib.parse.urlencode(sorted(params.items()))
    canon = "\n".join([now, method.upper(), host.lower(), path, qs])
    sig = hmac.new(skey.encode(), canon.encode(), hashlib.sha1).hexdigest()
    auth = base64.b64encode(f"{ikey}:{sig}".encode()).decode()
    url = f"https://{host}{path}"
    body = None
    if method.upper() == "GET":
        if qs:
            url += "?" + qs
    else:
        body = qs.encode()
    req = urllib.request.Request(url, data=body, method=method.upper(), headers={
        "Date": now, "Authorization": "Basic " + auth,
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read().decode())
    if out.get("stat") != "OK":
        raise RuntimeError(f"Duo API error on {path}: {out}")
    return out


def fetch_users(host, ikey, skey, extra=None):
    users, offset = [], 0
    while True:
        params = {"limit": "300", "offset": str(offset)}
        if extra:
            params.update(extra)
        out = signed_request("GET", host, "/admin/v1/users", params, ikey, skey)
        users.extend(out["response"])
        nxt = (out.get("metadata") or {}).get("next_offset")
        if nxt is None:
            return users
        offset = nxt


def summarize(name, account_id, users):
    active = [u for u in users if u.get("status") in ("active", "bypass")]
    enrolled = [u for u in active if u.get("is_enrolled")]
    no_mfa = [u for u in active if not u.get("is_enrolled")]
    return {
        "name": name,
        "accountId": account_id,
        "users": len(users),
        "active": len(active),
        "enrolled": len(enrolled),
        "bypass": sum(1 for u in users if u.get("status") == "bypass"),
        "mfaPct": round(len(enrolled) / len(active) * 100, 1) if active else None,
        "enrolledEmails": sorted({(u.get("email") or "").lower() for u in enrolled if u.get("email")}),
        "noMfaUsers": [{"name": u.get("realname") or u.get("username") or "",
                        "email": (u.get("email") or "").lower(),
                        "username": u.get("username") or ""} for u in no_mfa],
    }


def main():
    load_env()
    accounts = []

    host, ikey, skey = (os.environ.get(k) for k in ("DUO_HOST", "DUO_IKEY", "DUO_SKEY"))
    if host and ikey and skey:
        print(f"Pulling users from Duo account ({host})…")
        users = fetch_users(host, ikey, skey)
        info = signed_request("GET", host, "/admin/v1/settings", {}, ikey, skey)["response"]
        accounts.append(summarize(info.get("name") or "Duo", None, users))
        print(f"  {accounts[-1]['name']}: {accounts[-1]['active']} active, "
              f"{accounts[-1]['enrolled']} enrolled")

    ah, ai, ak = (os.environ.get(k) for k in
                  ("DUO_ACCOUNTS_HOST", "DUO_ACCOUNTS_IKEY", "DUO_ACCOUNTS_SKEY"))
    if ah and ai and ak:
        print(f"Enumerating child accounts ({ah})…")
        kids = signed_request("POST", ah, "/accounts/v1/account/list", {}, ai, ak)["response"]
        for kid in kids:
            try:
                users = fetch_users(kid["api_hostname"], ai, ak,
                                    extra={"account_id": kid["account_id"]})
                accounts.append(summarize(kid["name"], kid["account_id"], users))
                print(f"  {kid['name']}: {accounts[-1]['active']} active, "
                      f"{accounts[-1]['enrolled']} enrolled")
            except Exception as e:
                print(f"  ! {kid['name']}: {e}", file=sys.stderr)

    if not accounts:
        sys.exit("No Duo credentials found — create .duo.env (see header of this file).")

    out = {"fetchedAt": date.today().isoformat(), "accounts": accounts}
    dest = os.path.join(REPO, "duo.json")
    with open(dest, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"wrote duo.json ({len(accounts)} account(s)) — git-ignored, never commit")


if __name__ == "__main__":
    main()
