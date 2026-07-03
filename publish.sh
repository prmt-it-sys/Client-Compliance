#!/bin/zsh
# Rebuild data.enc.json from a monthly report workbook, commit and push.
# Usage: ./publish.sh <path-to-report.xlsx>
set -e
cd "$(dirname "$0")"

XLSX="$1"
if [[ -z "$XLSX" || ! -f "$XLSX" ]]; then
  echo "Usage: ./publish.sh <path-to-PRMT_Client_Security_Reports_*.xlsx>" >&2
  exit 1
fi

if [[ -z "$PRMT_DASH_PASS" && -f .dashpass ]]; then
  export PRMT_DASH_PASS="$(cat .dashpass)"
fi

python3 scripts/build.py "$XLSX"

ACTIVE=$(gh auth status 2>/dev/null | grep -B1 "Active account: true" | head -1 | awk '{print $NF}') || true
if [[ "$ACTIVE" != "prmt-it-sys" ]]; then
  echo "Switching gh to prmt-it-sys…"
  gh auth switch --user prmt-it-sys
fi

git add data.enc.json
git commit -m "Data refresh: $(basename "$XLSX")"
git push
echo "Pushed — GitHub Pages redeploys in ~1 minute."
