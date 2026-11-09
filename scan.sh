#!/usr/bin/env bash
# scan.sh — corre todos los escáneres y guarda la salida cruda en scans/<version>/
# Uso:  bash scan.sh v0      (o v1)
#       PORT=8000 bash scan.sh v0   si tu app no usa el puerto 5000
set -u
V="${1:-}"
if [[ "$V" != "v0" && "$V" != "v1" ]]; then
  echo "Uso: bash scan.sh v0|v1"; exit 1
fi
PORT="${PORT:-5000}"
URL="http://127.0.0.1:${PORT}"
OUT="scans/${V}"
mkdir -p "$OUT"
EXCL_DIRS=".venv,venv,scans,__pycache__"
echo "### Escaneo ${V} — $(date '+%F %T') — destino ${URL}" | tee "$OUT/run.log"
git rev-parse --short HEAD 2>/dev/null | sed 's/^/commit: /' | tee -a "$OUT/run.log"

echo "== [1/6] ss -tulpn" | tee -a "$OUT/run.log"
ss -tulpn > "$OUT/ss.txt" 2>&1

echo "== [2/6] pip-audit (SCA)" | tee -a "$OUT/run.log"
pip-audit -r requirements.txt --aliases on --desc off --progress-spinner off \
  -f json -o "$OUT/pip-audit.json" >>"$OUT/run.log" 2>&1
pip-audit -r requirements.txt --aliases on --desc off --progress-spinner off \
  > "$OUT/pip-audit.txt" 2>&1

echo "== [3/6] bandit (SAST)" | tee -a "$OUT/run.log"
BX=$(echo "$EXCL_DIRS" | sed 's/[^,]*/.\/&/g')
bandit -r . -x "$BX" -f txt  -o "$OUT/bandit.txt"  >>"$OUT/run.log" 2>&1
bandit -r . -x "$BX" -f json -o "$OUT/bandit.json" >>"$OUT/run.log" 2>&1

echo "== [4/6] semgrep (p/owasp-top-ten + p/secrets)" | tee -a "$OUT/run.log"
SX=(); IFS=',' read -ra D <<<"$EXCL_DIRS"; for d in "${D[@]}"; do SX+=(--exclude "$d"); done
semgrep scan --config p/owasp-top-ten --config p/secrets "${SX[@]}" \
  --metrics off --text-output "$OUT/semgrep.txt" --json-output "$OUT/semgrep.json" . \
  >>"$OUT/run.log" 2>&1

echo "== [5/6] gitleaks (historial git)" | tee -a "$OUT/run.log"
gitleaks detect --source . -v --redact --report-format json \
  --report-path "$OUT/gitleaks.json" > "$OUT/gitleaks.txt" 2>&1

echo "== [6/6] ZAP baseline (pasivo) contra ${URL}" | tee -a "$OUT/run.log"
if curl -s -o /dev/null --max-time 5 "$URL"; then
  chmod a+rwx "$OUT"
  docker run --rm --network host -v "$PWD/$OUT":/zap/wrk:rw -t \
    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "$URL" \
    -r zap_report.html -J zap_report.json -w zap_report.md \
    > "$OUT/zap.txt" 2>&1
else
  echo "   !! La app no responde en ${URL}: ZAP omitido. Levántala y repite." | tee -a "$OUT/run.log"
fi

echo "== Resumen" | tee -a "$OUT/run.log"
python3 - "$OUT" <<'PY' | tee "$OUT/summary.txt"
import json, sys, os
out = sys.argv[1]
def load(name):
    p = os.path.join(out, name)
    try:
        with open(p) as f: return json.load(f)
    except Exception: return None
pa = load("pip-audit.json")
if pa:
    deps = [d for d in pa.get("dependencies", []) if d.get("vulns")]
    uniq = {(d["name"], v["id"]) for d in deps for v in d["vulns"]}
    print(f"pip-audit : {len(uniq)} avisos únicos en {len(deps)} paquetes (salida cruda puede repetir IDs)")
else: print("pip-audit : sin salida (revisa run.log)")
b = load("bandit.json")
if b:
    from collections import Counter
    r = b.get("results", [])
    c = Counter(x["issue_severity"] for x in r)
    print(f"bandit    : {len(r)} hallazgos  " + " ".join(f"{k}={v}" for k, v in sorted(c.items())))
else: print("bandit    : sin salida")
s = load("semgrep.json")
print(f"semgrep   : {len(s.get('results', []))} hallazgos" if s else "semgrep   : sin salida")
g = load("gitleaks.json")
print(f"gitleaks  : {len(g)} secretos" if isinstance(g, list) else "gitleaks  : sin salida (0 o error, revisa gitleaks.txt)")
z = load("zap_report.json")
if z:
    alerts = [a for site in z.get("site", []) for a in site.get("alerts", [])]
    from collections import Counter
    c = Counter(a.get("riskdesc", "?").split(" ")[0] for a in alerts)
    print(f"ZAP       : {len(alerts)} alertas  " + " ".join(f"{k}={v}" for k, v in sorted(c.items())))
else: print("ZAP       : sin salida")
PY
echo "Salidas crudas en $OUT/"
