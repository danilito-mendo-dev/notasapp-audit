#!/usr/bin/env python3
"""cve_lookup.py — lee scans/<v>/pip-audit.json y consulta, desde TU máquina:
  * NVD API 2.0  -> CVSS 3.1 (puntaje, vector, severidad, fuente) y CWE
  * FIRST EPSS   -> probabilidad de explotación en 30 días y percentil
  * CISA KEV     -> ¿está en el catálogo de vulnerabilidades explotadas?
No inventa nada: si una fuente no devuelve dato, escribe "N/D".

Uso:  python3 cve_lookup.py scans/v0/pip-audit.json
      NVD_API_KEY=xxxx python3 cve_lookup.py ...   (opcional, más rápido)
Salida: <misma carpeta>/cve_lookup.csv, cve_lookup.json y cve_lookup.md
"""
import csv, json, os, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "cve-lookup-lab/1.0"}
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
EPSS = "https://api.first.org/data/v1/epss?cve="
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get_json(url, headers=None, tries=4):
    h = dict(UA, **(headers or {}))
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=30) as r:  # FP esperado de bandit (B310): URL fija https
                return json.load(r)
        except Exception as e:
            print(f"   reintento {i+1}/{tries} ({e})", file=sys.stderr)
            time.sleep(6 * (i + 1))
    return None


def parse_pip_audit(path):
    """Devuelve una fila por (paquete, CVE). pip-audit puede repetir avisos o dar
    dos IDs PYSEC para el mismo CVE: aquí se agrupan para no contar doble."""
    data = json.load(open(path))
    rows = {}
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            ids = [v.get("id", "")] + v.get("aliases", [])
            cves = sorted({i for i in ids if i.startswith("CVE-")}) or ["(sin CVE)"]
            others = {i for i in ids if not i.startswith("CVE-")}
            for cve in cves:
                k = (dep["name"], cve)
                r = rows.setdefault(k, {"package": dep["name"], "version": dep["version"],
                                        "cve": cve, "advisory": set(), "fixed_in": set()})
                r["advisory"] |= others
                r["fixed_in"] |= set(v.get("fix_versions", []))
    out = []
    for r in rows.values():
        r["advisory"] = ",".join(sorted(r["advisory"]))
        r["fixed_in"] = ",".join(sorted(r["fixed_in"])) or "N/D"
        out.append(r)
    return out


def nvd_cvss31(cve, key):
    hdr = {"apiKey": key} if key else {}
    j = get_json(NVD + urllib.parse.quote(cve), hdr)
    res = {"cvss31_score": "N/D", "cvss31_vector": "N/D", "cvss31_severity": "N/D",
           "cvss31_source": "N/D", "nvd_cwe": "N/D", "nvd_status": "N/D"}
    if not j or not j.get("vulnerabilities"):
        return res
    c = j["vulnerabilities"][0]["cve"]
    res["nvd_status"] = c.get("vulnStatus", "N/D")
    mets = c.get("metrics", {}).get("cvssMetricV31", [])
    pick = next((m for m in mets if m.get("type") == "Primary"), mets[0] if mets else None)
    if pick:
        d = pick["cvssData"]
        res.update(cvss31_score=d["baseScore"], cvss31_vector=d["vectorString"],
                   cvss31_severity=d["baseSeverity"],
                   cvss31_source=f'{pick.get("source")} ({pick.get("type")})')
    cwes = sorted({x["value"] for w in c.get("weaknesses", []) for x in w.get("description", [])
                   if x.get("value", "").startswith("CWE-")})
    if cwes:
        res["nvd_cwe"] = ",".join(cwes)
    return res


def main():
    if len(sys.argv) != 2:
        sys.exit("Uso: python3 cve_lookup.py scans/v0/pip-audit.json")
    src = sys.argv[1]
    outdir = os.path.dirname(src) or "."
    key = os.environ.get("NVD_API_KEY")
    rows = parse_pip_audit(src)
    allcves = sorted({r["cve"] for r in rows if r["cve"].startswith("CVE-")})
    print(f"{len(rows)} filas (paquete, CVE), {len(allcves)} CVE únicos")

    print("Descargando catálogo CISA KEV...")
    kevj = get_json(KEV)
    kev = {v["cveID"]: v.get("dateAdded", "") for v in kevj.get("vulnerabilities", [])} if kevj else None
    kev_ver = kevj.get("catalogVersion", "N/D") if kevj else "N/D"

    epss = {}
    if allcves:
        print("Consultando FIRST EPSS...")
        ej = get_json(EPSS + ",".join(allcves))
        for d in (ej or {}).get("data", []):
            epss[d["cve"]] = d

    nvd = {}
    for i, cve in enumerate(allcves, 1):
        print(f"NVD {i}/{len(allcves)}: {cve}")
        nvd[cve] = nvd_cvss31(cve, key)
        time.sleep(0.7 if key else 6.5)  # límite público de NVD: 5 peticiones / 30 s

    out = []
    for r in rows:
        for cve in [r["cve"]]:
            n = nvd.get(cve, {})
            e = epss.get(cve, {})
            kv = "N/D (KEV no descargado)" if kev is None else ("Sí (" + kev[cve] + ")" if cve in kev else "No")
            out.append({
                "package": r["package"], "version": r["version"], "cve": cve,
                "advisory": r["advisory"], "fixed_in": r["fixed_in"],
                "cvss31_score": n.get("cvss31_score", "N/D"),
                "cvss31_vector": n.get("cvss31_vector", "N/D"),
                "cvss31_severity": n.get("cvss31_severity", "N/D"),
                "cvss31_source": n.get("cvss31_source", "N/D"),
                "nvd_cwe": n.get("nvd_cwe", "N/D"), "nvd_status": n.get("nvd_status", "N/D"),
                "epss_pct": f'{float(e["epss"])*100:.3f}' if e else "N/D",
                "epss_percentile": f'{float(e["percentile"])*100:.1f}' if e else "N/D",
                "epss_date": e.get("date", "N/D"), "in_kev": kv,
            })

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(os.path.join(outdir, "cve_lookup.json"), "w") as f:
        json.dump({"queried": stamp, "kev_catalog": kev_ver, "rows": out}, f, indent=2)
    if out:
        with open(os.path.join(outdir, "cve_lookup.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
    md = [f"Consulta: {stamp} · KEV catalogVersion {kev_ver}", "",
          "| Paquete | Versión | CVE | Corregido en | CVSS 3.1 (NVD) | Vector | EPSS % (percentil) | ¿KEV? |",
          "|---|---|---|---|---|---|---|---|"]
    for o in out:
        md.append(f'| {o["package"]} | {o["version"]} | {o["cve"]} | {o["fixed_in"]} | '
                  f'{o["cvss31_score"]} {o["cvss31_severity"]} | `{o["cvss31_vector"]}` | '
                  f'{o["epss_pct"]} ({o["epss_percentile"]}) | {o["in_kev"]} |')
    open(os.path.join(outdir, "cve_lookup.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\nGuardado en {outdir}/cve_lookup.(csv|json|md)")


if __name__ == "__main__":
    main()
