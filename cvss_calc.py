#!/usr/bin/env python3
"""cvss_calc.py — calcula el puntaje CVSS 3.1 de TUS hallazgos (CWE sin CVE)
usando la librería `cvss` (pip install cvss dentro del .venv).

Uso:
  python3 cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  python3 cvss_calc.py vectores.csv     # CSV con columnas: id,finding,vector
"""
import csv, sys
from cvss import CVSS3


def calc(vector):
    c = CVSS3(vector)
    return c.clean_vector(), c.scores()[0], c.severities()[0]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    arg = sys.argv[1]
    if arg.endswith(".csv"):
        rows = list(csv.DictReader(open(arg)))
        print(f'{"id":<6} {"score":>5}  {"severidad":<9} vector / hallazgo')
        for r in rows:
            v, s, sev = calc(r["vector"])
            print(f'{r["id"]:<6} {s:>5}  {sev:<9} {v}  — {r.get("finding", "")}')
    else:
        v, s, sev = calc(arg)
        print(f"{v} -> {s} {sev}")


if __name__ == "__main__":
    main()
