"""Interfaz de línea de comandos.

    python -m phishing analizar correo.eml
    python -m phishing analizar carpeta/ --json
    python -m phishing analizar carpeta/ --html reporte.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import reporte
from .analizador import analizar_archivo
from .marcas import cargar_marcas


def _archivos(rutas: list[str]) -> list[Path]:
    salida: list[Path] = []
    for r in rutas:
        p = Path(r)
        if p.is_dir():
            salida.extend(sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() == ".eml"))
        elif p.is_file():
            salida.append(p)
        else:
            print(f"Aviso: no existe {r}", file=sys.stderr)
    return salida


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m phishing", description="Detector de señales de phishing en correos .eml")
    sub = ap.add_subparsers(dest="comando", required=True)
    a = sub.add_parser("analizar", help="Analiza archivos .eml o carpetas")
    a.add_argument("rutas", nargs="+", help="Archivos .eml o carpetas")
    a.add_argument("--json", action="store_true", help="Salida en JSON")
    a.add_argument("--html", metavar="ARCHIVO", help="Genera un reporte HTML autocontenido")
    a.add_argument("--marcas", metavar="JSON", help="Marcas extra: {\"marca\": [\"dominio\", ...]}")
    args = ap.parse_args(argv)

    if args.marcas:
        cargar_marcas(args.marcas)
    archivos = _archivos(args.rutas)
    if not archivos:
        print("No se encontraron archivos .eml.", file=sys.stderr)
        return 2
    resultados = [analizar_archivo(f) for f in archivos]

    if args.json:
        print(reporte.como_json(resultados))
    else:
        print(reporte.texto(resultados))
    if args.html:
        Path(args.html).write_text(reporte.html(resultados), encoding="utf-8")
        print(f"Reporte HTML guardado en {args.html}", file=sys.stderr)
    return 0
