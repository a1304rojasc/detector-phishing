"""Salidas: texto legible, JSON y HTML autocontenido.

Todo dato que proviene del correo se considera NO confiable: en HTML se
escapa con html.escape (incluidas comillas) y la página declara una CSP
que bloquea scripts, imágenes y recursos remotos.
"""

from __future__ import annotations

import json
from datetime import datetime
from html import escape

from .analizador import Resultado

_ICONO = {"bajo": "🟢", "medio": "🟡", "alto": "🔴", "error": "⚠️"}


def _limpio(t: str) -> str:
    """Quita caracteres de control para que no alteren la terminal."""
    return "".join(c if c.isprintable() or c in "\t" else "�" for c in (t or ""))


def texto(resultados: list[Resultado]) -> str:
    lineas = []
    for r in resultados:
        lineas.append("=" * 72)
        lineas.append(f"Archivo : {_limpio(r.archivo)}")
        if r.error:
            lineas.append(f"ERROR   : {_limpio(r.error)}")
            continue
        lineas.append(f"Asunto  : {_limpio(r.asunto)}")
        lineas.append(f"De      : {_limpio(r.remitente)}")
        lineas.append(f"Riesgo  : {r.puntaje}/100  {_ICONO.get(r.nivel, '')} {r.nivel.upper()}")
        if not r.senales:
            lineas.append("  Sin señales de phishing detectadas.")
        for s in r.senales:
            lineas.append(f"  [+{s.peso:>2}] {s.titulo} ({s.codigo})" + ("  · repetida, no suma" if s.peso == 0 and s.codigo != "URGENCIA" else ""))
            lineas.append(f"         Evidencia : {_limpio(s.evidencia)}")
            lineas.append(f"         Por qué   : {s.explicacion}")
    if len(resultados) > 1:
        cuenta = {n: sum(r.nivel == n for r in resultados) for n in ("alto", "medio", "bajo", "error")}
        lineas.append("=" * 72)
        lineas.append(f"Total: {len(resultados)} correo(s) — alto: {cuenta['alto']}, medio: {cuenta['medio']}, "
                      f"bajo: {cuenta['bajo']}, errores: {cuenta['error']}")
    return "\n".join(lineas)


def como_json(resultados: list[Resultado]) -> str:
    return json.dumps([r.a_dict() for r in resultados], ensure_ascii=False, indent=2)


_CSS = """
:root{--fondo:#f6f7f9;--carta:#fff;--txt:#1d2433;--sub:#5b6475;--borde:#dde1e8;
--bajo:#1f8a4c;--medio:#b7791f;--alto:#c53030}
@media (prefers-color-scheme:dark){:root{--fondo:#12151b;--carta:#1b2029;--txt:#e6e9ef;--sub:#9aa3b2;--borde:#2c3340}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;font:15px/1.5 system-ui,sans-serif;background:var(--fondo);color:var(--txt)}
main{max-width:960px;margin:auto}h1{margin:0 0 4px}.sub{color:var(--sub);margin:0 0 20px}
table{width:100%;border-collapse:collapse;background:var(--carta);border:1px solid var(--borde);border-radius:8px;overflow:hidden;margin-bottom:24px}
th,td{padding:8px 10px;border-bottom:1px solid var(--borde);text-align:left;vertical-align:top;overflow-wrap:anywhere}
.carta{background:var(--carta);border:1px solid var(--borde);border-radius:8px;padding:16px;margin-bottom:16px}
.nivel{display:inline-block;padding:2px 10px;border-radius:99px;color:#fff;font-weight:600;font-size:13px}
.bajo{background:var(--bajo)}.medio{background:var(--medio)}.alto{background:var(--alto)}.error{background:#666}
.barra{height:8px;background:var(--borde);border-radius:4px;overflow:hidden;margin:6px 0 12px}
.barra span{display:block;height:100%}code{overflow-wrap:anywhere;font-size:13px}
ul{padding-left:18px}li{margin-bottom:8px}.peso{font-weight:700}
"""


def html(resultados: list[Resultado]) -> str:
    e = lambda t: escape(str(t or ""), quote=True)  # noqa: E731
    filas, cartas = [], []
    for i, r in enumerate(resultados):
        filas.append(
            f"<tr><td><a href=\"#c{i}\">{e(r.archivo)}</a></td><td>{e(r.asunto)}</td>"
            f"<td>{r.puntaje}</td><td><span class=\"nivel {e(r.nivel)}\">{e(r.nivel)}</span></td></tr>")
        items = "".join(
            f"<li><span class=\"peso\">+{s.peso}</span> <strong>{e(s.titulo)}</strong> "
            f"<small>({e(s.codigo)})</small><br><code>{e(s.evidencia)}</code><br>{e(s.explicacion)}</li>"
            for s in r.senales) or "<li>Sin señales detectadas.</li>"
        color = {"bajo": "var(--bajo)", "medio": "var(--medio)", "alto": "var(--alto)"}.get(r.nivel, "#666")
        cuerpo = f"<p><strong>Error:</strong> {e(r.error)}</p>" if r.error else f"<ul>{items}</ul>"
        cartas.append(
            f"<section class=\"carta\" id=\"c{i}\"><h2>{e(r.asunto) or '(sin asunto)'}</h2>"
            f"<div>Archivo: <code>{e(r.archivo)}</code></div><div>De: <code>{e(r.remitente)}</code></div>"
            f"<div>Riesgo: <strong>{r.puntaje}/100</strong> <span class=\"nivel {e(r.nivel)}\">{e(r.nivel)}</span></div>"
            f"<div class=\"barra\"><span style=\"width:{r.puntaje}%;background:{color}\"></span></div>"
            f"{cuerpo}</section>")
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        f"<title>Reporte de phishing</title><style>{_CSS}</style></head><body><main>"
        f"<h1>Reporte de phishing</h1><p class=\"sub\">{len(resultados)} correo(s) analizados · {fecha}</p>"
        "<table><thead><tr><th>Archivo</th><th>Asunto</th><th>Puntaje</th><th>Nivel</th></tr></thead><tbody>"
        + "".join(filas) + "</tbody></table>" + "".join(cartas) + "</main></body></html>")
