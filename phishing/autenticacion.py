"""Señal 2: SPF / DKIM / DMARC.

Lee Authentication-Results y Received-SPF (agregados por el servidor
receptor). Marca resultados fallidos y dominios autenticados que no
coinciden (no están alineados) con el dominio del From.

Nota: estos encabezados pueden falsificarse si el correo no pasó por un
servidor confiable; solo deben creerse los que agrega tu propio servidor.
"""

from __future__ import annotations

import re

from .modelo import Correo, Senal
from .util import dominio_de_correo, dominio_organizacional, recortar

_RES = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_FALLA = {"fail", "softfail", "permerror", "temperror"}


def _dominios(ar: str, clave: str) -> list[str]:
    return [d.lower().strip(".>") for d in re.findall(rf"{clave}\s*=\s*\"?(?:[^\s;@\"]*@)?([\w.-]+)", ar, re.I)]


def detectar(c: Correo) -> list[Senal]:
    senales: list[Senal] = []
    org_from = dominio_organizacional(dominio_de_correo(c.de))
    resultados = c.encabezado("Authentication-Results")
    rspf = c.encabezado("Received-SPF")

    if not resultados and not rspf:
        return [Senal(
            "AUTH_AUSENTE", "Sin resultados de autenticación",
            "No hay encabezados Authentication-Results ni Received-SPF",
            "No se puede verificar que el remitente sea quien dice ser.",
        )]

    vistos: dict[str, str] = {}
    for ar in resultados:
        for mec, res in _RES.findall(ar):
            mec, res = mec.lower(), res.lower()
            # Si hay varios resultados del mismo mecanismo, prevalece el peor.
            if mec not in vistos or res in _FALLA or res == "none":
                vistos[mec] = res
    for r in rspf:
        res = r.strip().split()[0].lower() if r.strip() else ""
        if res and ("spf" not in vistos or res in _FALLA):
            vistos["spf"] = res

    textos = {
        "spf": ("AUTH_SPF_FALLA", "SPF falló", "El servidor que envió no está autorizado por el dominio."),
        "dkim": ("AUTH_DKIM_FALLA", "DKIM falló", "La firma digital del correo no es válida o fue alterada."),
        "dmarc": ("AUTH_DMARC_FALLA", "DMARC falló", "El dominio del From no respalda este correo (política DMARC)."),
    }
    evid = recortar(" | ".join(resultados + rspf), 200)
    for mec, (cod, tit, exp) in textos.items():
        res = vistos.get(mec)
        if res in _FALLA:
            senales.append(Senal(cod, tit, f"{mec}={res} — {evid}", exp))

    # Alineación: dominios autenticados vs dominio del From.
    if org_from:
        auten = []
        for ar in resultados:
            if re.search(r"dkim\s*=\s*pass", ar, re.I):
                auten += _dominios(ar, r"header\.d") + _dominios(ar, r"header\.i")
            if re.search(r"spf\s*=\s*pass", ar, re.I):
                auten += _dominios(ar, r"smtp\.mailfrom")
        auten = [d for d in auten if d]
        if auten and all(dominio_organizacional(d) != org_from for d in auten):
            senales.append(Senal(
                "AUTH_DESALINEADO", "Autenticación de otro dominio",
                f"From: {org_from} | autenticado como: {', '.join(sorted(set(auten)))}",
                "SPF/DKIM pasaron, pero para un dominio distinto al que se muestra en el From.",
            ))
    return senales
