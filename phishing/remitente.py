"""Señal 1: remitente falso.

- Reply-To o Return-Path de una organización distinta al From.
- Nombre visible que menciona una marca, pero el dominio no es de esa marca.
"""

from __future__ import annotations

import re

from .marcas import MARCAS, es_oficial
from .modelo import Correo, Senal
from .util import dominio_de_correo, dominio_organizacional, esqueletos, recortar


def marcas_en_texto(texto: str) -> set[str]:
    """Marcas mencionadas en un texto corto (nombre visible, texto de enlace)."""
    encontradas = set()
    tokens = re.findall(r"[\w@$|!-]+", texto or "")
    pegado = set()
    for v in esqueletos(texto or ""):
        pegado.add(re.sub(r"[^a-z0-9]", "", v))
    tok_norm = set()
    for t in tokens:
        tok_norm |= esqueletos(t)
    for marca in MARCAS:
        if marca in tok_norm or (len(marca) >= 5 and any(marca in p for p in pegado)):
            encontradas.add(marca)
    return encontradas


def detectar(c: Correo) -> list[Senal]:
    senales: list[Senal] = []
    dom_from = dominio_de_correo(c.de)
    org_from = dominio_organizacional(dom_from)

    if c.reply_to:
        dom_rt = dominio_de_correo(c.reply_to)
        if dom_rt and org_from and dominio_organizacional(dom_rt) != org_from:
            senales.append(Senal(
                "REMITENTE_REPLY_TO", "Reply-To distinto del remitente",
                f"From: {recortar(c.de)} | Reply-To: {recortar(c.reply_to)}",
                "Las respuestas irían a otro dominio; típico de fraude o suplantación.",
            ))

    if c.return_path:
        dom_rp = dominio_de_correo(c.return_path)
        if dom_rp and org_from and dominio_organizacional(dom_rp) != org_from:
            senales.append(Senal(
                "REMITENTE_RETURN_PATH", "Return-Path distinto del remitente",
                f"From: {recortar(c.de)} | Return-Path: {recortar(c.return_path)}",
                "El servidor que envió el correo pertenece a otro dominio que el From visible.",
            ))

    if c.de_nombre and dom_from:
        for marca in sorted(marcas_en_texto(c.de_nombre)):
            if not es_oficial(marca, dom_from):
                senales.append(Senal(
                    "REMITENTE_SUPLANTA_MARCA", "Nombre visible suplanta una marca",
                    f"Nombre «{recortar(c.de_nombre, 60)}» con dominio {dom_from} (marca: {marca})",
                    f"El nombre dice ser «{marca}», pero el dominio no es uno de sus dominios oficiales.",
                ))
                break

    # Dirección dentro del nombre visible: "seguridad@paypal.com" <x@otro.test>
    m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", c.de_nombre or "")
    if m and dominio_organizacional(m.group(1).lower()) != org_from:
        senales.append(Senal(
            "REMITENTE_SUPLANTA_MARCA", "Dirección falsa en el nombre visible",
            f"Nombre «{recortar(c.de_nombre, 60)}» pero la dirección real es {c.de_direccion}",
            "El nombre visible muestra una dirección distinta de la real para engañar.",
        ))
    return senales
