"""Señal 3 (y extras): enlaces engañosos.

- Texto visible que parece una URL/dominio distinto del destino real.
- Texto visible que nombra una marca pero apunta a un dominio ajeno.
- URLs con dirección IP, acortadores, '@' en la URL o esquemas peligrosos.
Los enlaces nunca se visitan: solo se analiza su texto.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .marcas import es_oficial
from .modelo import Correo, Senal
from .remitente import marcas_en_texto
from .util import dominio_organizacional, es_ip, host_de_url, recortar

_PARECE_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?((?:[\w-]+\.)+(?:[a-z]{2,}|xn--[\w-]+))(?:[:/?#]\S*)?$", re.I)

ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly", "tiny.cc", "rb.gy", "s.id",
}


def detectar(c: Correo) -> list[Senal]:
    senales: list[Senal] = []
    for e in c.enlaces:
        href = e.href.strip()
        esquema = href.split(":", 1)[0].lower() if ":" in href else ""
        if esquema in ("javascript", "data", "vbscript"):
            senales.append(Senal("ENLACE_ESQUEMA_PELIGROSO", "Enlace con esquema peligroso",
                                 recortar(href, 100), "El enlace ejecuta código o incrusta contenido en lugar de abrir una web."))
            continue
        if esquema in ("mailto", "tel", "cid") or href.startswith("#"):
            continue
        host = host_de_url(href)
        if not host:
            continue
        org_real = dominio_organizacional(host)
        texto = e.texto.strip()

        if texto:
            m = _PARECE_URL.match(texto)
            if m:
                org_texto = dominio_organizacional(m.group(1).lower())
                if org_texto != org_real:
                    senales.append(Senal(
                        "ENLACE_TEXTO_ENGANOSO", "El texto del enlace no coincide con su destino",
                        f"Texto «{recortar(texto, 80)}» → destino {recortar(href, 100)}",
                        "Se muestra una dirección, pero el clic lleva a otra distinta.",
                    ))
            else:
                for marca in sorted(marcas_en_texto(texto)):
                    if not es_oficial(marca, host):
                        senales.append(Senal(
                            "ENLACE_TEXTO_ENGANOSO", "Enlace con nombre de marca a dominio ajeno",
                            f"Texto «{recortar(texto, 80)}» → destino {recortar(href, 100)}",
                            f"El texto menciona «{marca}» pero el enlace no va a un dominio de esa marca.",
                        ))
                        break

        if es_ip(host):
            senales.append(Senal("URL_IP", "Enlace a una dirección IP", recortar(href, 100),
                                 "Las empresas legítimas usan dominios, no direcciones IP directas."))
        if org_real in ACORTADORES or host in ACORTADORES:
            senales.append(Senal("URL_ACORTADOR", "Enlace acortado", recortar(href, 100),
                                 "Un acortador oculta el destino real del enlace."))
        try:
            netloc = urlsplit(href if "://" in href else "http://" + href).netloc
        except ValueError:
            netloc = ""
        if "@" in netloc:
            senales.append(Senal("URL_CON_ARROBA", "URL con '@' (usuario falso)", recortar(href, 100),
                                 "Todo lo anterior a '@' se ignora; el destino real es lo que va después."))
    return senales
