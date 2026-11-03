"""Señal 4: dominios parecidos (typosquatting y homógrafos).

Para cada dominio del correo (From, Reply-To, Return-Path y enlaces):
1. Punycode (xn--): se decodifica y se avisa, porque permite mezclar
   alfabetos (p. ej. una «о» cirílica en lugar de una «o» latina).
2. Se normaliza la etiqueta principal (confundibles: 0→o, 1→l, rn→m,
   cirílico→latino…) y se compara con cada marca conocida:
   - igual tras normalizar pero distinto en bruto → homógrafo/sustitución;
   - distancia de edición 1 (o 2 en nombres largos) → typosquatting;
   - la marca aparece dentro del dominio (paypal-seguridad.test) → marca embebida.
"""

from __future__ import annotations

from .marcas import MARCAS, es_dominio_de_alguna_marca, es_oficial
from .modelo import Correo, Senal
from .util import (decodificar_punycode, dominio_de_correo, esqueletos,
                   etiqueta_principal, es_ip, host_de_url, levenshtein)


def hosts_del_correo(c: Correo) -> list[tuple[str, str]]:
    """(host, de dónde salió) sin repetir."""
    pares = []
    for nombre, valor in (("From", c.de), ("Reply-To", c.reply_to), ("Return-Path", c.return_path)):
        d = dominio_de_correo(valor)
        if d:
            pares.append((d, nombre))
    for e in c.enlaces:
        h = host_de_url(e.href)
        if h:
            pares.append((h, "enlace"))
    vistos, salida = set(), []
    for h, o in pares:
        if h not in vistos:
            vistos.add(h)
            salida.append((h, o))
    return salida


def _umbral(marca: str) -> int:
    if len(marca) < 5:
        return 0
    return 2 if len(marca) >= 9 else 1


def analizar_host(host: str) -> list[tuple[str, str, str]]:
    """Devuelve [(codigo, marca, detalle)] para un host."""
    if es_ip(host) or es_dominio_de_alguna_marca(host):
        return []
    hallazgos = []
    unicode_host = decodificar_punycode(host)
    if "xn--" in host:
        hallazgos.append(("DOMINIO_PUNYCODE", "", f"{host} se muestra como «{unicode_host}»"))

    principal = etiqueta_principal(unicode_host)
    crudo = principal.lower()
    variantes = esqueletos(principal)
    etiquetas = [e for e in unicode_host.split(".")[:-1] if e]
    for marca in MARCAS:
        if es_oficial(marca, host):
            continue
        if marca in variantes and crudo != marca:
            hallazgos.append(("DOMINIO_PARECIDO", marca, f"«{principal}» imita a «{marca}» (caracteres sustituidos)"))
            continue
        u = _umbral(marca)
        if u and min(levenshtein(v, marca) for v in variantes) <= u and crudo != marca:
            hallazgos.append(("DOMINIO_PARECIDO", marca, f"«{principal}» está a {min(levenshtein(v, marca) for v in variantes)} letra(s) de «{marca}»"))
            continue
        # Marca usada tal cual en un dominio que no es suyo.
        for et in etiquetas:
            ev = esqueletos(et)
            if (marca in ev) or (len(marca) >= 5 and any(marca in x for x in ev)):
                hallazgos.append(("DOMINIO_MARCA_EMBEBIDA", marca, f"«{marca}» aparece en {unicode_host}, que no es un dominio oficial"))
                break
    return hallazgos


_TEXTOS = {
    "DOMINIO_PUNYCODE": ("Dominio internacionalizado (punycode)",
                         "Los dominios xn-- pueden usar letras de otros alfabetos que se ven idénticas."),
    "DOMINIO_PARECIDO": ("Dominio parecido a una marca",
                         "Typosquatting: el dominio imita a una marca conocida cambiando pocas letras."),
    "DOMINIO_MARCA_EMBEBIDA": ("Marca dentro de un dominio ajeno",
                               "Usar el nombre de una marca dentro de otro dominio aparenta legitimidad."),
}


def detectar(c: Correo) -> list[Senal]:
    senales = []
    for host, origen in hosts_del_correo(c):
        for cod, _marca, detalle in analizar_host(host):
            tit, exp = _TEXTOS[cod]
            senales.append(Senal(cod, tit, f"[{origen}] {detalle}", exp))
    return senales
