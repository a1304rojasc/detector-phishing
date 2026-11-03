"""Utilidades compartidas: dominios, normalización y distancia de edición."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import urlsplit

# Sufijos de segundo nivel frecuentes (aproximación sin la Public Suffix List).
_SEGUNDO_NIVEL = {"co", "com", "org", "net", "gob", "gov", "edu", "ac", "mil", "nom"}


def direccion(valor: str) -> str:
    """Extrae la dirección de correo de un encabezado ('Nombre <a@b>' -> 'a@b')."""
    return parseaddr(valor or "")[1].strip().strip("<>").lower()


def dominio_de_correo(valor: str) -> str:
    d = direccion(valor)
    return d.rsplit("@", 1)[1].strip(".") if "@" in d else ""


def dominio_organizacional(host: str) -> str:
    """'mail.correo.ejemplo.com.mx' -> 'ejemplo.com.mx' (aproximado)."""
    host = (host or "").lower().strip(".")
    if not host or es_ip(host):
        return host
    partes = host.split(".")
    if len(partes) >= 3 and len(partes[-1]) == 2 and partes[-2] in _SEGUNDO_NIVEL:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def etiqueta_principal(host: str) -> str:
    """Etiqueta registrada sin el sufijo: 'login.paypa1.example' -> 'paypa1'."""
    org = dominio_organizacional(host)
    return org.split(".")[0] if org and not es_ip(org) else ""


def es_ip(host: str) -> bool:
    h = (host or "").strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Formas ofuscadas: entero decimal (3232235777) u hexadecimal (0xC0A80001).
    return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", h, re.I))


def host_de_url(url: str) -> str:
    url = (url or "").strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def decodificar_punycode(host: str) -> str:
    """Convierte etiquetas xn-- a Unicode; si falla, devuelve el original."""
    salida = []
    for et in (host or "").split("."):
        if et.startswith("xn--"):
            try:
                et = et[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        salida.append(et)
    return ".".join(salida)


def sin_acentos(texto: str) -> str:
    nfkd = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


# Caracteres confundibles -> letra latina que imitan.
_CONFUNDIBLES = {
    # cirílico
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q",
    "ԝ": "w", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
    # griego
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "ρ": "p", "κ": "k", "τ": "t",
    "υ": "u", "ε": "e", "χ": "x",
    # dígitos y símbolos
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "|": "l", "!": "i",
}
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]


def esqueletos(texto: str) -> set[str]:
    """Formas normalizadas de un texto para comparar contra marcas.

    Aplica NFKC, minúsculas, quita acentos, mapea confundibles y guiones.
    Devuelve varias variantes porque '1' puede imitar 'l' o 'i' y 'rn'
    puede imitar 'm' (o ser legítimo).
    """
    base = sin_acentos(unicodedata.normalize("NFKC", texto).lower())
    base = "".join(_CONFUNDIBLES.get(c, c) for c in base).replace("-", "").replace("_", "")
    variantes = {base, base.replace("l", "i") if "1" in texto else base}
    for a, b in _MULTI:
        variantes |= {v.replace(a, b) for v in list(variantes)}
    return variantes


def levenshtein(a: str, b: str) -> int:
    """Distancia de edición (inserción, borrado, sustitución y transposición)."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            costo = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + costo)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def recortar(texto: str, n: int = 160) -> str:
    texto = " ".join((texto or "").split())
    return texto if len(texto) <= n else texto[: n - 1] + "…"
