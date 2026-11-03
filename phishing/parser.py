"""Lectura segura de archivos .eml.

Solo se *lee* el correo: no se abren enlaces, no se descargan recursos
remotos y los adjuntos nunca se guardan ni se ejecutan (solo se anotan
nombre, tipo y tamaño).
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser

from .modelo import Adjunto, Correo, Enlace

_URL_TEXTO = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+")


class _ExtractorHTML(HTMLParser):
    """Extrae texto visible y enlaces <a href> sin interpretar scripts."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.texto: list[str] = []
        self.enlaces: list[Enlace] = []
        self._href: str | None = None
        self._texto_a: list[str] = []
        self._ignorar = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self._ignorar += 1
        elif tag == "a":
            href = dict(attrs).get("href")
            if href is not None:
                self._href = href.strip()
                self._texto_a = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.texto.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self._ignorar = max(0, self._ignorar - 1)
        elif tag == "a" and self._href is not None:
            self.enlaces.append(Enlace(self._href, " ".join("".join(self._texto_a).split()), "html"))
            self._href = None

    def handle_data(self, data):
        if self._ignorar:
            return
        self.texto.append(data)
        if self._href is not None:
            self._texto_a.append(data)


def _contenido(parte: EmailMessage) -> str:
    try:
        return parte.get_content()
    except (LookupError, UnicodeError, AssertionError, KeyError):
        datos = parte.get_payload(decode=True) or b""
        return datos.decode("utf-8", errors="replace")


def _cabecera(msg: EmailMessage, nombre: str) -> str:
    try:
        valor = msg.get(nombre)
        return "" if valor is None else str(valor)
    except Exception:  # encabezado malformado: se usa el valor crudo
        for k, v in msg.raw_items():
            if k.lower() == nombre.lower():
                return str(v)
        return ""


def parsear_bytes(datos: bytes) -> Correo:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(datos)
    from .util import direccion
    from email.utils import parseaddr

    c = Correo()
    c.asunto = _cabecera(msg, "Subject")
    c.de = _cabecera(msg, "From")
    c.de_nombre, _ = parseaddr(c.de)
    c.de_direccion = direccion(c.de)
    c.reply_to = _cabecera(msg, "Reply-To")
    c.return_path = _cabecera(msg, "Return-Path")
    c.fecha = _cabecera(msg, "Date")
    c.encabezados = [(k, str(v)) for k, v in msg.raw_items()]

    textos: list[str] = []
    htmls: list[str] = []
    for parte in msg.walk():
        if parte.is_multipart():
            continue
        tipo = parte.get_content_type()
        nombre = parte.get_filename()
        disp = parte.get_content_disposition()
        if nombre or disp == "attachment":
            carga = parte.get_payload(decode=True) or b""
            c.adjuntos.append(Adjunto(nombre or "(sin nombre)", tipo, len(carga)))
            continue
        if tipo == "text/plain":
            textos.append(_contenido(parte))
        elif tipo == "text/html":
            htmls.append(_contenido(parte))

    c.html = "\n".join(htmls)
    plano = "\n".join(textos)
    texto_html = ""
    if c.html:
        ext = _ExtractorHTML()
        try:
            ext.feed(c.html)
            ext.close()
        except Exception:
            pass
        c.enlaces.extend(ext.enlaces)
        texto_html = "".join(ext.texto)
    c.texto = (plano + "\n" + texto_html).strip()

    vistos = {e.href for e in c.enlaces}
    for url in _URL_TEXTO.findall(plano):
        url = url.rstrip(".,;:!?")
        if url not in vistos:
            vistos.add(url)
            c.enlaces.append(Enlace(url, "", "texto"))
    return c


def parsear_archivo(ruta) -> Correo:
    with open(ruta, "rb") as f:
        return parsear_bytes(f.read())
