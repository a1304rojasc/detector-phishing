"""Extra: adjuntos peligrosos.

Solo se mira el nombre declarado del archivo; nunca se guarda ni se abre.
"""

from __future__ import annotations

import re

from .modelo import Correo, Senal

EJECUTABLES = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "cpl", "dll",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "hta", "jar", "lnk",
    "reg", "iso", "img", "vhd", "apk", "sh", "app",
}
RIESGOSOS = {"html", "htm", "shtml", "svg", "docm", "xlsm", "pptm", "xlam", "one"}
_DOCUMENTO = r"(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|zip|mp3|mp4)"


def detectar(c: Correo) -> list[Senal]:
    senales = []
    for a in c.adjuntos:
        nombre = a.nombre.strip().lower().rstrip(". ")
        ext = nombre.rsplit(".", 1)[-1] if "." in nombre else ""
        if re.search(rf"\.{_DOCUMENTO}\s*\.[a-z0-9]{{1,5}}$", nombre) and ext in EJECUTABLES | RIESGOSOS:
            senales.append(Senal("ADJUNTO_DOBLE_EXTENSION", "Adjunto con doble extensión", a.nombre,
                                 f"Parece un documento, pero en realidad es un archivo .{ext}."))
        elif ext in EJECUTABLES:
            senales.append(Senal("ADJUNTO_EJECUTABLE", "Adjunto ejecutable", f"{a.nombre} ({a.tipo})",
                                 f"Los archivos .{ext} pueden ejecutar programas en tu equipo."))
        elif ext in RIESGOSOS:
            senales.append(Senal("ADJUNTO_RIESGOSO", "Adjunto de tipo riesgoso", f"{a.nombre} ({a.tipo})",
                                 f"Los .{ext} pueden contener formularios falsos o macros."))
        if "‮" in a.nombre:
            senales.append(Senal("ADJUNTO_DOBLE_EXTENSION", "Nombre de adjunto invertido (RLO)", repr(a.nombre),
                                 "Un carácter invisible invierte el texto para ocultar la extensión real."))
    return senales
