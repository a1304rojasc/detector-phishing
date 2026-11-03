"""Estructuras de datos compartidas por todos los detectores."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Senal:
    """Una señal de phishing encontrada en un correo."""

    codigo: str          # identificador estable, p. ej. "AUTH_DMARC_FALLA"
    titulo: str          # nombre corto legible
    evidencia: str       # qué encabezado, enlace o texto la provocó
    explicacion: str     # por qué es sospechoso (español, una línea)
    peso: int = 0        # puntos que aporta (lo asigna puntaje.py si es 0)

    def a_dict(self) -> dict:
        return asdict(self)


@dataclass
class Enlace:
    href: str
    texto: str = ""      # texto visible (vacío si viene de texto plano)
    origen: str = "texto"  # "html" o "texto"


@dataclass
class Adjunto:
    nombre: str
    tipo: str
    tamano: int = 0


@dataclass
class Correo:
    """Vista ya procesada de un correo. Todo su contenido es NO confiable."""

    asunto: str = ""
    de: str = ""                 # encabezado From completo
    de_nombre: str = ""
    de_direccion: str = ""
    reply_to: str = ""
    return_path: str = ""
    fecha: str = ""
    encabezados: list[tuple[str, str]] = field(default_factory=list)
    texto: str = ""              # texto plano + texto extraído del HTML
    html: str = ""
    enlaces: list[Enlace] = field(default_factory=list)
    adjuntos: list[Adjunto] = field(default_factory=list)

    def encabezado(self, nombre: str) -> list[str]:
        n = nombre.lower()
        return [v for k, v in self.encabezados if k.lower() == n]
