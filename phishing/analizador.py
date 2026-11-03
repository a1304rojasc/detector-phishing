"""Orquesta el análisis: parsea el correo, ejecuta cada detector y puntúa."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import adjuntos, autenticacion, dominios, enlaces, remitente, urgencia
from .modelo import Correo, Senal
from .parser import parsear_bytes
from .puntaje import asignar_pesos, calcular, nivel

DETECTORES = [remitente, autenticacion, enlaces, dominios, urgencia, adjuntos]


@dataclass
class Resultado:
    archivo: str
    asunto: str
    remitente: str
    puntaje: int
    nivel: str
    senales: list[Senal] = field(default_factory=list)
    error: str = ""

    def a_dict(self) -> dict:
        return {
            "archivo": self.archivo, "asunto": self.asunto, "remitente": self.remitente,
            "puntaje": self.puntaje, "nivel": self.nivel, "error": self.error,
            "senales": [s.a_dict() for s in self.senales],
        }


def analizar_correo(c: Correo, archivo: str = "") -> Resultado:
    senales: list[Senal] = []
    for det in DETECTORES:
        senales.extend(det.detectar(c))
    asignar_pesos(senales)
    senales.sort(key=lambda s: -s.peso)
    # Una señal repetida (mismo código) solo suma una vez: las demás quedan en 0.
    contadas: set[str] = set()
    for s in senales:
        if s.codigo in contadas:
            s.peso = 0
        contadas.add(s.codigo)
    p = calcular(senales)
    return Resultado(archivo, c.asunto, c.de, p, nivel(p), senales)


def analizar_bytes(datos: bytes, archivo: str = "") -> Resultado:
    return analizar_correo(parsear_bytes(datos), archivo)


def analizar_archivo(ruta: str | Path) -> Resultado:
    ruta = Path(ruta)
    try:
        return analizar_bytes(ruta.read_bytes(), str(ruta))
    except Exception as exc:  # un archivo dañado no debe detener el lote
        return Resultado(str(ruta), "", "", 0, "error", [], f"{type(exc).__name__}: {exc}")
