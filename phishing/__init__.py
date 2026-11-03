"""Detector de señales de phishing en correos .eml (solo librería estándar)."""

from .analizador import analizar_archivo, analizar_bytes, Resultado
from .modelo import Senal

__all__ = ["analizar_archivo", "analizar_bytes", "Resultado", "Senal"]
__version__ = "1.0.0"
