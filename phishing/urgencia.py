"""Señal 5: urgencia y presión en el texto (español e inglés).

Se busca en asunto y cuerpo (sin acentos y en minúsculas). El peso crece
con la cantidad de expresiones distintas encontradas (ver puntaje.py).
"""

from __future__ import annotations

import re

from .modelo import Correo, Senal
from .util import sin_acentos

FRASES = [
    # español
    r"urgente", r"de inmediato", r"inmediatamente", r"accion (inmediata|requerida)",
    r"(cuenta|tarjeta|servicio) (ha sido |fue |sera )?(suspendid[ao]|bloquead[ao]|cancelad[ao]|desactivad[ao])",
    r"suspendid[ao]", r"bloquead[ao]", r"\d+ horas", r"hoy mismo", r"ultimo aviso",
    r"verifi(que|ca|car) (su|tu) (cuenta|identidad|informacion|datos)",
    r"confirm(e|a|ar) (su|tu)s? (cuenta|identidad|datos|contrasena)",
    r"actualic(e|a) (su|tu)s? (datos|informacion|pago|contrasena)",
    r"actividad (inusual|sospechosa)", r"acceso no autorizado", r"evite (la|el) (suspension|cierre|cargo)",
    r"pago (inmediato|pendiente|vencido)", r"transferencia", r"confidencial", r"no (lo )?comente",
    r"perdera (el )?acceso", r"premio", r"ha ganado", r"reembolso",
    # inglés
    r"urgent", r"immediately", r"action required", r"within \d+ hours",
    r"(account|card) (has been |is |will be )?(suspended|locked|disabled|limited)",
    r"verify your (account|identity|information)", r"confirm your (account|identity|password|details)",
    r"update your (payment|billing|information|details)", r"unusual (activity|sign-in)",
    r"final notice", r"last warning", r"you have won", r"refund", r"wire transfer",
]
_PATRONES = [re.compile(rf"\b{p}\b") for p in FRASES]


def detectar(c: Correo) -> list[Senal]:
    texto = sin_acentos(f"{c.asunto}\n{c.texto}".lower())
    encontradas: list[str] = []
    for pat in _PATRONES:
        m = pat.search(texto)
        if m and not any(m.group(0) in e or e in m.group(0) for e in encontradas):
            encontradas.append(m.group(0))
    if not encontradas:
        return []
    return [Senal(
        "URGENCIA", "Lenguaje de urgencia o presión",
        f"{len(encontradas)} expresión(es): " + ", ".join(f"«{e}»" for e in encontradas[:8]),
        "Meter prisa o miedo busca que actúes sin pensar ni verificar.",
        peso=peso_urgencia(len(encontradas)),
    )]


def peso_urgencia(n: int) -> int:
    """1 expresión = 5, 2 = 12, 3 = 18, 4 o más = 25."""
    return {0: 0, 1: 5, 2: 12, 3: 18}.get(n, 25)
