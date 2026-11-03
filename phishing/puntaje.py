"""Cálculo del puntaje de riesgo (0–100) y nivel.

Cada tipo de señal (código) suma su peso UNA sola vez, aunque aparezca
varias veces (p. ej. cinco enlaces engañosos suman lo mismo que uno).
La urgencia tiene peso variable (ver urgencia.peso_urgencia).
El total se limita a 100.

Niveles: 0–29 bajo · 30–59 medio · 60–100 alto.
"""

from __future__ import annotations

from .modelo import Senal

PESOS: dict[str, int] = {
    # 1. Remitente
    "REMITENTE_REPLY_TO": 15,
    "REMITENTE_RETURN_PATH": 10,
    "REMITENTE_SUPLANTA_MARCA": 25,
    # 2. Autenticación
    "AUTH_SPF_FALLA": 15,
    "AUTH_DKIM_FALLA": 15,
    "AUTH_DMARC_FALLA": 25,
    "AUTH_DESALINEADO": 10,
    "AUTH_AUSENTE": 10,
    # 3. Enlaces
    "ENLACE_TEXTO_ENGANOSO": 25,
    "ENLACE_ESQUEMA_PELIGROSO": 25,
    "URL_IP": 20,
    "URL_ACORTADOR": 10,
    "URL_CON_ARROBA": 20,
    # 4. Dominios
    "DOMINIO_PARECIDO": 30,
    "DOMINIO_PUNYCODE": 15,
    "DOMINIO_MARCA_EMBEBIDA": 20,
    # 5. Urgencia: variable (5, 12, 18 o 25)
    "URGENCIA": 0,
    # Extras: adjuntos
    "ADJUNTO_EJECUTABLE": 30,
    "ADJUNTO_DOBLE_EXTENSION": 35,
    "ADJUNTO_RIESGOSO": 15,
}

UMBRAL_MEDIO = 30
UMBRAL_ALTO = 60


def asignar_pesos(senales: list[Senal]) -> None:
    for s in senales:
        if not s.peso:
            s.peso = PESOS.get(s.codigo, 10)


def calcular(senales: list[Senal]) -> int:
    por_codigo: dict[str, int] = {}
    for s in senales:
        por_codigo[s.codigo] = max(por_codigo.get(s.codigo, 0), s.peso)
    return min(100, sum(por_codigo.values()))


def nivel(puntaje: int) -> str:
    if puntaje >= UMBRAL_ALTO:
        return "alto"
    if puntaje >= UMBRAL_MEDIO:
        return "medio"
    return "bajo"
