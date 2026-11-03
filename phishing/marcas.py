"""Marcas conocidas y sus dominios oficiales.

Se usan para detectar suplantación (nombre visible) y dominios parecidos.
Incluye marcas reales muy suplantadas y marcas ficticias usadas en los
ejemplos (dominios .test). Se puede ampliar en tiempo de ejecución con
`registrar_marca()` o con la opción --marcas de la CLI (archivo JSON).
"""

from __future__ import annotations

import json
from pathlib import Path

from .util import dominio_organizacional

MARCAS: dict[str, set[str]] = {
    # nombre normalizado -> dominios organizacionales oficiales
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.es", "amazon.com.mx"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "office365": {"microsoft.com", "office.com"},
    "outlook": {"microsoft.com", "outlook.com"},
    "google": {"google.com", "gmail.com"},
    "gmail": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "mercadolibre": {"mercadolibre.com", "mercadolibre.com.mx", "mercadolibre.com.ar"},
    "mercadopago": {"mercadopago.com"},
    "santander": {"santander.com", "santander.es"},
    "bbva": {"bbva.com", "bbva.es", "bbva.mx"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "correos": {"correos.es"},
    # Marcas ficticias de los ejemplos
    "bancoejemplo": {"bancoejemplo.test"},
    "tiendaejemplo": {"tiendaejemplo.test"},
    "rapidoenvios": {"rapidoenvios.test"},
}


def registrar_marca(nombre: str, dominios: list[str] | set[str]) -> None:
    clave = "".join(c for c in nombre.lower() if c.isalnum())
    MARCAS.setdefault(clave, set()).update(dominio_organizacional(d) for d in dominios)


def cargar_marcas(ruta: str | Path) -> None:
    """Carga un JSON {"marca": ["dominio1", ...]} y lo agrega a MARCAS."""
    datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
    for nombre, dominios in datos.items():
        registrar_marca(nombre, dominios)


def es_oficial(marca: str, host: str) -> bool:
    return dominio_organizacional(host) in MARCAS.get(marca, set())


def es_dominio_de_alguna_marca(host: str) -> bool:
    org = dominio_organizacional(host)
    return any(org in doms for doms in MARCAS.values())
