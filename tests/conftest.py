import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from phishing.parser import parsear_bytes  # noqa: E402

EJEMPLOS = RAIZ / "ejemplos"


def construir(encabezados: dict | None = None, cuerpo: str = "Hola.", html: str | None = None,
              adjuntos: list[tuple[str, str]] | None = None) -> bytes:
    """Arma un .eml mínimo para pruebas."""
    enc = {"From": "Ana <ana@example.com>", "To": "luis@example.org", "Subject": "Prueba"}
    enc.update(encabezados or {})
    lineas = [f"{k}: {v}" for k, v in enc.items() if v is not None]
    lineas.append("MIME-Version: 1.0")
    partes = []
    if html is not None:
        partes.append(("text/html; charset=utf-8", html, None))
    else:
        partes.append(("text/plain; charset=utf-8", cuerpo, None))
    for nombre, tipo in adjuntos or []:
        partes.append((tipo, "contenido", nombre))
    lineas.append('Content-Type: multipart/mixed; boundary="B"')
    lineas.append("")
    for tipo, contenido, nombre in partes:
        lineas.append("--B")
        lineas.append(f"Content-Type: {tipo}")
        if nombre:
            lineas.append(f'Content-Disposition: attachment; filename="{nombre}"')
        lineas.append("")
        lineas.append(contenido)
    lineas.append("--B--")
    return "\r\n".join(lineas).encode("utf-8")


@pytest.fixture
def correo():
    return lambda **kw: parsear_bytes(construir(**kw))
