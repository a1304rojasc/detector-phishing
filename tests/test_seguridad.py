"""El contenido del correo es no confiable: el reporte HTML debe escaparlo todo."""

from phishing import reporte
from phishing.analizador import analizar_bytes

from conftest import construir

ATAQUE = '<script>alert("xss")</script>'


def _resultado():
    datos = construir(
        encabezados={"Subject": f"Hola {ATAQUE}", "From": f'"<img src=x onerror=alert(1)>" <a@paypa1.example>'},
        html=f'<a href="javascript:alert(2)">{ATAQUE}</a><a href="http://192.0.2.1/&quot;onmouseover=&quot;x">"><b>x</b></a>',
        adjuntos=[(f"{ATAQUE}.pdf.exe", "application/octet-stream")],
    )
    return analizar_bytes(datos, archivo=f"ruta/{ATAQUE}.eml")


def test_html_escapa_asunto_y_evidencias():
    pagina = reporte.html([_resultado()])
    assert "<script>" not in pagina.lower()
    assert "<img" not in pagina.lower()
    assert "&lt;script&gt;" in pagina
    assert "onerror=alert(1)>" not in pagina
    # Solo nuestras etiquetas: ningún atributo de evento inyectado.
    assert 'onmouseover="' not in pagina


def test_html_tiene_csp_sin_scripts():
    pagina = reporte.html([_resultado()])
    assert "Content-Security-Policy" in pagina and "default-src 'none'" in pagina
    assert "<script" not in pagina.lower()


def test_no_se_abren_enlaces(monkeypatch):
    import socket
    import urllib.request

    def prohibido(*a, **k):
        raise AssertionError("se intentó abrir una conexión de red")

    monkeypatch.setattr(socket, "create_connection", prohibido)
    monkeypatch.setattr(urllib.request, "urlopen", prohibido)
    r = _resultado()
    assert r.senales  # se analizó sin tocar la red


def test_texto_quita_caracteres_de_control():
    datos = construir(encabezados={"Subject": "a\x1b[31mrojo"})
    salida = reporte.texto([analizar_bytes(datos)])
    assert "\x1b" not in salida
