import json

import pytest

from phishing.analizador import analizar_archivo
from phishing.cli import main
from phishing.puntaje import calcular, nivel
from phishing.modelo import Senal

from conftest import EJEMPLOS

LEGITIMOS = sorted(EJEMPLOS.glob("legitimo_*.eml"))
PHISHING = sorted(EJEMPLOS.glob("phishing_*.eml"))


def test_hay_10_ejemplos():
    assert len(LEGITIMOS) == 4 and len(PHISHING) == 6


@pytest.mark.parametrize("ruta", LEGITIMOS, ids=lambda p: p.name)
def test_legitimos_riesgo_bajo(ruta):
    r = analizar_archivo(ruta)
    assert r.nivel == "bajo", [s.codigo for s in r.senales]


@pytest.mark.parametrize("ruta", PHISHING, ids=lambda p: p.name)
def test_phishing_riesgo_medio_o_alto(ruta):
    r = analizar_archivo(ruta)
    assert r.nivel in ("medio", "alto"), (r.puntaje, [s.codigo for s in r.senales])


def test_ejemplos_ejercitan_senales_distintas():
    por_correo = [{s.codigo for s in analizar_archivo(p).senales} for p in PHISHING]
    todas = set().union(*por_correo)
    for cod in ("REMITENTE_REPLY_TO", "REMITENTE_SUPLANTA_MARCA", "AUTH_DMARC_FALLA",
                "ENLACE_TEXTO_ENGANOSO", "DOMINIO_PARECIDO", "DOMINIO_PUNYCODE", "URGENCIA",
                "ADJUNTO_DOBLE_EXTENSION", "URL_IP", "URL_ACORTADOR"):
        assert cod in todas, cod


def test_puntaje_cuenta_cada_codigo_una_vez():
    s = [Senal("URL_IP", "", "", "", 20), Senal("URL_IP", "", "", "", 20), Senal("X", "", "", "", 15)]
    assert calcular(s) == 35
    assert calcular([Senal("A", "", "", "", 90), Senal("B", "", "", "", 90)]) == 100
    assert (nivel(29), nivel(30), nivel(60)) == ("bajo", "medio", "alto")


def test_cli_json_y_html(tmp_path, capsys):
    salida = tmp_path / "r.html"
    assert main(["analizar", str(EJEMPLOS), "--json", "--html", str(salida)]) == 0
    datos = json.loads(capsys.readouterr().out)
    assert len(datos) == 10 and all("puntaje" in d and "senales" in d for d in datos)
    contenido = salida.read_text(encoding="utf-8")
    assert contenido.startswith("<!doctype html>") and "phishing_01_paypal_typo.eml" in contenido


def test_cli_archivo_texto(capsys):
    assert main(["analizar", str(PHISHING[0])]) == 0
    out = capsys.readouterr().out
    assert "Riesgo" in out and "Evidencia" in out


def test_archivo_corrupto_no_detiene(tmp_path):
    p = tmp_path / "roto.eml"
    p.write_bytes(b"\xff\xfe\x00basura sin encabezados")
    r = analizar_archivo(p)
    assert r.nivel in ("bajo", "medio", "alto", "error")
