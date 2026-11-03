from phishing.util import (decodificar_punycode, dominio_organizacional, es_ip,
                           esqueletos, host_de_url, levenshtein)


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypa1", "paypal") == 1
    assert levenshtein("amazno", "amazon") == 1  # transposición
    assert levenshtein("", "abc") == 3


def test_dominio_organizacional():
    assert dominio_organizacional("login.correo.paypa1.example") == "paypa1.example"
    assert dominio_organizacional("www.tienda.com.mx") == "tienda.com.mx"


def test_esqueletos_confundibles():
    assert "paypal" in esqueletos("paypa1")
    assert "microsoft" in esqueletos("rnicrosoft")
    assert "microsoft" in esqueletos("micrоsoft")  # 'о' cirílica
    assert "amazon" in esqueletos("amaz0n")


def test_punycode_e_ip():
    assert decodificar_punycode("xn--microsft-sbh.example") == "microsоft.example"
    assert es_ip("192.0.2.1") and es_ip("[2001:db8::1]") and es_ip("3232235777")
    assert not es_ip("example.com")
    assert host_de_url("http://usuario@198.51.100.2/x") == "198.51.100.2"
    assert host_de_url("www.example.com/ruta") == "www.example.com"
