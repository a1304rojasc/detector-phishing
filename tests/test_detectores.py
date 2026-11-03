from phishing import adjuntos, autenticacion, dominios, enlaces, remitente, urgencia

AUTH_OK = ("buzon.example.org; spf=pass smtp.mailfrom=ana@example.com; "
           "dkim=pass header.d=example.com; dmarc=pass header.from=example.com")


def codigos(senales):
    return {s.codigo for s in senales}


# 1. Remitente --------------------------------------------------------------

def test_remitente_reply_to_distinto(correo):
    c = correo(encabezados={"Reply-To": "otro@correo-gratis.test"})
    assert "REMITENTE_REPLY_TO" in codigos(remitente.detectar(c))


def test_remitente_reply_to_mismo_org_no_marca(correo):
    c = correo(encabezados={"Reply-To": "soporte@ayuda.example.com", "Return-Path": "<r@mail.example.com>"})
    assert remitente.detectar(c) == []


def test_remitente_return_path(correo):
    c = correo(encabezados={"Return-Path": "<rebote@masivo.test>"})
    assert "REMITENTE_RETURN_PATH" in codigos(remitente.detectar(c))


def test_remitente_suplanta_marca(correo):
    c = correo(encabezados={"From": "PayPal Seguridad <aviso@cuentas-seguras.test>"})
    s = remitente.detectar(c)
    assert "REMITENTE_SUPLANTA_MARCA" in codigos(s)
    assert "paypal" in s[0].explicacion


def test_remitente_marca_oficial_no_marca(correo):
    c = correo(encabezados={"From": "Banco Ejemplo <avisos@bancoejemplo.test>"})
    assert remitente.detectar(c) == []


def test_remitente_direccion_en_nombre(correo):
    c = correo(encabezados={"From": '"soporte@bancoejemplo.test" <x@otro.test>'})
    assert "REMITENTE_SUPLANTA_MARCA" in codigos(remitente.detectar(c))


# 2. Autenticación ----------------------------------------------------------

def test_auth_todo_pasa(correo):
    c = correo(encabezados={"Authentication-Results": AUTH_OK})
    assert autenticacion.detectar(c) == []


def test_auth_fallos(correo):
    c = correo(encabezados={"Authentication-Results":
                            "mx; spf=fail smtp.mailfrom=a@malo.test; dkim=fail header.d=malo.test; dmarc=fail"})
    assert {"AUTH_SPF_FALLA", "AUTH_DKIM_FALLA", "AUTH_DMARC_FALLA"} <= codigos(autenticacion.detectar(c))


def test_auth_received_spf_softfail(correo):
    c = correo(encabezados={"Received-SPF": "softfail (mx: domain does not designate 198.51.100.1)"})
    assert codigos(autenticacion.detectar(c)) == {"AUTH_SPF_FALLA"}


def test_auth_desalineado(correo):
    c = correo(encabezados={"Authentication-Results":
                            "mx; spf=pass smtp.mailfrom=x@envios.test; dkim=pass header.d=envios.test; dmarc=none"})
    assert "AUTH_DESALINEADO" in codigos(autenticacion.detectar(c))


def test_auth_ausente(correo):
    assert codigos(autenticacion.detectar(correo())) == {"AUTH_AUSENTE"}


# 3. Enlaces ----------------------------------------------------------------

def test_enlace_texto_url_distinta(correo):
    c = correo(html='<a href="http://malo.test/login">https://www.bancoejemplo.test</a>')
    assert "ENLACE_TEXTO_ENGANOSO" in codigos(enlaces.detectar(c))


def test_enlace_texto_marca_dominio_ajeno(correo):
    c = correo(html='<a href="https://malo.test/">Entrar a PayPal</a>')
    assert "ENLACE_TEXTO_ENGANOSO" in codigos(enlaces.detectar(c))


def test_enlace_coherente_no_marca(correo):
    c = correo(html='<a href="https://www.tiendaejemplo.test/x">tiendaejemplo.test</a>'
                    '<a href="https://www.tiendaejemplo.test/y">Ver ofertas</a>')
    assert enlaces.detectar(c) == []


def test_enlace_ip_acortador_arroba_esquema(correo):
    c = correo(html='<a href="http://192.0.2.9/a">clic</a><a href="https://bit.ly/abc">aquí</a>'
                    '<a href="http://paypal.com@198.51.100.4/">ver</a><a href="javascript:alert(1)">x</a>')
    assert {"URL_IP", "URL_ACORTADOR", "URL_CON_ARROBA", "ENLACE_ESQUEMA_PELIGROSO"} <= codigos(enlaces.detectar(c))


def test_enlace_en_texto_plano(correo):
    c = correo(cuerpo="Entra en http://203.0.113.5/verificar ya.")
    assert "URL_IP" in codigos(enlaces.detectar(c))


# 4. Dominios ---------------------------------------------------------------

def test_dominio_typo_digito(correo):
    s = dominios.detectar(correo(encabezados={"From": "a@paypa1.example"}))
    assert "DOMINIO_PARECIDO" in codigos(s)


def test_dominio_rn_por_m(correo):
    c = correo(cuerpo="Ingresa en https://rnicrosoft.example/login")
    assert "DOMINIO_PARECIDO" in codigos(dominios.detectar(c))


def test_dominio_letra_cambiada(correo):
    c = correo(encabezados={"From": "a@netfliz.example"})
    assert "DOMINIO_PARECIDO" in codigos(dominios.detectar(c))


def test_dominio_punycode_homografo(correo):
    s = codigos(dominios.detectar(correo(encabezados={"From": "a@xn--microsft-sbh.example"})))
    assert {"DOMINIO_PUNYCODE", "DOMINIO_PARECIDO"} <= s


def test_dominio_marca_embebida(correo):
    c = correo(encabezados={"From": "a@seguridad.paypal-verificacion.test"})
    assert "DOMINIO_MARCA_EMBEBIDA" in codigos(dominios.detectar(c))


def test_dominio_oficial_y_neutro(correo):
    c = correo(encabezados={"From": "a@paypal.com"}, cuerpo="Ver https://www.example.org/")
    assert dominios.detectar(c) == []


# 5. Urgencia ---------------------------------------------------------------

def test_urgencia_es(correo):
    c = correo(encabezados={"Subject": "URGENTE"}, cuerpo="Su cuenta ha sido suspendida. Verifique su cuenta en 24 horas.")
    s = urgencia.detectar(c)
    assert s and s[0].peso >= 18


def test_urgencia_en(correo):
    c = correo(cuerpo="Your account has been suspended. Verify your account immediately.")
    assert urgencia.detectar(c)[0].peso >= 12


def test_urgencia_sin_acentos_y_vacia(correo):
    assert urgencia.detectar(correo(cuerpo="Último aviso"))
    assert urgencia.detectar(correo(cuerpo="Nos vemos el jueves en la reunión.")) == []


# Extras: adjuntos ----------------------------------------------------------

def test_adjuntos(correo):
    c = correo(adjuntos=[("factura.pdf.exe", "application/octet-stream"),
                         ("script.js", "application/javascript"),
                         ("pago.html", "text/html"),
                         ("informe.pdf", "application/pdf")])
    s = adjuntos.detectar(c)
    assert {"ADJUNTO_DOBLE_EXTENSION", "ADJUNTO_EJECUTABLE", "ADJUNTO_RIESGOSO"} == codigos(s)
    assert not any("informe.pdf" == x.evidencia for x in s)
