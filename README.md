# Detector de phishing

[![tests](https://github.com/a1304rojasc/detector-phishing/actions/workflows/tests.yml/badge.svg)](https://github.com/a1304rojasc/detector-phishing/actions/workflows/tests.yml)

Herramienta en Python (solo librería estándar) que analiza correos en formato `.eml`, busca señales de phishing y asigna un **puntaje de riesgo de 0 a 100** con su nivel (**bajo / medio / alto**). Para cada señal muestra la **evidencia** (qué encabezado, enlace o texto la provocó) y una explicación corta.

## ¿Qué es el phishing?

El phishing es un engaño por correo (o SMS, o mensajería) en el que alguien se hace pasar por una empresa, un banco o una persona de confianza para conseguir que la víctima:

- entregue contraseñas, datos de tarjeta o códigos de verificación,
- abra un adjunto con malware,
- o haga una transferencia (fraude del CEO o *BEC*).

Casi siempre combina **suplantación** (remitente o dominio falsos), **enlaces engañosos** y **presión** («su cuenta será suspendida en 24 horas»). Esta herramienta busca precisamente esas huellas.

## Requisitos

- Python 3.10 o superior.
- Nada más para usar la herramienta. `pytest` solo para los tests.

## Uso de la CLI

```bash
# Un correo
python -m phishing analizar ejemplos/phishing_01_paypal_typo.eml

# Una carpeta (busca *.eml de forma recursiva)
python -m phishing analizar ejemplos/

# Salida en JSON (para otros programas)
python -m phishing analizar ejemplos/ --json

# Reporte HTML autocontenido
python -m phishing analizar ejemplos/ --html reporte.html

# Agregar marcas propias: {"mibanco": ["mibanco.com", "mibanco.com.mx"]}
python -m phishing analizar correo.eml --marcas marcas.json
```

Ejemplo de salida:

```
Archivo : ejemplos/phishing_01_paypal_typo.eml
Asunto  : URGENTE: Su cuenta ha sido suspendida
De      : PayPal <servicio@paypa1.example>
Riesgo  : 100/100  🔴 ALTO
  [+30] Dominio parecido a una marca (DOMINIO_PARECIDO)
         Evidencia : [From] «paypa1» imita a «paypal» (caracteres sustituidos)
         Por qué   : Typosquatting: el dominio imita a una marca conocida cambiando pocas letras.
  ...
```

También se puede usar como biblioteca:

```python
from phishing import analizar_archivo
r = analizar_archivo("correo.eml")
print(r.puntaje, r.nivel, [s.codigo for s in r.senales])
```

## Cómo funciona cada señal

| Módulo | Señal | Qué revisa |
|---|---|---|
| `remitente.py` | **1. Remitente falso** | `Reply-To` o `Return-Path` de una organización distinta a la del `From`; nombre visible que dice ser una marca («PayPal») con un dominio que no es de esa marca; una dirección escrita dentro del nombre visible que no coincide con la real. |
| `autenticacion.py` | **2. SPF / DKIM / DMARC** | Lee `Authentication-Results` y `Received-SPF`. Marca `fail`, `softfail`, `permerror`, `temperror`; la ausencia total de resultados; y la **falta de alineación**: SPF/DKIM pasaron, pero para un dominio distinto al del `From`. |
| `enlaces.py` | **3. Enlaces engañosos** | En HTML compara el texto visible de cada `<a>` con su `href`: si el texto parece una URL de otro dominio, o nombra una marca y el enlace va a un dominio ajeno. Extras: URLs con IP (también decimal/hex), acortadores (`bit.ly`…), `@` dentro de la URL (`http://banco.com@1.2.3.4/`) y esquemas `javascript:`/`data:`. |
| `dominios.py` | **4. Dominios parecidos** | Para cada dominio del correo (From, Reply-To, Return-Path, enlaces): avisa de punycode (`xn--`), lo decodifica y **normaliza caracteres confundibles** (`0→o`, `1→l/i`, `rn→m`, `vv→w`, cirílico/griego→latino). Luego compara con la lista de marcas: igual tras normalizar → homógrafo; **distancia de edición** ≤1 (≤2 en nombres de 9+ letras) → typosquatting; la marca aparece dentro de un dominio ajeno (`paypal-seguridad.test`) → marca embebida. |
| `urgencia.py` | **5. Urgencia y presión** | Expresiones en español e inglés («urgente», «suspendida», «24 horas», «verifique su cuenta», «transferencia», «confidencial», «action required», «verify your account»…), sin importar acentos ni mayúsculas. |
| `adjuntos.py` | **Extra: adjuntos** | Ejecutables (`.exe`, `.js`, `.vbs`, `.ps1`, `.iso`, `.lnk`…), tipos riesgosos (`.html`, `.svg`, macros `.docm`…), **doble extensión** (`factura.pdf.exe`) y el carácter invisible RLO que invierte el nombre. |

La lista de marcas está en `phishing/marcas.py` (marcas reales muy suplantadas + marcas ficticias de los ejemplos) y se puede ampliar con `--marcas`.

## Cómo se calcula el puntaje

1. Cada detector devuelve señales con un **código**.
2. Cada código tiene un **peso** (`phishing/puntaje.py`). Un código **suma una sola vez** aunque aparezca varias veces (cinco enlaces a IPs suman lo mismo que uno; en el reporte las repeticiones aparecen con `+0`).
3. El total se limita a **100**.
4. Nivel: **0–29 bajo · 30–59 medio · 60–100 alto**.

| Código | Peso | | Código | Peso |
|---|---:|---|---|---:|
| `REMITENTE_REPLY_TO` | 15 | | `URL_IP` | 20 |
| `REMITENTE_RETURN_PATH` | 10 | | `URL_ACORTADOR` | 10 |
| `REMITENTE_SUPLANTA_MARCA` | 25 | | `URL_CON_ARROBA` | 20 |
| `AUTH_SPF_FALLA` | 15 | | `DOMINIO_PARECIDO` | 30 |
| `AUTH_DKIM_FALLA` | 15 | | `DOMINIO_PUNYCODE` | 15 |
| `AUTH_DMARC_FALLA` | 25 | | `DOMINIO_MARCA_EMBEBIDA` | 20 |
| `AUTH_DESALINEADO` | 10 | | `URGENCIA` | 5 / 12 / 18 / 25 (1, 2, 3, 4+ expresiones) |
| `AUTH_AUSENTE` | 10 | | `ADJUNTO_EJECUTABLE` | 30 |
| `ENLACE_TEXTO_ENGANOSO` | 25 | | `ADJUNTO_DOBLE_EXTENSION` | 35 |
| `ENLACE_ESQUEMA_PELIGROSO` | 25 | | `ADJUNTO_RIESGOSO` | 15 |

Los pesos premian lo que casi nunca ocurre en correo legítimo (dominio que imita una marca, doble extensión, DMARC fallido) y dan poco a lo que sí aparece a veces en correos normales (una palabra de urgencia, falta de encabezados de autenticación).

## Ejemplos incluidos (`ejemplos/`)

Todos usan dominios reservados o ficticios (`example.com`, `.example`, `.test`) e IPs de documentación (`192.0.2.x`, `198.51.100.x`). Los adjuntos son texto inofensivo.

| Archivo | Tipo | Señales que ejercita |
|---|---|---|
| `legitimo_01_banco.eml` | legítimo | autenticación correcta, enlace al dominio oficial |
| `legitimo_02_tienda.eml` | legítimo | HTML con enlaces coherentes, Reply-To del mismo dominio |
| `legitimo_03_colega.eml` | legítimo | adjunto PDF, una palabra de urgencia («no es urgente») |
| `legitimo_04_envio.eml` | legítimo | Return-Path en subdominio propio, «24 horas» |
| `phishing_01_paypal_typo.eml` | phishing | `paypa1`, nombre visible falso, SPF/DMARC fallan, Reply-To ajeno, urgencia |
| `phishing_02_enlace_enganoso.eml` | phishing | texto de enlace ≠ destino, IP, marca embebida |
| `phishing_03_homografo.eml` | phishing | punycode con «о» cirílica, `rnicrosoft`, sin autenticación |
| `phishing_04_adjunto.eml` | phishing | `Factura.pdf.exe`, adjunto `.html`, SPF softfail |
| `phishing_05_acortador_en.eml` | phishing | inglés, acortador, URL con `@`, DKIM desalineado |
| `phishing_06_fraude_ceo.eml` | phishing | fraude del CEO: Reply-To/Return-Path ajenos, DMARC falla, sin enlaces |

## Seguridad: el correo es contenido no confiable

- **No se abre ningún enlace** ni se descargan recursos remotos (hay un test que bloquea la red).
- **Los adjuntos nunca se guardan ni se ejecutan**: solo se leen su nombre, tipo y tamaño.
- El HTML del correo se procesa con `html.parser` solo para extraer texto y enlaces; no se interpreta ni se renderiza.
- El **reporte HTML escapa todo** el contenido del correo (asunto, remitente, evidencias, nombres de archivo) e incluye una `Content-Security-Policy` que bloquea scripts y recursos externos. Un asunto con `<script>` aparece como texto. Hay tests para esto (`tests/test_seguridad.py`).
- La salida de terminal elimina caracteres de control (secuencias ANSI) que vengan en el correo.

## Tests

```bash
pip install pytest
python -m pytest
```

Cubren cada detector por separado, los 10 ejemplos (los 6 de phishing dan medio/alto y los 4 legítimos bajo), la CLI y el escape del HTML.

## Límites de la herramienta

**Falsos positivos** (marca un correo legítimo):
- Boletines enviados por plataformas de mailing tienen `Return-Path` y DKIM de otro dominio (desalineado) aunque sean legítimos.
- Correos reenviados o de listas de correo suelen romper SPF/DKIM.
- Palabras como «urgente», «transferencia» o «reembolso» aparecen en correos normales.
- Dominios reales que se parecen por casualidad a una marca (distancia de edición 1) o que la contienen (`pineapple` contiene `apple`).
- Empresas que usan acortadores en sus campañas.

**Falsos negativos** (no detecta un phishing):
- Phishing desde cuentas legítimas comprometidas: pasa SPF/DKIM/DMARC y no imita ningún dominio.
- Marcas que no están en `marcas.py` (agrégalas con `--marcas`).
- Enlaces ocultos en imágenes, PDF, QR, archivos adjuntos o redirecciones de sitios legítimos.
- Textos de engaño redactados sin las palabras clave o en otros idiomas.
- Dominios recién registrados con nombres que no imitan marcas.

**Otros límites:**
- Los encabezados `Authentication-Results` pueden falsificarse si el correo no pasó por tu servidor; solo son fiables los que agrega tu propio servidor de correo.
- El dominio organizacional se calcula de forma aproximada (sin la *Public Suffix List* completa).
- Es una ayuda para revisar, no un veredicto: un puntaje bajo no garantiza que el correo sea seguro.

## Estructura

```
phishing/
  __main__.py      # python -m phishing
  cli.py           # argumentos de la CLI
  parser.py        # lectura segura del .eml
  modelo.py        # Correo, Senal, Enlace, Adjunto
  util.py          # dominios, confundibles, Levenshtein
  marcas.py        # marcas conocidas y dominios oficiales
  remitente.py     # señal 1
  autenticacion.py # señal 2
  enlaces.py       # señal 3 + IP, acortadores, '@'
  dominios.py      # señal 4
  urgencia.py      # señal 5
  adjuntos.py      # extra
  puntaje.py       # pesos, total y nivel
  analizador.py    # orquesta todo
  reporte.py       # texto, JSON y HTML
ejemplos/          # 4 legítimos + 6 phishing
tests/             # pytest
```
