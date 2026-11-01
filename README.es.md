# CPA Plugin PII Filter

[English](README.md) | Español

Plugin nativo de filtro de privacidad para CLIProxyAPI v8. Intercepta las peticiones a los modelos, detecta texto
sensible y lo sustituye por marcadores (`[EMAIL]`, `[ID]`…) antes de que la petición salga hacia el proveedor.

## Sobre este fork

Es un fork de [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter) v0.3.0,
mantenido por helixnebulatech. Cambios en la v0.4.0:

- **Nuevo id `pii-filter`** (antes `privacyfilter`). La librería pasa a ser `pii-filter.so` / `.dylib` / `.dll` y el
  bloque de config `plugins.configs.pii-filter`. Para migrar, borra la librería antigua `privacyfilter` y renombra su
  bloque de config; si no, se cargan los dos plugins y se redacta dos veces.

- **CLIProxyAPI v8.** Compila contra el SDK de plugins `github.com/router-for-me/CLIProxyAPI/v8` v8.0.49 (antes v7
  con schema 1). Se registra con la versión de schema que anuncia el host, hasta un máximo de 10.
- **Ediciones en el sitio.** Con hosts de schema 8+ devuelve `body_edits` que solo sustituyen los textos redactados.
  El orden de claves, los números grandes y los espacios llegan al proveedor sin cambios (la v0.3.0 reescribía todo el
  JSON, cambiando el orden y redondeando enteros mayores de 2^53). Los cuerpos con claves duplicadas se normalizan
  antes, para que no se pueda esconder PII en una clave repetida.
- **PII en español e inglés.** El original solo cubría teléfonos y DNI chinos. Se añaden DNI/NIE, teléfonos de España,
  EE. UU. e internacionales, SSN, IBAN, tarjetas con espacios o guiones, IPv6, fechas de nacimiento, pasaporte, nº de la
  Seguridad Social y contraseñas escritas en español o inglés (`contraseña es X`, `password is X`, `PIN: [SECRET]
- **Correcciones.** Ahora se redactan las contraseñas débiles con etiqueta (`password: [SECRET]. Un email ya no se
  salta solo porque "ssh" aparezca antes en la línea. Las reglas de gitleaks sin `secretGroup` conservan el nombre de
  la clave (`password: [SECRET] en vez de `[SECRET]`).
- **Ruta de reglas.** El original buscaba `rules/gitleaks.toml` y las rutas relativas junto a la librería, pero
  CLIProxyAPI v8 carga los plugins desde una copia temporal, así que nunca los encontraba. Ahora `gitleaks_toml`
  acepta rutas absolutas, `~/…` o relativas al directorio de trabajo, y si está vacío se usan las reglas embebidas.
- **Autocontenido.** El motor de detección está dentro del repo, en `internal/filter` (MIT, de
  [packyme/privacy-filter](https://github.com/packyme/privacy-filter) vía
  [rheodev/privacy-filter](https://github.com/rheodev/privacy-filter)).

## Datos detectados

| Tipo        | Marcador      | Qué detecta                                                                                         |
|-------------|---------------|-----------------------------------------------------------------------------------------------------|
| `email`     | `[EMAIL]`     | Direcciones de correo (no los destinos `ssh usuario@host` ni remotos `git@host:ruta`)               |
| `phone`     | `[PHONE]`     | España (`+34 612 345 678`, `91 234 56 78`), EE. UU./Canadá (`(415) 555-2671`), cualquier `+CC …`, China |
| `id`        | `[ID]`        | DNI/NIE (con letra de control), SSN de EE. UU. (`123-45-6789`), pasaporte y nº de la Seguridad Social junto a su palabra clave, DNI chino |
| `iban`      | `[IBAN]`      | IBAN con o sin espacios (longitud por país y mod-97)                                                |
| `bank_card` | `[BANK_CARD]` | Tarjetas, juntas o con espacios/guiones (Luhn)                                                      |
| `ip`        | `[IP]`        | IPv4 e IPv6                                                                                         |
| `dob`       | `[DOB]`       | Fechas tras "fecha de nacimiento", "nacido el", "date of birth", "DOB", "born on"                   |
| `secret`    | `[SECRET]`    | Reglas de gitleaks, tokens de alta entropía y valores tras `contraseña`/`clave`/`password`/`PIN`/`token`… (`: X`, `= X`, `es X`, `is X`) |

No detecta: nombres, direcciones postales, datos de salud o financieros en texto libre, emails ofuscados
(`a [arroba] b`) ni texto dentro de imágenes o ficheros. Es un filtro de expresiones regulares, no un modelo NER.

Campos de la petición que **no** se filtran a propósito: argumentos de llamadas a herramientas
(`tool_use.input`, `function_call.arguments`, `functionCall`/`functionResponse` de Gemini), bloques `thinking`,
imágenes y ficheros.

## Compilar

```bash
make build                 # pii-filter.so / .dylib / .dll
BUILD_DIR=dist make build
go test ./...
```

Requiere Go 1.26.10+, CGO y `make`.

## Instalar en CLIProxyAPI

Copia la librería en el directorio de plugins (las reglas de gitleaks van embebidas):

```text
~/.cli-proxy-api/plugins/pii-filter.so
```

Y actívalo en `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "~/.cli-proxy-api/plugins"   # una ruta relativa se resuelve desde el directorio de trabajo del proceso
  configs:
    pii-filter:
      enabled: true
      priority: 100
      # skip_models: [gpt-4]
      # skip_formats: [openai]
      # replacement: "[REDACTADO]"
      # replacement_labels:
      #   email: "[CORREO]"
      #   phone: "[TELÉFONO]"
```

| Campo                | Tipo   | Por defecto | Descripción                                                                  |
|----------------------|--------|-------------|------------------------------------------------------------------------------|
| `gitleaks_toml`      | string | `""`        | Fichero de reglas propio: absoluto, `~/…` o relativo al directorio de trabajo de CLIProxyAPI. Vacío usa las reglas embebidas. |
| `skip_models`        | array  | `[]`        | Modelos que no se filtran.                                                   |
| `skip_formats`       | array  | `[]`        | Formatos de origen que no se filtran (`openai`, `openai-response`, `claude`, `gemini`, `gemini-cli`…). |
| `replacement`        | string | sin definir | Un único marcador para todos los tipos.                                      |
| `replacement_labels` | mapa   | `{}`        | Marcador por tipo; tiene prioridad sobre `replacement`.                      |

Comprueba que está activo con `GET /v0/management/plugins` (`effective_enabled: true`) o en el log:
`pluginhost: plugin registered plugin_id=pii-filter … version=0.4.0`.

Si una recarga en caliente trae una configuración inválida, el plugin la rechaza y **sigue filtrando con la última
válida**. Los logs solo incluyen las rutas JSON redactadas (`messages[0].content`), nunca el texto.

## Cómo funciona

1. Registra un `request_interceptor` con el schema que anuncia el host en `plugin.register` (máximo 10).
2. En los ganchos before-auth y after-auth recorre los campos de texto del prompt de cada formato
   (OpenAI Chat/Responses/imagen, Claude, Gemini, Gemini CLI).
3. En hosts con schema 8+ responde con `body_edits`: solo sustituye los literales de texto redactados, así que el
   orden de claves, los números y los espacios llegan al proveedor tal y como los envió el cliente. Los cuerpos con
   claves duplicadas se normalizan antes (gana la última) y se devuelven enteros, para que un duplicado no pueda
   colar texto sin filtrar. Los hosts más antiguos reciben el cuerpo completo reescrito.
4. Si el cuerpo no es JSON, pasa sin cambios.
