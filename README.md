# kdeconnect-mcp

MCP server que expone **llamadas, SMS y notificaciones** de un movil Android a
un agente, via **KDE Connect**, con un sistema de **PII** que impide que los
codigos de autorizacion (OTP), numeros de tarjeta, IBAN y telefonos completos
lleguen al agente o toquen el disco. Los nombres de contacto y de app si son
visibles.

```
movil Android ──KDE Connect──> kdeconnectd ──DBus──> listener ──PII──> SQLite ──MCP──> agente
```

## Que redacta (y que no)

| Categoria | Ejemplo | Resultado |
|---|---|---|
| `otp` | `Tu codigo de autorizacion es 483920` | `[REDACTADO:otp]` |
| `card` | `407-1234567-8901234` | `[REDACTADO:card]` |
| `iban` | `ES91 2100 0418 4502 0005 1332` | `[REDACTADO:iban]` |
| `phone` | `+34 600 123 456` | `+34 ***456` (configurable) |
| Nombres | `Ana`, `Mama`, `BBVA` | sin cambios |

Garantias:

1. **Redaccion en la ingesta**: el listener redacta antes de `INSERT`. El texto
   original solo existe en memoria durante el evento.
2. **Hash con HMAC** (`content_hash`) para deduplicar/auditar sin guardar texto.
3. **Defensa en profundidad**: las respuestas MCP vuelven a pasar por el
   redactor, tambien las lecturas en vivo de DBus.
4. **Logs sin contenido**: el listener registra kind/app/contadores, nunca el
   texto. Los tests E2E escanean el fichero SQLite (incluido `-wal`) buscando
   los secretos simulados y fallan si aparecen.

El detector de OTP combina palabras clave (codigo, autorizacion, verificacion,
otp, code, password...) con ventana de contexto y lista de **apps sensibles**
(authenticator, authy, bitwarden...). Anade tus bancos a `sensitive_apps` en la
config para que cualquier codigo suyo se redacte aunque falte la palabra clave.

## Requisitos

- Linux de escritorio con sesion grafica y bus de sesion DBus.
- `kdeconnect` en el escritorio:
  ```bash
  sudo apt install kdeconnect      # Ubuntu/Debian
  systemctl --user enable --now kdeconnect.service   # o abrilo desde el menu
  ```
- Movil con KDE Connect emparejado y los plugins **Notificaciones**, **SMS** y
  **Telefonia** activos (en la app: Ajustes > Plugins).
- Python >= 3.11 y [uv](https://docs.astral.sh/uv/).

Verifica el emparejamiento con:

```bash
uv run kdeconnect-mcp doctor
```

## Instalacion

```bash
git clone https://github.com/DaBlitzStein/kdeconnect-mcp.git
cd kdeconnect-mcp
uv sync
uv run kdeconnect-mcp demo        # prueba el pipeline con datos simulados
```

### Sin clonar el repo (uvx, recomendado)

`uvx` es el equivalente a `npx` en Python: ejecuta el paquete sin clonar ni instalar.

```bash
# desde GitHub (disponible ya)
uvx --from git+https://github.com/DaBlitzStein/kdeconnect-mcp kdeconnect-mcp serve

# cuando este publicado en PyPI
uvx kdeconnect-mcp serve
```

Configuracion en un agente MCP (opencode, Claude Code, Cursor, LibreFang...):

```json
"kdeconnect": {
  "type": "local",
  "command": ["uvx", "--from", "git+https://github.com/DaBlitzStein/kdeconnect-mcp", "kdeconnect-mcp", "serve"],
  "enabled": true
}
```

Listener permanente (captura aunque no haya agente abierto): instala la herramienta y provisiona:

```bash
uv tool install git+https://github.com/DaBlitzStein/kdeconnect-mcp   # o: uv tool install kdeconnect-mcp
kdeconnect-mcp provision
```

### Registrar en opencode

En `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "kdeconnect": {
      "type": "local",
      "command": [
        "uv", "--directory", "/ruta/a/kdeconnect-mcp",
        "run", "kdeconnect-mcp", "serve"
      ],
      "enabled": true
    }
  }
}
```

### Listener permanente (recomendado)

El servidor MCP captura mientras hay una sesion de agente. Para capturar
siempre (aunque el agente este cerrado), instala el service de usuario:

```bash
uv tool install /ruta/a/kdeconnect-mcp   # deja el binario en ~/.local/bin
mkdir -p ~/.config/systemd/user
cp systemd/kdeconnect-mcp-listen.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now kdeconnect-mcp-listen.service
```

El lock (`listener.lock`) garantiza un unico escritor; si el service ya corre,
el servidor MCP solo lee la misma base de datos.

## Operacion con kcd

[`kcd`](https://github.com/bethropolis/kcd) es un daemon de KDE Connect
(protocolo v8) escrito en Go, headless: binario unico, sin Qt ni sesion grafica.
Escucha en el socket Unix `$XDG_RUNTIME_DIR/kcd/kcd.sock` (o el que fije
`KDCONNECT_SOCKET`).

### Provision

```bash
uv run kdeconnect-mcp provision --dry-run   # plan completo, no descarga ni escribe
uv run kdeconnect-mcp provision             # instala y arranca
```

`provision` trabaja sobre la release fijada **v1.20.0** (`--version vX.Y.Z` para
cambiarla):

1. Descarga `kcd_<version>_linux_x86_64.tar.gz` y `checksums.txt` de GitHub a
   un directorio temporal.
2. Verifica el SHA256 del tarball contra `checksums.txt` y aborta con error si
   no coincide.
3. Extrae el binario y lo instala en `~/.local/bin/kcd` (chmod +x).
4. Escribe `~/.config/systemd/user/kcd.service`
   (`ExecStart=%h/.local/bin/kcd daemon`) y `kdeconnect-mcp-listen.service`
   (`ExecStart=<proyecto>/.venv/bin/python -m kdeconnect_mcp listen`, sin
   depender del PATH de systemd).
5. `systemctl --user daemon-reload`; salvo `--no-start`, hace
   `enable --now` de ambos servicios.

### Emparejamiento

```bash
uv run kdeconnect-mcp pair <deviceId>   # inicia el pairing desde el escritorio
uv run kdeconnect-mcp pair_listen       # escucha y acepta solicitudes del movil
```

El flujo es TLS con huella SHA-256: confirma la huella en el movil cuando
aparezca la solicitud. Desde el agente, `scan_devices` y `request_pair` cubren
lo mismo.

### Plugins en el movil

En la app KDE Connect del movil, Ajustes > Plugins, activa al menos
**Notificaciones**, **SMS** y **Telefonia**. Sin ellos kcd no reenvia eventos,
aunque el emparejamiento exista.

### Refresco

- El listener re-sincroniza dispositivos al conectar y mantiene abierto el
  stream de pairing; si el socket cae, reconecta con backoff (1s-30s).
- `kcd devices` lista los dispositivos vistos por el daemon.
- `uv run kdeconnect-mcp doctor` muestra socket, version de kcd y estado de las
  unidades systemd.
- Refresco forzado: `systemctl --user restart kdeconnect-mcp-listen.service`.

### Limites con kcd

- **Sin backfill de historial SMS**: solo se captura lo que llega mientras el
  listener esta activo.
- **`list_active_notifications` no soportado**: no hay consulta en vivo de
  notificaciones activas; usa `get_activity`.
- **`sync_sms_history` no soportado**: devuelve un error explicito.
- La release v1.20.0 solo publica binario para Linux x86_64.

## Herramientas MCP

| Tool | Para que |
|---|---|
| `get_status` | Estado del listener, captura y PII |
| `list_devices` | Dispositivos conocidos (BD) |
| `get_activity` | Timeline filtrable (`kind`, `app`, `since_minutes`, ...) |
| `search_activity` | Busqueda de texto sobre lo redactado |
| `get_conversation` | Hilo de SMS por telefono/contacto |
| `get_call_log` | Llamadas; `only_missed=true` para perdidas |
| `list_active_notifications` | Notificaciones activas en el movil ahora (DBus en vivo) |
| `acknowledge_events` | Marca leidos por ids o antiguedad |
| `get_redaction_stats` | Redacciones por categoria |
| `sync_sms_history` | Pide al movil las conversaciones cacheadas |
| `scan_devices` / `request_pair` | Emparejamiento |

## CLI

```bash
kdeconnect-mcp serve          # MCP por stdio (por defecto)
kdeconnect-mcp listen         # captura en primer plano
kdeconnect-mcp sync           # sincroniza SMS cacheados
kdeconnect-mcp events         # timeline reciente
kdeconnect-mcp redact-test "Tu codigo es 123456"
kdeconnect-mcp demo           # datos simulados, sin KDE Connect
kdeconnect-mcp doctor         # diagnostico (config, kcd, systemd, KDE Connect)
kdeconnect-mcp provision      # instala kcd y los services systemd de usuario
kdeconnect-mcp config-init    # escribe config de ejemplo
```

Todas aceptan `--data-dir`, `--config` y `--fake`.

## Configuracion

Ver `config/config.example.yaml`. Se carga de
`~/.config/kdeconnect-mcp/config.yaml` (o `KDCONNECT_MCP_CONFIG`).

Claves utiles:

- `redaction.phone.mode`: `off` | `partial` (por defecto, ultimos 3) | `full`.
- `redaction.keywords`: palabras que activan la redaccion de codigos cercanos.
- `redaction.sensitive_apps`: apps donde todo codigo se redacta siempre.
- `capture.ignore_apps`: apps cuyas notificaciones no se capturan.

## Desarrollo

```bash
uv run pytest          # 37 tests: PII, store, ingesta, fake E2E, MCP stdio
```

Estructura:

- `pii.py` — motor de redaccion (categorias, solapes, enmascarado de telefono).
- `listener.py` — ingesta: redacta, deduplica, mergea llamadas, persiste.
- `store.py` — SQLite WAL + FTS5, solo texto redactado.
- `dbus_backend.py` — DBus KDE Connect (interfaces verificadas contra master y v24.02).
- `fake_backend.py` — movil simulado para desarrollo/tests.
- `server.py` — tools MCP; `cli.py` — comandos.

## Limitaciones

- Las llamadas se exponen como eventos `ringing`/`missedCall` (no hay audio ni
  estado "en curso" persistente en KDE Connect).
- Los SMS se reciben por la API de conversaciones; en la primera conexion se
  piden las conversaciones cacheadas al movil (`sync_sms_history`).
- No hay envio de SMS ni respuesta a notificaciones (posible extension).
- El escritorio debe estar encendido y con KDE Connect conectado al movil.

## Diagramas (mermaid con Firefox headless, sin Chrome)

`mermaid-cli` usa Puppeteer, que por defecto baja `chrome-headless-shell`. Aquí se
usa el Firefox de Puppeteer en su lugar:

```bash
# una vez: descarga el Firefox de Puppeteer (~90 MB, sin Chrome)
PUPPETEER_SKIP_DOWNLOAD=1 npx -y puppeteer browsers install firefox

# renderizar cualquier .mmd (svg o png; pdf es Chromium-only)
./tools/render-mermaid.sh docs/arquitectura-kcd.mmd docs/arquitectura-kcd.png
```

La config `tools/puppeteer.firefox.json` fija `{"browser": "firefox", "headless": true}`
(necesario para pisar el `headless: "shell"` por defecto de mermaid-cli, que es Chrome).

Para ver diagramas en la terminal (flowchart y sequence) sin visor gráfico:

```bash
./tools/mmd.sh docs/flujo-ingesta.mmd
```

Nota: `mermaid-ascii` no soporta `subgraph` ni formas no rectangulares; los
flowcharts para terminal se escriben planos (ver `docs/arquitectura-kcd-plano.mmd`).
Para ERD/gantt o el diagrama con subgraphs, usar el PNG y `chafa`.
