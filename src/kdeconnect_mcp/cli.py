"""CLI: serve (MCP stdio), listen (captura), sync, events, redact-test, doctor, provision."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from .backends import (
    BACKEND_UNAVAILABLE,
    backend_label,
    build_backend,
    with_live_backend,
)
from .config import DEFAULT_CONFIG_PATH, load_config
from .fake_backend import FakeBackend
from .listener import Ingestor, Listener, acquire_lock, load_secret
from .pii import Redactor
from .store import Store

EXAMPLE_CONFIG = """\
# Configuracion de kdeconnect-mcp
data_dir: ~/.local/state/kdeconnect-mcp
log_level: INFO
backend: kcd             # kcd | dbus | fake
kcd:
  socket_path: null      # null = $XDG_RUNTIME_DIR/kcd/kcd.sock

capture:
  sms: true
  calls: true
  notifications: true
  ignore_apps: []        # ej. ["facebook", "instagram"]
  min_body_chars: 0
  sms_poll_seconds: 300  # kcd no empuja SMS: pide conversaciones cada N s (0 = off)

redaction:
  enabled: true
  placeholder: "[REDACTADO:{category}]"
  window_chars: 40       # distancia a la palabra clave para considerar un codigo
  otp_min_digits: 4
  otp_max_digits: 15
  redact_cards: true
  redact_iban: true
  phone:
    mode: partial        # off | partial | full
    show_last: 3
    keep_country_code: true
  # Palabras que activan la redaccion de codigos cercanos
  keywords:
    - codigo
    - contraseña
    - autorizacion
    - verificacion
    - clave
    - pin
    - token
    - otp
    - code
    - password
    - verification
    - do not share
  # Apps cuyos codigos se redactan siempre, aunque falte palabra clave
  sensitive_apps:
    - authenticator
    - authy
    - bitwarden
    - 1password
    # - bbva
    # - santander
    # - caixabank
"""

# ------------------------------------------------------------------ kcd install
KCD_DEFAULT_VERSION = "v1.20.0"
KCD_RELEASE_BASE = "https://github.com/bethropolis/kcd/releases/download"
KCD_ARCH = "linux_x86_64"
KCD_INSTALL_PATH = Path("~/.local/bin/kcd")
KCD_UNIT_NAME = "kcd.service"
LISTENER_UNIT_NAME = "kdeconnect-mcp-listen.service"
KCD_UNIT = """\
[Unit]
Description=kcd daemon (KDE Connect protocol v8, headless)

[Service]
ExecStart=%h/.local/bin/kcd daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


class ProvisionError(RuntimeError):
    """Fallo controlado de `provision` (descarga, checksum o extraccion)."""


def _project_dir() -> Path:
    """Raiz del proyecto (src/kdeconnect_mcp/cli.py -> raiz)."""
    return Path(__file__).resolve().parents[2]


def _listener_unit(project_dir: Path) -> str:
    return f"""\
[Unit]
Description=kdeconnect-mcp listener (SMS, llamadas y notificaciones con redaccion PII)

[Service]
WorkingDirectory={project_dir}
ExecStart={project_dir}/.venv/bin/python -m kdeconnect_mcp listen
Environment=KDCONNECT_MCP_CONFIG=%h/.config/kdeconnect-mcp/config.yaml
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


def _systemd_user_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "systemd" / "user"


def _download(url: str, dest: Path) -> None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "kdeconnect-mcp-provision"}
    )
    with urllib.request.urlopen(request, timeout=60) as response, dest.open(
        "wb"
    ) as out:
        shutil.copyfileobj(response, out)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_sha256(checksums_text: str, filename: str) -> str | None:
    """Acepta formato goreleaser (`hash  fichero`) y BSD (`SHA256 (f) = hash`)."""
    for raw_line in checksums_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("sha256"):
            if f"({filename})" in line:
                _, _, digest = line.partition("=")
                digest = digest.strip().lower()
                if digest:
                    return digest
            continue
        parts = line.replace("*", " ").split()
        if len(parts) >= 2 and parts[-1] == filename:
            return parts[0].lower()
    return None


def _extract_kcd(tarball: Path, dest_dir: Path) -> Path:
    """Extrae el binario `kcd` del tarball sin permitir rutas fuera de dest_dir."""
    with tarfile.open(tarball, "r:gz") as tar:
        member = next(
            (
                m
                for m in tar.getmembers()
                if m.isfile() and Path(m.name).name == "kcd"
            ),
            None,
        )
        if member is None:
            raise ProvisionError(f"El tarball {tarball.name} no contiene el binario kcd")
        if member.name.startswith("/") or ".." in Path(member.name).parts:
            raise ProvisionError(f"Ruta insegura en el tarball: {member.name}")
        source = tar.extractfile(member)
        if source is None:
            raise ProvisionError(f"No se pudo extraer {member.name}")
        target = dest_dir / "kcd"
        with source, target.open("wb") as out:
            shutil.copyfileobj(source, out)
    return target


def _install_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp")
    shutil.copyfile(source, tmp)
    tmp.chmod(0o755)
    os.replace(tmp, dest)


def _write_file(path: Path, content: str) -> None:
    """Escritura atomica: reemplaza symlinks y no deja ficheros a medias."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _run_systemctl(extra: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["systemctl", "--user", *extra],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        return False, "systemctl no encontrado en PATH"
    except subprocess.TimeoutExpired:
        return False, "systemctl agoto el tiempo de espera"
    except OSError as exc:
        return False, str(exc)
    output = (proc.stdout or proc.stderr or "").strip()
    if proc.returncode == 0:
        return True, output
    return False, output or f"exit={proc.returncode}"


def _kcd_socket_path() -> Path:
    override = os.environ.get("KDCONNECT_SOCKET")
    if override:
        return Path(override).expanduser()
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "kcd" / "kcd.sock"


def _kcd_check() -> dict:
    """Diagnostico de kcd tolerante a fallos: sin excepciones, siempre un dict."""
    socket_path = _kcd_socket_path()
    kcd: dict = {"socket_path": str(socket_path)}
    try:
        kcd["socket_exists"] = socket_path.exists()
    except OSError as exc:
        kcd["socket_exists"] = False
        kcd["socket_error"] = str(exc)
    binary = shutil.which("kcd")
    if not binary:
        local_binary = KCD_INSTALL_PATH.expanduser()
        if local_binary.is_file():
            binary = str(local_binary)
    kcd["binary"] = binary or "(no encontrado)"
    if binary:
        try:
            proc = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            version = (proc.stdout or proc.stderr).strip()
            kcd["version"] = version or f"exit={proc.returncode}"
        except (OSError, subprocess.SubprocessError) as exc:
            kcd["version"] = f"error: {exc}"
    return kcd


def _unit_is_active(unit: str) -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unknown: {exc}"
    state = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    return state or "unknown"


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, str(level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _build_backend(cfg):
    return build_backend(cfg)


def _build_ingestor(cfg) -> Ingestor:
    store = Store(cfg.db_path)
    return Ingestor(cfg, store, Redactor(cfg.redaction), load_secret(cfg.data_dir))


# --------------------------------------------------------------------- commands
def cmd_serve(cfg) -> int:
    from .server import run_stdio

    run_stdio(cfg)
    return 0


def cmd_listen(cfg) -> int:
    _setup_logging(cfg.log_level)
    ingestor = _build_ingestor(cfg)
    handle = acquire_lock(cfg.lock_path)
    if handle is None:
        print(f"Ya hay un listener activo (lock: {cfg.lock_path})", file=sys.stderr)
        return 1
    backend = _build_backend(cfg)
    listener = Listener(cfg, ingestor.store, backend, ingestor)

    async def main() -> None:
        try:
            await listener.run()
        finally:
            await backend.close()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("listener detenido", file=sys.stderr)
    except BACKEND_UNAVAILABLE as exc:
        print(f"KDE Connect no disponible: {exc}", file=sys.stderr)
        return 2
    finally:
        handle.close()
    return 0


def cmd_sync(cfg, wait: float) -> int:
    ingestor = _build_ingestor(cfg)
    if backend_label(cfg) == "kcd":
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "kcd no soporta backfill de conversaciones; la captura es solo en vivo",
                },
                ensure_ascii=False,
            )
        )
        return 2
    if cfg.fake:
        events = asyncio.run(FakeBackend(cfg).sync_conversations())
    else:
        try:
            events = asyncio.run(
                with_live_backend(cfg, lambda backend: backend.sync_conversations(wait))
            )
        except BACKEND_UNAVAILABLE as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
            return 2
    counts = {"inserted": 0, "duplicate": 0, "merged": 0, "skipped": 0}
    for event in events:
        outcome = ingestor.handle(event)
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    print(
        json.dumps(
            {"ok": True, "fetched": len(events), **counts}, ensure_ascii=False
        )
    )
    return 0


def cmd_events(cfg, args) -> int:
    from .server import Runtime

    runtime = Runtime(cfg)
    store = runtime.store
    since = time.time() - args.since_minutes * 60 if args.since_minutes > 0 else None
    events = store.query_events(kind=args.kind, since=since, limit=args.limit)
    events = [runtime.present(event) for event in events]
    if args.json:
        print(json.dumps(events, ensure_ascii=False, indent=2, default=str))
        return 0
    for event in events:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(event["received_at"]))
        who = event.get("contact") or event.get("address") or event.get("app") or "-"
        text = event.get("body") or event.get("title") or ""
        print(f"[{stamp}] {event['kind']:<12} {who!s:<18} {text[:80]}")
    return 0


def cmd_redact_test(cfg, args) -> int:
    redactor = Redactor(cfg.redaction)
    text = args.text
    if not text:
        text = sys.stdin.read()
    result = redactor.redact(text, app=args.app)
    print(
        json.dumps(
            {
                "input_length": len(text),
                "redacted": result.text,
                "categories": result.categories,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_demo(cfg) -> int:
    """Siembra eventos simulados y muestra el resultado (sin KDE Connect)."""
    from .fake_backend import script_events

    cfg.fake = True
    ingestor = _build_ingestor(cfg)
    for event in script_events():
        ingestor.handle(event)
    print("Demo con backend simulado; datos en", cfg.db_path, file=sys.stderr)
    args = argparse.Namespace(kind=None, since_minutes=1440, limit=20, json=False)
    return cmd_events(cfg, args)


def cmd_provision(cfg, args) -> int:
    version = str(args.version).strip()
    semver = version.removeprefix("v")
    if not semver:
        print("Version de kcd invalida (usa p.ej. v1.20.0)", file=sys.stderr)
        return 2
    tag = f"v{semver}"
    tarball_name = f"kcd_{semver}_{KCD_ARCH}.tar.gz"
    release_url = f"{KCD_RELEASE_BASE}/{tag}"
    tarball_url = f"{release_url}/{tarball_name}"
    checksums_url = f"{release_url}/checksums.txt"
    install_path = KCD_INSTALL_PATH.expanduser()
    project_dir = _project_dir()
    unit_dir = _systemd_user_dir()
    kcd_unit_path = unit_dir / KCD_UNIT_NAME
    listener_unit_path = unit_dir / LISTENER_UNIT_NAME
    listener_unit = _listener_unit(project_dir)

    if args.dry_run:
        print(f"Plan de provision kcd {tag} (dry-run: no se descarga ni escribe nada)")
        print(f"  tarball        : {tarball_url}")
        print(f"  checksums      : {checksums_url}")
        print("  verificacion   : SHA256 del tarball contra checksums.txt (aborta si no coincide)")
        print(f"  binario        : {install_path} (chmod +x)")
        print(f"  unidad kcd     : {kcd_unit_path}")
        print(f"  unidad listener: {listener_unit_path}")
        print(f'                   ExecStart=uv run --directory "{project_dir}" kdeconnect-mcp listen')
        print("  systemctl      : --user daemon-reload")
        print(
            f"  systemctl      : --user enable --now {KCD_UNIT_NAME} {LISTENER_UNIT_NAME}"
        )
        if args.no_start:
            print("  arranque       : omitido (--no-start)")
        print()
        print(f"--- {KCD_UNIT_NAME} ---")
        print(KCD_UNIT, end="")
        print(f"--- {LISTENER_UNIT_NAME} ---")
        print(listener_unit, end="")
        print()
        print("Dry-run: no se ha descargado ni escrito nada.")
        return 0

    print(f"provision kcd {tag}")
    actual: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="kcd-provision-") as tmp:
            tmpdir = Path(tmp)
            tarball = tmpdir / tarball_name
            checksums = tmpdir / "checksums.txt"
            print(f"  [1/4] Descargando {tarball_name}")
            _download(tarball_url, tarball)
            print("  [2/4] Descargando checksums.txt")
            _download(checksums_url, checksums)
            expected = _expected_sha256(
                checksums.read_text(encoding="utf-8", errors="replace"), tarball_name
            )
            if expected is None:
                raise ProvisionError(f"checksums.txt no contiene {tarball_name}")
            actual = _sha256(tarball)
            if actual != expected:
                raise ProvisionError(
                    f"SHA256 no coincide para {tarball_name}:"
                    f" esperado {expected}, obtenido {actual}"
                )
            print(f"  [3/4] SHA256 verificado: {actual}")
            binary = _extract_kcd(tarball, tmpdir)
            _install_file(binary, install_path)
            print(f"  [4/4] Instalado {install_path}")
    except (ProvisionError, tarfile.TarError, OSError) as exc:
        print(f"provision fallido: {exc}", file=sys.stderr)
        return 1

    try:
        _write_file(kcd_unit_path, KCD_UNIT)
        _write_file(listener_unit_path, listener_unit)
    except OSError as exc:
        print(f"provision fallido al escribir unidades: {exc}", file=sys.stderr)
        return 1
    print(f"  Unidad escrita: {kcd_unit_path}")
    print(f"  Unidad escrita: {listener_unit_path}")

    failures: list[str] = []
    ok, detail = _run_systemctl(["daemon-reload"])
    if ok:
        print("  systemctl --user daemon-reload: OK")
    else:
        failures.append(f"daemon-reload: {detail}")
        print(f"  AVISO: systemctl --user daemon-reload fallo: {detail}", file=sys.stderr)

    if args.no_start:
        print("  Servicios no arrancados (--no-start)")
    else:
        for unit in (KCD_UNIT_NAME, LISTENER_UNIT_NAME):
            ok, detail = _run_systemctl(["enable", "--now", unit])
            if ok:
                print(f"  systemctl --user enable --now {unit}: OK")
            else:
                failures.append(f"enable --now {unit}: {detail}")
                print(
                    f"  AVISO: systemctl --user enable --now {unit} fallo: {detail}",
                    file=sys.stderr,
                )

    print()
    print("Resumen:")
    print(f"  kcd                   : {install_path} ({tag}, sha256 {actual})")
    print(f"  kcd.service           : {kcd_unit_path}")
    print(f"  kdeconnect-mcp-listen : {listener_unit_path}")
    print("Comandos utiles:")
    print("  kcd --version")
    print("  kcd devices")
    print(f"  uv run --directory {project_dir} kdeconnect-mcp doctor")

    if failures:
        print()
        print("provision termino con avisos; ejecuta manualmente:", file=sys.stderr)
        print("  systemctl --user daemon-reload", file=sys.stderr)
        print(
            f"  systemctl --user enable --now {KCD_UNIT_NAME} {LISTENER_UNIT_NAME}",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_doctor(cfg) -> int:
    from .server import Runtime

    runtime = Runtime(cfg)
    report: dict = {
        "config_path": str(cfg.config_path) if cfg.config_path else "(defaults)",
        "data_dir": str(cfg.data_dir),
        "db_path": str(cfg.db_path),
        "fake_backend": cfg.fake,
        "db": runtime.store.stats(),
    }
    handle = acquire_lock(cfg.lock_path)
    if handle is None:
        report["listener_lock"] = "held-by-another-process"
    else:
        report["listener_lock"] = "free"
        handle.close()
    report["kcd"] = _kcd_check()
    report["systemd_units"] = {
        unit: _unit_is_active(unit) for unit in (KCD_UNIT_NAME, LISTENER_UNIT_NAME)
    }
    if cfg.fake:
        report["kdeconnect"] = {"available": True, "backend": "fake"}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    try:
        devices = asyncio.run(
            with_live_backend(
                cfg, lambda backend: backend.list_devices(only_reachable=True, only_paired=False)
            )
        )
        report["kdeconnect"] = {
            "available": True,
            "devices": [
                {"id": d.id, "name": d.name, "paired": d.paired, "reachable": d.reachable}
                for d in devices
            ],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except BACKEND_UNAVAILABLE as exc:
        report["kdeconnect"] = {
            "available": False,
            "error": str(exc),
            "hint": (
                "Arranca el backend (kcd: `uv run kdeconnect-mcp provision`; "
                "DBus: `sudo apt install kdeconnect`) y empareja el movil."
            ),
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1


def cmd_config_init(cfg) -> int:
    target = cfg.config_path or DEFAULT_CONFIG_PATH.expanduser()
    target = Path(target)
    if target.exists():
        print(f"Ya existe: {target}", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(target)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kdeconnect-mcp",
        description="MCP server para KDE Connect con redaccion de PII.",
    )
    parser.add_argument("--config", "-c", help="Ruta del YAML de configuracion")
    parser.add_argument("--data-dir", help="Directorio de datos (SQLite + lock)")
    parser.add_argument("--fake", action="store_true", help="Backend simulado sin KDE Connect")
    parser.add_argument("--log-level", help="DEBUG, INFO, WARNING, ERROR")

    # Opciones comunes tambien despues del subcomando (SUPPRESS evita pisar las globales)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", "-c", default=argparse.SUPPRESS)
    common.add_argument("--data-dir", default=argparse.SUPPRESS)
    common.add_argument("--fake", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--log-level", default=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", parents=[common], help="Servidor MCP por stdio (por defecto)")
    sub.add_parser("listen", parents=[common], help="Listener de captura en primer plano (systemd)")
    p_sync = sub.add_parser("sync", parents=[common], help="Sincroniza conversaciones SMS cacheadas")
    p_sync.add_argument("--wait", type=float, default=5.0)
    p_events = sub.add_parser("events", parents=[common], help="Muestra eventos recientes")
    p_events.add_argument("--kind")
    p_events.add_argument("--since-minutes", type=int, default=1440)
    p_events.add_argument("--limit", type=int, default=20)
    p_events.add_argument("--json", action="store_true")
    p_redact = sub.add_parser("redact-test", parents=[common], help="Prueba las reglas de redaccion")
    p_redact.add_argument("text", nargs="?")
    p_redact.add_argument("--app")
    sub.add_parser("demo", parents=[common], help="Siembra eventos simulados y los muestra")
    sub.add_parser("doctor", parents=[common], help="Diagnostico de configuracion y KDE Connect")
    sub.add_parser("config-init", parents=[common], help="Escribe una configuracion de ejemplo")
    p_provision = sub.add_parser(
        "provision", parents=[common], help="Instala kcd y los servicios systemd de usuario"
    )
    p_provision.add_argument(
        "--dry-run", action="store_true", help="Muestra el plan sin descargar ni escribir nada"
    )
    p_provision.add_argument(
        "--no-start", action="store_true", help="No hace enable --now de los servicios"
    )
    p_provision.add_argument(
        "--version", default=KCD_DEFAULT_VERSION, help="Version de kcd (por defecto v1.20.0)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(args.config, args.data_dir, fake=args.fake)
    if args.log_level:
        cfg.log_level = args.log_level
    command = args.command or "serve"
    if command != "serve":
        _setup_logging(cfg.log_level)
    if command == "serve":
        return cmd_serve(cfg)
    if command == "listen":
        return cmd_listen(cfg)
    if command == "sync":
        return cmd_sync(cfg, args.wait)
    if command == "events":
        return cmd_events(cfg, args)
    if command == "redact-test":
        return cmd_redact_test(cfg, args)
    if command == "demo":
        return cmd_demo(cfg)
    if command == "doctor":
        return cmd_doctor(cfg)
    if command == "provision":
        return cmd_provision(cfg, args)
    if command == "config-init":
        return cmd_config_init(cfg)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
