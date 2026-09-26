"""Tests de helpers de `provision`: checksums, extraccion de tarball y escritura atomica."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from kdeconnect_mcp.cli import (
    STAR_URL,
    ProvisionError,
    _expected_sha256,
    _extract_kcd,
    _star_nudge,
    _write_file,
)

TARBALL = "kcd_1.20.0_linux_x86_64.tar.gz"


def _make_tar(path: Path, members: dict[str, bytes | None]) -> Path:
    """Crea un tar.gz; valor None = symlink peligroso a /etc/passwd."""
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return path


def _run_provision(
    tmp_path: Path, *extra: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "kdeconnect_mcp",
            "provision",
            "--dry-run",
            "--data-dir",
            str(tmp_path / "data"),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# ------------------------------------------------------------------ checksums
def test_expected_sha256_goreleaser_format() -> None:
    text = f"AbCdEf0123  {TARBALL}\n"
    assert _expected_sha256(text, TARBALL) == "abcdef0123"


def test_expected_sha256_goreleaser_binary_marker() -> None:
    text = f"AbCdEf0123 *{TARBALL}\n"
    assert _expected_sha256(text, TARBALL) == "abcdef0123"


def test_expected_sha256_bsd_format() -> None:
    text = f"SHA256 ({TARBALL}) = AbCdEf0123\n"
    assert _expected_sha256(text, TARBALL) == "abcdef0123"


def test_expected_sha256_missing_entry_returns_none() -> None:
    assert _expected_sha256("AbCdEf0123  otro.tar.gz\n", TARBALL) is None
    assert _expected_sha256("", TARBALL) is None


# ------------------------------------------------------------------ extraccion
def test_extract_kcd_valid_tar(tmp_path: Path) -> None:
    data = b"#!/bin/sh\necho kcd\n"
    tarball = _make_tar(tmp_path / "ok.tar.gz", {"kcd_1.20.0_linux_x86_64/kcd": data})
    dest = tmp_path / "out"
    dest.mkdir()

    result = _extract_kcd(tarball, dest)

    assert result == dest / "kcd"
    assert result.read_bytes() == data


def test_extract_kcd_rejects_traversal(tmp_path: Path) -> None:
    tarball = _make_tar(tmp_path / "evil.tar.gz", {"../kcd": b"malo"})
    dest = tmp_path / "out"
    dest.mkdir()

    with pytest.raises(ProvisionError):
        _extract_kcd(tarball, dest)

    assert not (tmp_path / "kcd").exists()
    assert not (dest / "kcd").exists()


def test_extract_kcd_rejects_tar_without_binary(tmp_path: Path) -> None:
    tarball = _make_tar(tmp_path / "evil.tar.gz", {"../evil.txt": b"malo"})

    with pytest.raises(ProvisionError):
        _extract_kcd(tarball, tmp_path / "out")

    assert not (tmp_path / "evil.txt").exists()


def test_extract_kcd_rejects_symlink_member(tmp_path: Path) -> None:
    tarball = _make_tar(tmp_path / "link.tar.gz", {"kcd": None})
    dest = tmp_path / "out"

    with pytest.raises(ProvisionError):
        _extract_kcd(tarball, dest)

    assert not (dest / "kcd").exists()


# ------------------------------------------------------------------ escritura
def test_write_file_does_not_follow_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("original", encoding="utf-8")
    link = tmp_path / "dest.txt"
    link.symlink_to(victim)

    _write_file(link, "nuevo")

    assert victim.read_text(encoding="utf-8") == "original"
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "nuevo"


# ------------------------------------------------------------------ CLI
def test_star_nudge_prints_url(capsys: pytest.CaptureFixture[str]) -> None:
    _star_nudge()
    assert STAR_URL in capsys.readouterr().out


def test_provision_dry_run_plan(tmp_path: Path) -> None:
    proc = _run_provision(tmp_path)

    assert proc.returncode == 0
    stdout = proc.stdout
    assert (
        "https://github.com/bethropolis/kcd/releases/download/v1.20.0/"
        "kcd_1.20.0_linux_x86_64.tar.gz" in stdout
    )
    assert "checksums.txt" in stdout
    assert "kcd.service" in stdout
    assert "kdeconnect-mcp-listen.service" in stdout
    assert "Traceback" not in proc.stderr


def test_provision_rejects_invalid_version_without_urls(tmp_path: Path) -> None:
    for bad in ("1.20", "1.20.0/../x", "v1.2.3.4", "abc", "v"):
        proc = _run_provision(tmp_path, "--version", bad)
        assert proc.returncode != 0, bad
        assert "invalida" in proc.stderr, bad
        assert "github.com" not in proc.stdout, bad
