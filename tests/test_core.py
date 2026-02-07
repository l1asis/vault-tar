"""Unit tests for cryptographic primitives, header I/O, and helper logic."""

from __future__ import annotations

import io
from collections.abc import Callable

import pytest

from vault_tar.core import _compression_kwargs  # type: ignore
from vault_tar.core import _format_size  # type: ignore
from vault_tar.core import _make_nonce  # type: ignore
from vault_tar.core import _parse_size  # type: ignore
from vault_tar.core import _read_header  # type: ignore
from vault_tar.core import _write_header  # type: ignore
from vault_tar.core import (FORMAT_VERSION, MAGIC, NONCE_SIZE, SALT_SIZE,
                            CompressionAlgorithm, derive_key)

# ── Nonce construction: the most security-critical custom logic ──────────────

class TestMakeNonce:
    """XOR nonce derivation — correctness and uniqueness guarantees."""

    def test_identity_at_index_zero(self) -> None:
        base = b"\xab" * NONCE_SIZE
        assert _make_nonce(base, 0) == base

    def test_xor_manual_verification(self) -> None:
        base = bytes(range(NONCE_SIZE))
        result = _make_nonce(base, 1)
        expected = bytearray(base)
        expected[-1] ^= 1
        assert result == bytes(expected)

    @pytest.mark.parametrize("count", [256, 1000])
    def test_uniqueness_over_n_indices(self, count: int) -> None:
        base = b"\xff" * NONCE_SIZE
        nonces = {_make_nonce(base, i) for i in range(count)}
        assert len(nonces) == count

    def test_max_96bit_index(self) -> None:
        """2^96 - 1 is the theoretical upper bound."""
        result = _make_nonce(b"\x00" * NONCE_SIZE, 2**96 - 1)
        assert result == b"\xff" * NONCE_SIZE

    def test_index_exceeding_96bits_raises(self) -> None:
        with pytest.raises((OverflowError, ValueError)):
            _make_nonce(b"\x00" * NONCE_SIZE, 2**96)

    def test_negative_index_raises(self) -> None:
        with pytest.raises((OverflowError, ValueError)):
            _make_nonce(b"\x00" * NONCE_SIZE, -1)


# ── Key derivation: only test custom decision points ─────────────────────────

class TestDeriveKey:
    """Verify vault_tar's key derivation contract (not PBKDF2 itself)."""

    def test_output_length_is_256_bits(self) -> None:
        assert len(derive_key("pw", b"\x00" * SALT_SIZE)) == 32

    def test_deterministic_same_inputs(self) -> None:
        salt = b"\xaa" * SALT_SIZE
        assert derive_key("test", salt) == derive_key("test", salt)

    @pytest.mark.parametrize(
        "pw_a, pw_b",
        [("alpha", "bravo"), ("", "x"), ("a" * 1000, "a" * 1001)],
        ids=["distinct", "empty-vs-char", "long-strings"],
    )
    def test_different_passwords_yield_different_keys(
        self, pw_a: str, pw_b: str
    ) -> None:
        salt = b"\xbb" * SALT_SIZE
        assert derive_key(pw_a, salt) != derive_key(pw_b, salt)

    def test_different_salts_yield_different_keys(self) -> None:
        assert derive_key("pw", b"\x00" * 16) != derive_key("pw", b"\xff" * 16)

    def test_unicode_password(self) -> None:
        """Non-ASCII password must not crash and must produce a valid key."""
        key = derive_key("пароль_密码_🔑", b"\x01" * SALT_SIZE)
        assert len(key) == 32

    def test_extremely_long_password(self) -> None:
        key = derive_key("A" * 10_000, b"\x02" * SALT_SIZE, iterations=1000)
        assert len(key) == 32


# ── Header I/O: round-trip + malformed input detection ───────────────────────

class TestHeaderIO:
    """Custom binary format parsing — the part that *can* go wrong."""

    def test_round_trip(self) -> None:
        salt, nonce = b"\xde\xad" * 8, b"\xca\xfe" * 6
        buf = io.BytesIO()
        _write_header(buf, salt, nonce)
        buf.seek(0)
        assert _read_header(buf) == (salt, nonce)

    def test_wire_format_layout(self) -> None:
        """Verify exact byte layout: magic(2) + version(1) + salt_len(2) + salt + nonce_len(2) + nonce."""
        salt, nonce = b"\x11" * SALT_SIZE, b"\x22" * NONCE_SIZE
        buf = io.BytesIO()
        _write_header(buf, salt, nonce)
        raw = buf.getvalue()

        assert raw[:2] == MAGIC
        assert raw[2] == FORMAT_VERSION
        assert int.from_bytes(raw[3:5], "big") == SALT_SIZE
        assert raw[5 : 5 + SALT_SIZE] == salt
        offset = 5 + SALT_SIZE
        assert int.from_bytes(raw[offset : offset + 2], "big") == NONCE_SIZE
        assert raw[offset + 2 : offset + 2 + NONCE_SIZE] == nonce

    @pytest.mark.parametrize(
        "payload, match",
        [
            (b"\x00\x00\x01", "magic"),  # bad magic
            (MAGIC + b"\x63", "version"),  # version 99
        ],
        ids=["bad-magic", "unsupported-version"],
    )
    def test_invalid_header_rejected(self, payload: bytes, match: str) -> None:
        buf = io.BytesIO(payload + b"\x00" * 50)
        with pytest.raises(ValueError, match=match):
            _read_header(buf)

    @pytest.mark.parametrize(
        "build",
        [
            # Claims 100-byte salt, provides 10
            lambda: MAGIC + b"\x01" + (100).to_bytes(2, "big") + b"\x00" * 10,
            # Valid salt, claims 12-byte nonce, provides 5
            lambda: (
                MAGIC
                + b"\x01"
                + SALT_SIZE.to_bytes(2, "big")
                + b"\x00" * SALT_SIZE
                + (12).to_bytes(2, "big")
                + b"\x00" * 5
            ),
        ],
        ids=["truncated-salt", "truncated-nonce"],
    )
    def test_truncated_header_fields(self, build: Callable[[], bytes]) -> None:
        buf = io.BytesIO(build())
        with pytest.raises(ValueError, match="[Tt]runcated"):
            _read_header(buf)

    def test_empty_stream_raises(self) -> None:
        with pytest.raises(ValueError, match="magic"):
            _read_header(io.BytesIO(b""))


# ── _parse_size: custom parsing with edge cases ─────────────────────────────

class TestParseSize:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("0", 0),
            ("1", 1),
            ("1B", 1),
            ("1KiB", 1024),
            ("1MiB", 1024**2),
            ("1GiB", 1024**3),
            ("1TiB", 1024**4),
            ("2.5GiB", int(2.5 * 1024**3)),
            ("512MiB", 512 * 1024**2),
            ("1KB", 1000),
            ("1MB", 1_000_000),
            ("  256MiB  ", 256 * 1024**2),  # whitespace
        ],
        ids=[
            "zero", "plain-int", "bytes", "kib", "mib", "gib", "tib",
            "fractional-gib", "512mib", "kb-decimal", "mb-decimal", "whitespace",
        ],
    )
    def test_valid_sizes(self, text: str, expected: int) -> None:
        assert _parse_size(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["", "abc", "MiB", "12.34.56"],
        ids=["empty", "letters", "suffix-only", "multi-dot"],
    )
    def test_invalid_sizes_raise(self, text: str) -> None:
        with pytest.raises(ValueError):
            _parse_size(text)


# ── _format_size: boundary transitions ───────────────────────────────────────

class TestFormatSize:
    @pytest.mark.parametrize(
        "value, expected_unit",
        [
            (0, "B"),
            (1023, "B"),
            (1024, "KiB"),
            (1024**2 - 1, "KiB"),
            (1024**2, "MiB"),
            (1024**3, "GiB"),
            (1024**4, "TiB"),
            (1024**5, "PiB"),
        ],
        ids=["0B", "1023B", "1KiB", "1023KiB", "1MiB", "1GiB", "1TiB", "1PiB"],
    )
    def test_unit_selection(self, value: int, expected_unit: str) -> None:
        assert expected_unit in _format_size(value)


# ── _compression_kwargs: decision matrix ─────────────────────────────────────

class TestCompressionKwargs:
    @pytest.mark.parametrize(
        "algo, level, expected",
        [
            ("none", 5, {}),
            ("xz", None, {}),
            ("xz", 6, {"preset": 6}),
            ("gz", 9, {"compresslevel": 9}),
            ("bz2", 3, {"compresslevel": 3}),
            ("zst", 10, {"level": 10}),
        ],
        ids=["none-ignores-level", "xz-none-level", "xz", "gz", "bz2", "zst"],
    )
    def test_kwarg_mapping(
        self, algo: CompressionAlgorithm, level: int | None, expected: dict[str, int]
    ) -> None:
        assert _compression_kwargs(algo, level) == expected
