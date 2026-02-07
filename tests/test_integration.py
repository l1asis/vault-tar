"""Integration tests — encrypt ↔ decrypt round-trips, split logic, edge cases."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from vault_tar.core import (CompressionAlgorithm, compare_directories,
                            decrypt_file, decrypt_to_directories,
                            encrypt_directories, encrypt_file)

PASSWORD = "t3st-P@ssw0rd!#"
UNICODE_PASSWORD = "пароль_密码_κωδ_\U0001f511"  # Cyrillic + CJK + Greek + emoji


# ── Single-file encrypt/decrypt ─────────────────────────────────────────────

class TestFileRoundTrip:
    """encrypt_file → decrypt_file: the core cryptographic pipeline."""

    def _roundtrip(
        self, src: Path, tmp_path: Path, *, password: str = PASSWORD, **enc_kw: Any
    ) -> bytes:
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec.bin")
        encrypt_file(str(src), enc, password, split_size=None, **enc_kw)
        decrypt_file(enc, dec, password)
        return Path(dec).read_bytes()

    def test_content_preserved(self, sample_tree: Path, tmp_path: Path) -> None:
        src = sample_tree / "hello.txt"
        assert self._roundtrip(src, tmp_path) == src.read_bytes()

    def test_empty_file(self, tmp_path: Path) -> None:
        src = tmp_path / "empty"
        src.write_bytes(b"")
        assert self._roundtrip(src, tmp_path) == b""

    def test_binary_data_preserved(self, sample_tree: Path, tmp_path: Path) -> None:
        src = sample_tree / "binary.bin"
        assert self._roundtrip(src, tmp_path) == src.read_bytes()

    @pytest.mark.parametrize("chunk", [64, 256, 4096])
    def test_various_chunk_sizes(
        self, sample_tree: Path, tmp_path: Path, chunk: int
    ) -> None:
        src = sample_tree / "hello.txt"
        assert self._roundtrip(src, tmp_path, chunk_size=chunk) == src.read_bytes()

    def test_multi_chunk_large_file(self, large_file: Path, tmp_path: Path) -> None:
        """5 MiB file with 1 MiB chunks → 5 chunks."""
        assert self._roundtrip(large_file, tmp_path) == large_file.read_bytes()

    def test_unicode_password(self, sample_tree: Path, tmp_path: Path) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec")
        encrypt_file(str(src), enc, UNICODE_PASSWORD, split_size=None)
        decrypt_file(enc, dec, UNICODE_PASSWORD)
        assert Path(dec).read_bytes() == src.read_bytes()

    def test_wrong_password_raises_and_cleans_up(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec")
        encrypt_file(str(src), enc, PASSWORD, split_size=None)
        with pytest.raises(ValueError, match="[Dd]ecryption|[Ww]rong"):
            decrypt_file(enc, dec, "WRONG")
        assert not os.path.exists(dec), "Partial output must be removed"

    def test_corrupted_ciphertext_detected(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "enc")
        encrypt_file(str(src), enc, PASSWORD, split_size=None)
        # Flip a byte deep inside the ciphertext region
        data = bytearray(Path(enc).read_bytes())
        data[-20] ^= 0xFF
        Path(enc).write_bytes(data)
        with pytest.raises(ValueError):
            decrypt_file(enc, str(tmp_path / "dec"), PASSWORD)

    def test_nonexistent_input_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            encrypt_file(str(tmp_path / "nope"), str(tmp_path / "out"), PASSWORD)


# ── Split-file output ────────────────────────────────────────────────────────

class TestSplitOutput:
    """Output splitting across .partN files."""

    def test_produces_multiple_parts(self, sample_tree: Path, tmp_path: Path) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "split")
        encrypt_file(str(src), enc, PASSWORD, split_size=512)
        parts = sorted(tmp_path.glob("split.part*"))
        assert len(parts) >= 2

    def test_split_roundtrip(self, sample_tree: Path, tmp_path: Path) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "split")
        dec = str(tmp_path / "dec")
        encrypt_file(str(src), enc, PASSWORD, split_size=512)
        decrypt_file(enc, dec, PASSWORD)
        assert Path(dec).read_bytes() == src.read_bytes()

    def test_decrypt_from_part0_path(self, sample_tree: Path, tmp_path: Path) -> None:
        """Passing base.part0 as input should auto-discover all parts."""
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "sp")
        encrypt_file(str(src), enc, PASSWORD, split_size=512)
        dec = str(tmp_path / "dec")
        decrypt_file(f"{enc}.part0", dec, PASSWORD)
        assert Path(dec).read_bytes() == src.read_bytes()

    def test_no_split_produces_single_file(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "single")
        encrypt_file(str(src), enc, PASSWORD, split_size=None)
        assert Path(enc).is_file()
        assert not list(tmp_path.glob("single.part*"))


# ── Directory encrypt/decrypt ────────────────────────────────────────────────

class TestDirectoryRoundTrip:
    """encrypt_directories → decrypt_to_directories with tar archiving."""

    @pytest.mark.parametrize("algorithm", ["none", "gz", "bz2", "xz"])
    def test_algorithm_roundtrip(
        self, sample_tree: Path, tmp_path: Path, algorithm: CompressionAlgorithm
    ) -> None:
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec")
        encrypt_directories(
            str(sample_tree),
            output_filename=enc,
            password=PASSWORD,
            algorithm=algorithm,
            split_size=None,
        )
        decrypt_to_directories(enc, output_directory=dec, password=PASSWORD)
        restored = os.path.join(dec, sample_tree.name)
        assert compare_directories(str(sample_tree), restored)

    def test_multiple_input_dirs(self, tmp_path: Path) -> None:
        da, db = tmp_path / "a", tmp_path / "b"
        da.mkdir()
        db.mkdir()
        (da / "x.txt").write_text("aaa")
        (db / "y.txt").write_text("bbb")
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec")
        encrypt_directories(
            str(da),
            str(db),
            output_filename=enc,
            password=PASSWORD,
            algorithm="none",
            split_size=None,
        )
        decrypt_to_directories(enc, output_directory=dec, password=PASSWORD)
        assert (tmp_path / "dec" / "a" / "x.txt").read_text() == "aaa"
        assert (tmp_path / "dec" / "b" / "y.txt").read_text() == "bbb"

    def test_unicode_filenames(self, unicode_tree: Path, tmp_path: Path) -> None:
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec")
        encrypt_directories(
            str(unicode_tree),
            output_filename=enc,
            password=PASSWORD,
            algorithm="none",
            split_size=None,
        )
        decrypt_to_directories(enc, output_directory=dec, password=PASSWORD)
        restored = os.path.join(dec, unicode_tree.name)
        assert compare_directories(str(unicode_tree), restored)

    def test_trailing_separator_in_output(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        """Output path with trailing slash/backslash should not break."""
        enc = str(tmp_path / "enc")
        dec = str(tmp_path / "dec") + os.sep
        encrypt_directories(
            str(sample_tree),
            output_filename=enc,
            password=PASSWORD,
            algorithm="none",
            split_size=None,
        )
        decrypt_to_directories(enc, output_directory=dec, password=PASSWORD)
        # The trailing sep is stripped; verify extraction worked
        restored = os.path.join(dec.rstrip(os.sep), sample_tree.name)
        assert os.path.isdir(restored)

    def test_nonexistent_input_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            encrypt_directories(
                str(tmp_path / "ghost"),
                output_filename=str(tmp_path / "out"),
                password=PASSWORD,
            )


# ── Cleanup flag ─────────────────────────────────────────────────────────────

class TestCleanup:
    def test_encrypt_file_removes_input(self, tmp_path: Path) -> None:
        src = tmp_path / "deleteme.txt"
        src.write_text("gone")
        encrypt_file(
            str(src), str(tmp_path / "enc"), PASSWORD, split_size=None, cleanup=True
        )
        assert not src.exists()

    def test_encrypt_dirs_removes_input(self, tmp_path: Path) -> None:
        d = tmp_path / "deleteme"
        d.mkdir()
        (d / "f.txt").write_text("gone")
        encrypt_directories(
            str(d),
            output_filename=str(tmp_path / "enc"),
            password=PASSWORD,
            algorithm="none",
            split_size=None,
            cleanup=True,
        )
        assert not d.exists()

    def test_decrypt_file_removes_input(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "enc")
        encrypt_file(str(src), enc, PASSWORD, split_size=None)
        dec = str(tmp_path / "dec")
        decrypt_file(enc, dec, PASSWORD, cleanup=True)
        assert not os.path.exists(enc)

    def test_decrypt_split_removes_all_parts(
        self, sample_tree: Path, tmp_path: Path
    ) -> None:
        src = sample_tree / "hello.txt"
        enc = str(tmp_path / "sp")
        encrypt_file(str(src), enc, PASSWORD, split_size=512)
        parts_before = list(tmp_path.glob("sp.part*"))
        assert len(parts_before) >= 2
        decrypt_file(enc, str(tmp_path / "dec"), PASSWORD, cleanup=True)
        assert not list(tmp_path.glob("sp.part*"))


# ── compare_directories ─────────────────────────────────────────────────────

class TestCompareDirectories:
    def test_identical(self, sample_tree: Path, tmp_path: Path) -> None:
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(sample_tree, copy)
        assert compare_directories(str(sample_tree), str(copy)) is True

    def test_content_differs(self, sample_tree: Path, tmp_path: Path) -> None:
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(sample_tree, copy)
        (copy / "hello.txt").write_text("tampered")
        assert compare_directories(str(sample_tree), str(copy)) is False

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda c: os.remove(c / "hello.txt"),
            lambda c: (c / "extra.txt").write_text("x"),
        ],
        ids=["missing-file", "extra-file"],
    )
    def test_structural_differences(
        self, sample_tree: Path, tmp_path: Path, mutation: Callable[[Path], None]
    ) -> None:
        import shutil

        copy = tmp_path / "copy"
        shutil.copytree(sample_tree, copy)
        mutation(copy)
        assert compare_directories(str(sample_tree), str(copy)) is False

    def test_nonexistent_dir_returns_false(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        assert compare_directories(str(real), str(tmp_path / "fake")) is False

    def test_both_nonexistent_returns_false(self, tmp_path: Path) -> None:
        assert compare_directories(str(tmp_path / "a"), str(tmp_path / "b")) is False
