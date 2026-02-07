"""Shared fixtures for the vault_tar test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ── Reusable constants ───────────────────────────────────────────────────────

PASSWORD = "t3st-P@ssw0rd!#"
UNICODE_PASSWORD = "пароль_密码_κωδ_🔑"  # Cyrillic + CJK + Greek + emoji


# ── Directory tree fixtures ──────────────────────────────────────────────────

@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    """Create a non-trivial directory tree for round-trip tests.

    Layout::

        source/
        ├── hello.txt          (text, ~1.4 KiB)
        ├── empty.txt          (0 bytes)
        ├── binary.bin         (random 4 KiB)
        ├── subdir/
        │   └── data.bin       (random 4 KiB)
        └── empty_dir/
    """
    root = tmp_path / "source"
    root.mkdir()
    (root / "hello.txt").write_text("Hello, World!\n" * 100)
    (root / "empty.txt").write_bytes(b"")
    (root / "binary.bin").write_bytes(os.urandom(4096))
    sub = root / "subdir"
    sub.mkdir()
    (sub / "data.bin").write_bytes(os.urandom(4096))
    (root / "empty_dir").mkdir()
    return root


@pytest.fixture()
def unicode_tree(tmp_path: Path) -> Path:
    """Directory tree with unicode names and content."""
    root = tmp_path / "юнікод_源"
    root.mkdir()
    (root / "файл_文件.txt").write_text("Привіт 你好 🌍\n" * 50, encoding="utf-8")
    sub = root / "підкаталог_子目录"
    sub.mkdir()
    (sub / "δεδομένα.bin").write_bytes(os.urandom(1024))
    return root


@pytest.fixture()
def large_file(tmp_path: Path) -> Path:
    """A ~5 MiB file to exercise multi-chunk logic."""
    p = tmp_path / "large.bin"
    p.write_bytes(os.urandom(5 * 1024 * 1024))
    return p
