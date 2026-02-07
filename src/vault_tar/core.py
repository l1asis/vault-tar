#!/usr/bin/env python3
"""AES-256-GCM file and directory encryption with optional splitting.

:author: Volodymyr Horshenin
:generated-with: Github Copilot & Claude Opus 4.6
:license: MIT

Encrypts files or directories with AES-256-GCM authenticated encryption,
using PBKDF2-HMAC-SHA256 for key derivation.  Supports chunked streaming
for arbitrarily large files, configurable compression (xz, gzip, bzip2,
zstandard, or none), and optional output splitting into fixed-size parts.

File Format (v1)
----------------
Header (first output part only)::

    [2 B]  magic 0xEF01
    [1 B]  format version 0x01
    [2 B]  salt length          [N B]  salt
    [2 B]  base-nonce length    [12 B] base nonce

Chunks (sequential across parts)::

    [4 B]  ciphertext length    [N B]  ciphertext (plaintext + 16 B GCM tag)

* Nonce per chunk — ``base_nonce XOR chunk_index`` (12 bytes, big-endian).
* AAD per chunk — ``b"chunk_<index>"``.

Examples
--------
Encrypt directories::

    $ vtar encrypt -i docs/ photos/ -o vault -v
    $ vtar encrypt -i docs/ -o vault --algorithm zst -v

Encrypt a single file (skip archiving)::

    $ vtar encrypt -i backup.sql -o backup.enc --file-only --no-split

Decrypt::

    $ vtar decrypt -i vault -o restored/ -v
    $ vtar decrypt -i backup.enc -o backup.sql --file-only
"""

from __future__ import annotations

import argparse
import filecmp
import glob
import os
import re
import shutil
import sys
import tarfile
from getpass import getpass
from secrets import token_bytes
from typing import BinaryIO, Callable, Iterator, Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Constants ────────────────────────────────────────────────────────────────

MAGIC = b"\xef\x01"
FORMAT_VERSION = 1

NONCE_SIZE = 12    # AES-GCM standard nonce size in bytes
SALT_SIZE = 16     # PBKDF2 salt size in bytes
GCM_TAG_SIZE = 16  # AES-GCM authentication tag size in bytes

DEFAULT_CHUNK_SIZE = 2**20  # 1 MiB
DEFAULT_SPLIT_SIZE = 2**30  # 1 GiB
DEFAULT_KDF_ITERATIONS = 1_200_000

# ── Compression algorithm configuration ──────────────────────────────────────

CompressionAlgorithm = Literal["xz", "gz", "bz2", "zst", "none"]
DEFAULT_ALGORITHM: CompressionAlgorithm = "xz"

_ALGO_EXT: dict[str, str] = {
    "xz": ".tar.xz",
    "gz": ".tar.gz",
    "bz2": ".tar.bz2",
    "zst": ".tar.zst",
    "none": ".tar",
}

_ALGO_WRITE_MODE: dict[str, str] = {
    "xz": "w:xz",
    "gz": "w:gz",
    "bz2": "w:bz2",
    "zst": "w:zst",
    "none": "w:",
}

# tarfile uses different keyword names for compression level per algorithm.
_ALGO_LEVEL_KWARG: dict[str, str | None] = {
    "xz": "preset",             # xz/lzma: 0–9
    "gz": "compresslevel",      # gzip: 0–9
    "bz2": "compresslevel",     # bzip2: 1–9
    "zst": "level",             # zstandard: 1–22 (Python ≥ 3.14)
    "none": None,
}


def _compression_kwargs(
    algorithm: CompressionAlgorithm,
    level: int | None,
) -> dict[str, int]:
    """Return keyword arguments for ``tarfile.open`` compression level."""
    if level is None or algorithm == "none":
        return {}
    kwarg = _ALGO_LEVEL_KWARG[algorithm]
    if kwarg is None:
        return {}
    return {kwarg: level}


# ── Key derivation ───────────────────────────────────────────────────────────

def derive_key(
    password: str,
    salt: bytes,
    iterations: int = DEFAULT_KDF_ITERATIONS,
) -> bytes:
    """Derive a 256-bit key from *password* using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ── Nonce construction ───────────────────────────────────────────────────────

def _make_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Return ``base_nonce XOR chunk_index`` as a 12-byte nonce.

    XOR with a monotonic counter guarantees uniqueness for up to 2^96
    chunks without risk of overflow beyond the fixed nonce size.
    """
    index_bytes = chunk_index.to_bytes(NONCE_SIZE, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, index_bytes))


# ── Header I/O ───────────────────────────────────────────────────────────────

def _write_header(f: BinaryIO, salt: bytes, base_nonce: bytes) -> None:
    """Serialize the encryption header into *f*."""
    f.write(MAGIC)
    f.write(FORMAT_VERSION.to_bytes(1, "big"))
    f.write(len(salt).to_bytes(2, "big") + salt)
    f.write(len(base_nonce).to_bytes(2, "big") + base_nonce)


def _read_header(f: BinaryIO) -> tuple[bytes, bytes]:
    """Read and validate the encryption header.

    Returns
    -------
    tuple[bytes, bytes]
        ``(salt, base_nonce)``.

    Raises
    ------
    ValueError
        If the header is missing, truncated, or has an unsupported version.
    """
    magic = f.read(2)
    if magic != MAGIC:
        raise ValueError(
            "Invalid file: missing magic number — "
            "not an encrypted file or unsupported format."
        )

    version = int.from_bytes(f.read(1), "big")
    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported format version {version} (expected {FORMAT_VERSION})."
        )

    salt_len = int.from_bytes(f.read(2), "big")
    salt = f.read(salt_len)
    if len(salt) != salt_len:
        raise ValueError("Truncated header: incomplete salt.")

    nonce_len = int.from_bytes(f.read(2), "big")
    base_nonce = f.read(nonce_len)
    if len(base_nonce) != nonce_len:
        raise ValueError("Truncated header: incomplete nonce.")

    return salt, base_nonce


# ── Split-file helpers ───────────────────────────────────────────────────────

def _get_part_paths(base_path: str) -> list[str]:
    """Return sorted ``[base.part0, base.part1, …]`` for a given *base_path*."""
    candidates = glob.glob(f"{glob.escape(base_path)}.part*")
    valid: list[tuple[int, str]] = []
    for p in candidates:
        suffix = p[len(base_path) + 5 :]  # strip ".part"
        if suffix.isdigit():
            valid.append((int(suffix), p))
    if not valid:
        raise FileNotFoundError(f"No part files found matching '{base_path}.part*'")
    valid.sort(key=lambda t: t[0])
    return [p for _, p in valid]


class _SplitFileWriter:
    """Context manager that writes data across numbered part files,
    rotating at *split_size* bytes per part."""

    def __init__(self, base_path: str, split_size: int | None) -> None:
        self._base = base_path
        self._split = split_size
        self._index = 0
        self._size = 0
        self._f: BinaryIO | None = None
        self._open_next()

    def _path(self) -> str:
        if self._split is not None:
            return f"{self._base}.part{self._index}"
        return self._base

    def _open_next(self) -> None:
        self._f = open(self._path(), "wb")
        self._size = 0

    def write_header(self, salt: bytes, base_nonce: bytes) -> None:
        assert self._f is not None
        _write_header(self._f, salt, base_nonce)
        self._size = self._f.tell()

    def write_chunk(self, ciphertext: bytes) -> None:
        """Write a length-prefixed ciphertext chunk, rotating as needed."""
        assert self._f is not None
        frame = len(ciphertext).to_bytes(4, "big") + ciphertext
        if self._split and (self._size + len(frame)) > self._split:
            self._f.close()
            self._index += 1
            self._open_next()
        self._f.write(frame)
        self._size += len(frame)

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None

    def __enter__(self) -> _SplitFileWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _SplitFileReader:
    """Context manager that reads length-prefixed chunks sequentially
    across one or more part files."""

    def __init__(self, path: str) -> None:
        if os.path.isfile(path):
            match = re.match(r"^(.+)\.part\d+$", path)
            if match:
                try:
                    self._paths = _get_part_paths(match.group(1))
                except FileNotFoundError:
                    self._paths = [path]
            else:
                self._paths = [path]
        else:
            self._paths = _get_part_paths(path)
        self._idx = 0
        self._f: BinaryIO | None = None
        self._bytes_read = 0
        self._open_current()

    @property
    def total_size(self) -> int:
        """Combined size of all part files in bytes."""
        return sum(os.path.getsize(p) for p in self._paths)

    def _open_current(self) -> None:
        self._f = open(self._paths[self._idx], "rb")

    def read_header(self) -> tuple[bytes, bytes]:
        assert self._f is not None
        return _read_header(self._f)

    def read_chunks(self) -> Iterator[bytes]:
        """Yield ciphertext chunks across all part files in order."""
        while True:
            assert self._f is not None
            length_bytes = self._f.read(4)

            if len(length_bytes) == 0:
                self._f.close()
                self._idx += 1
                if self._idx >= len(self._paths):
                    return
                self._open_current()
                length_bytes = self._f.read(4)
                if len(length_bytes) == 0:
                    return

            if len(length_bytes) < 4:
                raise ValueError("Truncated chunk: incomplete length prefix.")

            chunk_len = int.from_bytes(length_bytes, "big")
            data = self._f.read(chunk_len)
            if len(data) != chunk_len:
                raise ValueError(
                    f"Truncated chunk: expected {chunk_len} bytes, got {len(data)}."
                )
            self._bytes_read += 4 + chunk_len
            yield data

    @property
    def bytes_read(self) -> int:
        """Total bytes consumed from part files (lengths + ciphertext)."""
        return self._bytes_read

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None

    def __enter__(self) -> _SplitFileReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ── Progress reporting ───────────────────────────────────────────────────────

def _format_size(size_bytes: int | float) -> str:
    """Format *size_bytes* with an appropriate binary unit (B … TiB)."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{int(size_bytes)} B"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PiB"


def _progress_bar(
    current: int,
    total: int,
    label: str,
    *,
    unit: str | None = None,
) -> None:
    """Print ``label: |████░░░░| pct% (cur/tot)`` to stderr.

    *unit* can be ``"bytes"`` (auto-scaled), ``"items"``, or ``None``
    (auto-detect: uses bytes if *total* > 1024, otherwise items).
    """
    if total <= 0:
        return
    if unit is None:
        unit = "bytes" if total > 1024 else "items"

    pct = min(current / total, 1.0) * 100
    width = 40
    filled = int(width * current // total)
    bar = "█" * filled + "░" * (width - filled)

    if unit == "bytes":
        suffix = f"{_format_size(current)}/{_format_size(total)}"
    else:
        suffix = f"{current}/{total} {unit}"

    print(
        f"\r{label}: |{bar}| {pct:5.1f}% ({suffix})",
        end="",
        flush=True,
        file=sys.stderr,
    )


def _log(msg: str) -> None:
    """Print a status line to stderr."""
    print(msg, file=sys.stderr)


# ── Compression / decompression ──────────────────────────────────────────────

class _ProgressFileObj:
    """Wraps a readable file object and calls *callback* on every ``read``
    with the number of bytes actually consumed.

    This enables real-time byte-level progress during ``tar.addfile``,
    which reads the source file in internal buffer-sized chunks.
    """

    def __init__(
        self,
        path: str,
        callback: Callable[[int], None],
    ) -> None:
        self._f: BinaryIO = open(path, "rb")
        self._cb = callback

    def read(self, size: int = -1) -> bytes:
        data = self._f.read(size)
        if data:
            self._cb(len(data))
        return data

    def close(self) -> None:
        self._f.close()

    # tarfile may also check for these
    def tell(self) -> int:
        return self._f.tell()

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._f.seek(pos, whence)


def _collect_entries(
    *input_paths: str,
) -> tuple[list[tuple[str, str, int]], int]:
    """Walk *input_paths* and return ``(entries, total_bytes)``.

    Each entry is ``(arcname, full_path, size)`` where *size* is the file
    size (0 for directories).  *total_bytes* is the sum of all file sizes.
    """
    entries: list[tuple[str, str, int]] = []
    total_bytes = 0
    for path in input_paths:
        base = os.path.basename(path)
        if os.path.isfile(path):
            sz = os.path.getsize(path)
            entries.append((base, path, sz))
            total_bytes += sz
        elif os.path.isdir(path):
            entries.append((base, path, 0))
            for root, dirs, files in os.walk(path):
                rel = os.path.relpath(root, os.path.dirname(path))
                for d in sorted(dirs):
                    entries.append((os.path.join(rel, d), os.path.join(root, d), 0))
                for fname in sorted(files):
                    fp = os.path.join(root, fname)
                    sz = os.path.getsize(fp)
                    entries.append((os.path.join(rel, fname), fp, sz))
                    total_bytes += sz
    return entries, total_bytes


def compress_directories(
    *input_paths: str,
    output_filename: str,
    algorithm: CompressionAlgorithm = DEFAULT_ALGORITHM,
    compression_level: int | None = None,
    verbose: bool = False,
) -> str:
    """Compress *input_paths* into a tar archive.

    When *verbose* is ``True``, a single progress bar tracks cumulative
    bytes read across **all** files, updating in real time as each file's
    contents are fed into the compressor (not just when a file finishes).

    Parameters
    ----------
    input_paths : str
        Files or directories to archive.
    output_filename : str
        Destination archive path.
    algorithm : CompressionAlgorithm
        ``"xz"``, ``"gz"``, ``"bz2"``, ``"zst"`` (Python ≥ 3.14), or
        ``"none"`` for an uncompressed tar.
    compression_level : int | None
        Algorithm-specific level.  ``None`` uses the algorithm's default.
    verbose : bool
        Print byte-level compression progress to stderr.

    Returns
    -------
    str
        *output_filename* on success.

    Raises
    ------
    FileNotFoundError
        If any input path does not exist.
    RuntimeError
        If the chosen algorithm is unavailable in the current Python build.
    """
    for p in input_paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Input path does not exist: {p}")

    entries, total_bytes = _collect_entries(*input_paths)
    processed_bytes = 0

    def _on_bytes(n: int) -> None:
        nonlocal processed_bytes
        processed_bytes += n
        if verbose:
            _progress_bar(processed_bytes, total_bytes, "Compressing")

    kwargs = _compression_kwargs(algorithm, compression_level)
    mode = _ALGO_WRITE_MODE[algorithm]

    try:
        tar_fh = tarfile.open(output_filename, mode, **kwargs)  # type: ignore[call-overload]
        assert isinstance(tar_fh, tarfile.TarFile)
        with tar_fh:
            for arcname, fullpath, _size in entries:
                info = tar_fh.gettarinfo(fullpath, arcname=arcname)
                if info.isfile():
                    wrapper = _ProgressFileObj(fullpath, _on_bytes)
                    try:
                        tar_fh.addfile(info, fileobj=wrapper)
                    finally:
                        wrapper.close()
                else:
                    tar_fh.addfile(info)
    except tarfile.CompressionError as exc:
        raise RuntimeError(
            f"Compression algorithm '{algorithm}' is not available: {exc}"
        ) from exc

    if verbose:
        print(file=sys.stderr)  # newline after progress bar

    return output_filename


def decompress_archive(
    archive_path: str,
    output_directory: str,
    verbose: bool = False,
) -> str:
    """Extract a tar archive (any supported compression) to *output_directory*.

    Compression format is auto-detected from file content.  Uses
    ``filter='data'`` on Python ≥ 3.12 to prevent path-traversal attacks.
    """
    os.makedirs(output_directory, exist_ok=True)

    with tarfile.open(archive_path, "r:*") as tar:
        members = tar.getmembers()
        if verbose:
            _log(f"Extracting {len(members)} entries → {output_directory}")

        try:
            tar.extractall(output_directory, filter="data")
        except TypeError:
            # Python < 3.12 fallback: manual path-traversal guard
            abs_out = os.path.abspath(output_directory)
            for m in members:
                dest = os.path.join(output_directory, m.name)
                if not os.path.abspath(dest).startswith(abs_out):
                    raise ValueError(
                        f"Path traversal detected in archive member: {m.name}"
                    )
            tar.extractall(output_directory)

    return output_directory


# ── Encryption ───────────────────────────────────────────────────────────────

def encrypt_file(
    input_filename: str,
    output_filename: str,
    password: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    split_size: int | None = DEFAULT_SPLIT_SIZE,
    cleanup: bool = False,
    verbose: bool = False,
) -> None:
    """Encrypt *input_filename* → *output_filename* using AES-256-GCM.

    Parameters
    ----------
    input_filename : str
        Path to the plaintext file.
    output_filename : str
        Base path for encrypted output (``.partN`` suffixes when splitting).
    password : str
        Encryption password (fed into PBKDF2).
    chunk_size : int
        Plaintext bytes per chunk (default 1 MiB).
    split_size : int | None
        Max bytes per output part file (default 1 GiB).  ``None`` disables.
    cleanup : bool
        Remove *input_filename* after successful encryption.
    verbose : bool
        Print encryption progress to stderr.
    """
    if not os.path.isfile(input_filename):
        raise FileNotFoundError(f"Input file not found: {input_filename}")

    salt = token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    base_nonce = token_bytes(NONCE_SIZE)

    total = os.path.getsize(input_filename)
    processed = 0

    with _SplitFileWriter(output_filename, split_size) as writer:
        writer.write_header(salt, base_nonce)

        with open(input_filename, "rb") as f:
            idx = 0
            while data := f.read(chunk_size):
                nonce = _make_nonce(base_nonce, idx)
                aad = f"chunk_{idx}".encode()
                ciphertext = aesgcm.encrypt(nonce, data, aad)
                writer.write_chunk(ciphertext)

                idx += 1
                processed += len(data)
                if verbose:
                    _progress_bar(processed, total, "Encrypting")

    if verbose:
        print(file=sys.stderr)

    if cleanup:
        os.remove(input_filename)


def encrypt_directories(
    *input_paths: str,
    output_filename: str,
    password: str,
    algorithm: CompressionAlgorithm = DEFAULT_ALGORITHM,
    compression_level: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    split_size: int | None = DEFAULT_SPLIT_SIZE,
    cleanup: bool = False,
    verbose: bool = False,
) -> None:
    """Compress then encrypt files/directories → AES-256-GCM output.

    The intermediate archive is always removed after encryption.
    """
    ext = _ALGO_EXT[algorithm]
    archive_path = f"{output_filename}{ext}"

    if verbose:
        _log(f"Compressing {len(input_paths)} path(s) → {archive_path}")

    compress_directories(
        *input_paths,
        output_filename=archive_path,
        algorithm=algorithm,
        compression_level=compression_level,
        verbose=verbose,
    )

    if verbose:
        _log(f"Encrypting  {archive_path} → {output_filename}")

    encrypt_file(
        archive_path,
        output_filename=output_filename,
        password=password,
        chunk_size=chunk_size,
        split_size=split_size,
        cleanup=True,  # always remove intermediate archive
        verbose=verbose,
    )

    if cleanup:
        for p in input_paths:
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.isfile(p):
                os.remove(p)


# ── Decryption ───────────────────────────────────────────────────────────────

def decrypt_file(
    input_filename: str,
    output_filename: str,
    password: str,
    *,
    cleanup: bool = False,
    verbose: bool = False,
) -> None:
    """Decrypt an AES-256-GCM encrypted file (single or multi-part).

    Automatically detects single-file vs. split ``.partN`` inputs.

    Parameters
    ----------
    input_filename : str
        Encrypted file path, or base name for split ``.partN`` files.
    output_filename : str
        Destination for decrypted plaintext.
    password : str
        Decryption password.
    cleanup : bool
        Remove encrypted input(s) after successful decryption.
    verbose : bool
        Print decryption progress to stderr.

    Raises
    ------
    ValueError
        Wrong password, corrupted data, or format error.
    """
    with _SplitFileReader(input_filename) as reader:
        salt, base_nonce = reader.read_header()
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        total = reader.total_size

        try:
            with open(output_filename, "wb") as out:
                for idx, ciphertext in enumerate(reader.read_chunks()):
                    nonce = _make_nonce(base_nonce, idx)
                    aad = f"chunk_{idx}".encode()
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                    except Exception as exc:
                        raise ValueError(
                            f"Decryption failed at chunk {idx}. "
                            "Wrong password or corrupted data."
                        ) from exc
                    out.write(plaintext)
                    if verbose:
                        _progress_bar(reader.bytes_read, total, "Decrypting")
        except Exception:
            # Remove partial output on failure
            if os.path.isfile(output_filename):
                os.remove(output_filename)
            raise

    if verbose:
        print(file=sys.stderr)

    if cleanup:
        if os.path.isfile(input_filename):
            os.remove(input_filename)
        else:
            for part in _get_part_paths(input_filename):
                os.remove(part)


def decrypt_to_directories(
    input_filename: str,
    output_directory: str,
    password: str,
    *,
    cleanup: bool = False,
    verbose: bool = False,
) -> None:
    """Decrypt and extract an encrypted archive.

    The compression format of the inner archive is auto-detected,
    so the same function works regardless of which algorithm was
    used during encryption.

    Parameters
    ----------
    input_filename : str
        Encrypted file (or base name for split parts).
    output_directory : str
        Directory to extract into (created if needed).
    password : str
        Decryption password.
    cleanup : bool
        Remove encrypted input(s) after successful decryption.
    verbose : bool
        Print progress to stderr.
    """
    output_directory = output_directory.rstrip(os.sep).rstrip(os.altsep or "")
    archive_path = f"{output_directory}._archive.tmp"

    if verbose:
        _log(f"Decrypting  → {archive_path}")

    decrypt_file(
        input_filename,
        output_filename=archive_path,
        password=password,
        cleanup=cleanup,
        verbose=verbose,
    )

    if verbose:
        _log(f"Extracting  → {output_directory}")

    try:
        decompress_archive(archive_path, output_directory, verbose=verbose)
    finally:
        if os.path.isfile(archive_path):
            os.remove(archive_path)


# ── Directory comparison ─────────────────────────────────────────────────────

def compare_directories(
    dir_a: str,
    dir_b: str,
    *,
    verbose: bool = False,
) -> bool:
    """Recursively compare two directory trees.

    Reports missing, extra, and content-differing files.  Returns
    ``True`` if the trees are identical, ``False`` otherwise.

    Parameters
    ----------
    dir_a, dir_b : str
        Directories to compare.
    verbose : bool
        Print matching files too, not just differences.
    """
    if not os.path.isdir(dir_a):
        _log(f"Error: not a directory: {dir_a}")
        return False
    if not os.path.isdir(dir_b):
        _log(f"Error: not a directory: {dir_b}")
        return False

    identical = True
    stats = {"matched": 0, "differ": 0, "left_only": 0, "right_only": 0}

    def _walk(dcmp: filecmp.dircmp[str], rel: str) -> None:
        nonlocal identical

        for name in sorted(dcmp.left_only):
            path = os.path.join(rel, name) if rel else name
            kind = "dir" if os.path.isdir(os.path.join(dcmp.left, name)) else "file"
            _log(f"  ONLY in {dir_a}: {path}  ({kind})")
            stats["left_only"] += 1
            identical = False

        for name in sorted(dcmp.right_only):
            path = os.path.join(rel, name) if rel else name
            kind = "dir" if os.path.isdir(os.path.join(dcmp.right, name)) else "file"
            _log(f"  ONLY in {dir_b}: {path}  ({kind})")
            stats["right_only"] += 1
            identical = False

        for name in sorted(dcmp.diff_files):
            path = os.path.join(rel, name) if rel else name
            size_a = os.path.getsize(os.path.join(dcmp.left, name))
            size_b = os.path.getsize(os.path.join(dcmp.right, name))
            if size_a == size_b:
                _log(
                    f"  DIFFER: {path}  "
                    f"(same size: {size_a:,} B / {_format_size(size_a)}, content differs)"
                )
            else:
                _log(
                    f"  DIFFER: {path}  "
                    f"({size_a:,} B / {_format_size(size_a)} vs "
                    f"{size_b:,} B / {_format_size(size_b)})"
                )
            stats["differ"] += 1
            identical = False

        for name in sorted(dcmp.same_files):
            stats["matched"] += 1
            if verbose:
                path = os.path.join(rel, name) if rel else name
                _log(f"  OK: {path}")

        for sub, sub_dcmp in sorted(dcmp.subdirs.items()):
            _walk(sub_dcmp, os.path.join(rel, sub) if rel else sub)

    _log(f"Comparing: {dir_a}")
    _log(f"     with: {dir_b}")

    dcmp = filecmp.dircmp(dir_a, dir_b)
    _walk(dcmp, "")

    _log("")
    _log(
        f"Result: {stats['matched']} matched, {stats['differ']} differ, "
        f"{stats['left_only']} only in left, {stats['right_only']} only in right"
    )
    if identical:
        _log("Directories are IDENTICAL.")
    else:
        _log("Directories DIFFER.")

    return identical


# ── CLI helpers ──────────────────────────────────────────────────────────────

def _parse_size(value: str) -> int:
    """Parse a human-readable byte size (e.g. ``512MiB``, ``2GiB``, ``1048576``)."""
    value = value.strip()
    multipliers = {
        "TIB": 1024**4, "TB": 1000**4,
        "GIB": 1024**3, "GB": 1000**3,
        "MIB": 1024**2, "MB": 1000**2,
        "KIB": 1024,    "KB": 1000,
        "B": 1,
    }
    upper = value.upper()
    for suffix, mult in multipliers.items():
        if upper.endswith(suffix):
            num = value[: len(value) - len(suffix)].strip()
            return int(float(num) * mult)
    return int(value)


def _prompt_password(confirm: bool = False) -> str:
    """Prompt interactively for a password (hidden input)."""
    pw = getpass("Password: ")
    if not pw:
        print("Error: password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if confirm:
        if getpass("Confirm password: ") != pw:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return pw


# ── Argument parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""

    # Shared flags inherited by all subcommands.
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show progress bars and status messages.",
    )

    from vault_tar import __version__

    parser = argparse.ArgumentParser(
        prog="vtar",
        description=(
            "Encrypt and decrypt files or directories using AES-256-GCM "
            "with PBKDF2-HMAC-SHA256 key derivation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s encrypt -i secret_docs/ -o encrypted -v\n"
            "  %(prog)s encrypt -i data.bin -o data.enc --file-only --no-split\n"
            "  %(prog)s encrypt -i photos/ -o photos --algorithm zst -v\n"
            "  %(prog)s decrypt -i encrypted -o restored/ -v\n"
            "  %(prog)s decrypt -i data.enc -o data.bin --file-only\n"
            "  %(prog)s compare original/ restored/ -v\n"
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── encrypt ──────────────────────────────────────────────────────────
    enc = sub.add_parser(
        "encrypt",
        parents=[shared],
        help="Encrypt files or directories.",
    )
    enc.add_argument(
        "-i",
        "--input",
        nargs="+",
        required=True,
        help="Input file(s) or directories to encrypt.",
    )
    enc.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output base filename (.partN suffixes added when splitting).",
    )
    enc.add_argument(
        "--password",
        default=None,
        help="Password (prompted securely if omitted).",
    )
    enc.add_argument(
        "--file-only",
        action="store_true",
        help="Encrypt a single file directly (skip tar archiving).",
    )
    enc.add_argument(
        "--algorithm",
        choices=["xz", "gz", "bz2", "zst", "none"],
        default=DEFAULT_ALGORITHM,
        help="Compression algorithm (default: %(default)s). "
        "'zst' requires Python ≥ 3.14.",
    )
    enc.add_argument(
        "--compression-level",
        type=int,
        default=None,
        metavar="N",
        help="Compression level (algorithm-specific). "
        "None uses the algorithm's default.",
    )
    enc.add_argument(
        "--chunk-size",
        type=_parse_size,
        default=DEFAULT_CHUNK_SIZE,
        help="Plaintext chunk size (default: 1MiB). Accepts: KiB, MiB, GiB.",
    )
    enc.add_argument(
        "--split-size",
        type=_parse_size,
        default=DEFAULT_SPLIT_SIZE,
        help="Max part-file size (default: 1GiB). Accepts: KiB, MiB, GiB.",
    )
    enc.add_argument(
        "--no-split",
        action="store_true",
        help="Write a single output file (disable splitting).",
    )
    enc.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove original input(s) after successful encryption.",
    )

    # ── decrypt ──────────────────────────────────────────────────────────
    dec = sub.add_parser(
        "decrypt",
        parents=[shared],
        help="Decrypt files or directories.",
    )
    dec.add_argument(
        "-i",
        "--input",
        required=True,
        help="Encrypted file or base name for split parts.",
    )
    dec.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output file (--file-only) or directory for extracted content.",
    )
    dec.add_argument(
        "--password",
        default=None,
        help="Password (prompted securely if omitted).",
    )
    dec.add_argument(
        "--file-only",
        action="store_true",
        help="Decrypt to a single file (skip decompression/extraction).",
    )
    dec.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove encrypted input(s) after successful decryption.",
    )

    # ── compare ─────────────────────────────────────────────────────────
    cmp = sub.add_parser(
        "compare",
        parents=[shared],
        help="Recursively compare two directories.",
    )
    cmp.add_argument(
        "dir_a",
        help="First directory to compare.",
    )
    cmp.add_argument(
        "dir_b",
        help="Second directory to compare.",
    )

    return parser


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    verbose: bool = args.verbose

    if args.command == "compare":
        ok = compare_directories(args.dir_a, args.dir_b, verbose=verbose)
        sys.exit(0 if ok else 1)

    password = args.password or _prompt_password(
        confirm=(args.command == "encrypt"),
    )

    if args.command == "encrypt":
        split_size = None if args.no_split else args.split_size

        if args.file_only:
            if len(args.input) != 1:
                parser.error("--file-only requires exactly one input file.")
            encrypt_file(
                args.input[0],
                output_filename=args.output,
                password=password,
                chunk_size=args.chunk_size,
                split_size=split_size,
                cleanup=args.cleanup,
                verbose=verbose,
            )
        else:
            encrypt_directories(
                *args.input,
                output_filename=args.output,
                password=password,
                algorithm=args.algorithm,
                compression_level=args.compression_level,
                chunk_size=args.chunk_size,
                split_size=split_size,
                cleanup=args.cleanup,
                verbose=verbose,
            )

    elif args.command == "decrypt":
        if args.file_only:
            decrypt_file(
                args.input,
                output_filename=args.output,
                password=password,
                cleanup=args.cleanup,
                verbose=verbose,
            )
        else:
            decrypt_to_directories(
                args.input,
                output_directory=args.output,
                password=password,
                cleanup=args.cleanup,
                verbose=verbose,
            )

    if verbose:
        _log("Done.")


if __name__ == "__main__":
    main()
