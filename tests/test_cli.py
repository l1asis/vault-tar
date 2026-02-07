"""CLI argument parsing tests — validation, edge cases, type coercion."""

from __future__ import annotations

import argparse

import pytest

from vault_tar.core import build_parser


@pytest.fixture()
def parser() -> argparse.ArgumentParser:
    return build_parser()


class TestEncryptSubcommand:
    """Encrypt argument parsing and validation."""

    def test_minimal_valid(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["encrypt", "-i", "src/", "-o", "out"])
        assert args.command == "encrypt"
        assert args.input == ["src/"]
        assert args.output == "out"
        assert args.file_only is False
        assert args.no_split is False
        assert args.cleanup is False
        assert args.verbose is False
        assert args.password is None

    def test_all_flags_combined(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args([
            "encrypt", "-i", "a/", "b/", "-o", "out",
            "--algorithm", "gz", "--compression-level", "6",
            "--chunk-size", "512KiB", "--split-size", "2GiB",
            "--cleanup", "--password", "s3cret", "-v",
        ])
        assert args.input == ["a/", "b/"]
        assert args.algorithm == "gz"
        assert args.compression_level == 6
        assert args.chunk_size == 512 * 1024
        assert args.split_size == 2 * 1024**3
        assert args.cleanup is True
        assert args.password == "s3cret"
        assert args.verbose is True

    def test_multiple_inputs(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["encrypt", "-i", "a", "b", "c", "-o", "x"])
        assert args.input == ["a", "b", "c"]

    @pytest.mark.parametrize("algo", ["xz", "gz", "bz2", "zst", "none"])
    def test_valid_algorithms(self, parser: argparse.ArgumentParser, algo: str) -> None:
        args = parser.parse_args(["encrypt", "-i", "x", "-o", "y", "--algorithm", algo])
        assert args.algorithm == algo

    def test_invalid_algorithm_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["encrypt", "-i", "x", "-o", "y", "--algorithm", "lz4"])

    def test_missing_input_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["encrypt", "-o", "out"])

    def test_missing_output_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["encrypt", "-i", "src/"])

    def test_chunk_size_human_readable(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["encrypt", "-i", "x", "-o", "y", "--chunk-size", "2MiB"])
        assert args.chunk_size == 2 * 1024**2

    def test_invalid_chunk_size_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["encrypt", "-i", "x", "-o", "y", "--chunk-size", "abc"])


class TestDecryptSubcommand:
    def test_minimal(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["decrypt", "-i", "enc", "-o", "out/"])
        assert args.command == "decrypt"
        assert args.file_only is False

    def test_file_only(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["decrypt", "-i", "f.enc", "-o", "f.txt", "--file-only"])
        assert args.file_only is True

    def test_cleanup_flag(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["decrypt", "-i", "x", "-o", "y", "--cleanup"])
        assert args.cleanup is True


class TestCompareSubcommand:
    def test_positional_args(self, parser: argparse.ArgumentParser) -> None:
        args = parser.parse_args(["compare", "dir_a", "dir_b", "-v"])
        assert args.command == "compare"
        assert args.dir_a == "dir_a"
        assert args.dir_b == "dir_b"
        assert args.verbose is True

    def test_missing_dir_b_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["compare", "dir_a"])


class TestGlobalFlags:
    def test_no_command_exits(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_version_exits_zero(self, parser: argparse.ArgumentParser) -> None:
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0

    @pytest.mark.parametrize(
        "args",
        [
            ["encrypt", "-i", "x", "-o", "y", "--password", "pw with spaces"],
            ["encrypt", "-i", "x", "-o", "y", "--password", "пароль"],
            ["encrypt", "-i", "x", "-o", "y", "--password", "a" * 10_000],
        ],
        ids=["spaces", "unicode", "very-long"],
    )
    def test_special_password_values(self, parser: argparse.ArgumentParser, args: list[str]) -> None:
        """Passwords with spaces, unicode, and extreme length must parse."""
        parsed = parser.parse_args(args)
        assert parsed.password is not None
