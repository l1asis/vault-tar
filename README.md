# vault-tar

AES-256-GCM file and directory encryption with chunked streaming, configurable
compression, and optional output splitting.

## Features

- **AES-256-GCM** authenticated encryption with PBKDF2-HMAC-SHA256 key
  derivation (1 200 000 iterations by default).
- **Chunked streaming** — encrypts/decrypts in 1 MiB chunks so memory usage
  stays constant regardless of input size.
- **Compression** — choose between `xz`, `gz`, `bz2`, `zst`
  (Python ≥ 3.14), or `none`.
- **Output splitting** — split encrypted output into fixed-size parts (default
  1 GiB) for easier storage and transfer.
- **Single-file mode** — encrypt/decrypt individual files without tar
  archiving.
- **Directory comparison** — recursively compare two directory trees after a
  round-trip to verify integrity.
- **Progress bars** — optional verbose mode (`-v`) with real-time byte-level
  progress during compression, encryption, and decryption.

## Requirements

- Python ≥ 3.12
- [`cryptography`](https://cryptography.io/) ≥ 43.0

## Installation

### From PyPI

```bash
pip install vault-tar
```

### From source

```bash
git clone https://github.com/l1asis/vault-tar.git
cd vault-tar
pip install .
```

## Usage

After installation the `vtar` command is available on your `PATH`.

### Encrypt directories

```bash
vtar encrypt -i secret_docs/ photos/ -o encrypted -v
```

### Encrypt with a specific algorithm

```bash
vtar encrypt -i data/ -o data --algorithm zst -v        # zstandard (Python ≥ 3.14)
vtar encrypt -i data/ -o data --algorithm gz -v          # gzip
vtar encrypt -i data/ -o data --algorithm none -v        # tar only, no compression
```

### Encrypt a single file (skip archiving)

```bash
vtar encrypt -i backup.sql -o backup.enc --file-only --no-split
```

### Decrypt

```bash
vtar decrypt -i encrypted -o restored/ -v
vtar decrypt -i backup.enc -o backup.sql --file-only
```

### Compare directories

Verify that decrypted output matches the original:

```bash
vtar compare original/ restored/ -v
```

### Additional options

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Show progress bars and status messages |
| `--password TEXT` | Supply password on command line (prompted if omitted) |
| `--algorithm {xz,gz,bz2,zst,none}` | Compression algorithm (default: `xz`) |
| `--compression-level N` | Algorithm-specific compression level |
| `--chunk-size SIZE` | Plaintext chunk size (default: `1MiB`) |
| `--split-size SIZE` | Max part-file size (default: `1GiB`) |
| `--no-split` | Write a single output file |
| `--file-only` | Encrypt/decrypt a single file directly |
| `--cleanup` | Remove original input after success |
| `-V`, `--version` | Show version and exit |

Sizes accept human-readable suffixes: `KiB`, `MiB`, `GiB`.

## File format

All encrypted output follows a custom binary format (v1):

```
Header (first part only):
  [2 B]  magic  0xEF01
  [1 B]  format version  0x01
  [2 B]  salt length          [N B]  salt
  [2 B]  base-nonce length    [12 B] base nonce

Chunks (sequential across parts):
  [4 B]  ciphertext length    [N B]  ciphertext (plaintext + 16 B GCM tag)
```

Each chunk uses a unique nonce derived as `base_nonce XOR chunk_index`
(big-endian, 12 bytes) with AAD `b"chunk_<index>"`.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, cryptographic details,
known limitations, and responsible disclosure policy.

## Acknowledgments

Built with assistance from [GitHub Copilot](https://github.com/features/copilot)
(Claude Opus 4.6).

## License

[MIT](LICENSE) — Copyright 2026 Volodymyr Horshenin
