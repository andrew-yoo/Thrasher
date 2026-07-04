# Thrasher

A lightweight file encryption program written in Python.

## Installation

```bash
pip install Thrasher
```

## Usage

Currently, Thrasher only supports CLI usage.

```bash
thrasher --help
usage: thrasher [-h] (-e | -d) [-o] [-v] [-w] file

Thrasher

positional arguments:
  file             file to encrypt or decrypt

options:
  -h, --help       show this help message and exit
  -e, --encrypt    encrypt the file
  -d, --decrypt    decrypt the file
  -o, --overkill   use overkill mode (encrypt only)
  -v, --verify     verify before decrypting
  -w, --overwrite  overwrite the input file
```

## Cryptography

- Key derivation: Argon2id
- Subkey derivation: BLAKE2b
- AEAD: AEGIS-256 (and XChaCha20 in overkill mode)


See the [crypto.md](crypto.md) file for more details.