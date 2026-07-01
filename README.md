# Bulwark

A lightweight file encryption program written in Python.

## Installation

Python 3 is required to run Bulwark (future versions may come precompiled). You can download Python [here](https://www.python.org/downloads/) if you have not already done so.

A list of dependencies can be found in the requirements.txt file.

Then, download this repository.

## Usage

Bulwark uses a CLI (command-line interface).

Example encryption:
```bash
$ python main.py passwords.txt -e
```

Example decryption:
```bash
$ python main.py passwords.txt -d
```

Flags:
```bash
$ python main.py
usage: main.py [-h] [-e] [-d] [-o] file_path

positional arguments:
  file_path       Enter the file path of the file to encrypt or decrypt.

options:
  -h, --help      show this help message and exit
  -e, --encrypt   Encrypt the file
  -d, --decrypt   Decrypt the file
  -o, --overkill  Use overkill mode
```

## Cryptography

- Key Derivation
    - Argon2id
- Encryption
    - AEGIS-256
    - XChaCha20 cascaded with AEGIS-256 for overkill mode.
- Authentication
    - AEGIS-256

## .blwk File Structure

| Field               | Byte Size | Byte Offset |
| :------------------ | :-------- | :---------- |
| Magic Number        | 4         | 0           |
