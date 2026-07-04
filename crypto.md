# Crypto

This is a living document.

## Goals

- Ease of use, both on CLI and GUI
- Future-proof (including Post-quantum) security
- Speed

## Threat model

### Security Goals

- Confidentiality of plaintext data
- Integrity of encrypted data and metadata
- Resistance to offline cracking by a well-funded attacker
- Safe handling of plaintext during encryption and decryption

### Assumptions

- The user's computer is not already fully compromised
- Encrypted files are available
- Filenames, sizes, and timestamps are all known
- Argon2id is a memory-hard hash
- AEGIS-256 provides both security and authenticity

### Main Threats

- Brute-force attacks
- Ciphertext modification attacks
- Metadata leakage
- Side-channel attacks
    - Timing
    - CPU usage
    - Electrical draw

## Cryptography

### Key Derivation

Argon2id and BLAKE2b

### Authenticated Encryption

AEGIS-256 (cascaded with XChaCha20 in Overkill mode)