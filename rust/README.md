# G3FC Archiver - Rust Implementation

This document provides instructions on how to set up and use the Rust version of the G3FC command-line archiver.

---

## 1. Prerequisites

- **Rust:** Version 2024 or later.
- **Packages:** The script relies on the following packages. You can install them using `cargo`.
  - anyhow
  - byteorder
  - chrono
  - walkdir
  - clap
  - serde
  - serde_cbor
  - serde_bytes
  - crc32fast
  - uuid
  - zstd
  - aes-gcm
  - pbkdf2
  - sha2
  - rand
  - reed-solomon-erasure

---

## 2. Setup

1.  **Navigate to the project directory** where the Cargo.toml is located.
2.  **Install and build** using `cargo`:

    ```bash
    cargo build --release
    ```

---

## 3. Usage

The application is run as a Python script from the command line.

**General Syntax:**
`python g3fc.py <command> [options] [paths...]`
