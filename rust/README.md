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

## 2. Compilation

You can compile the application using standard Cargo tooling.

1.  **Navigate to the project directory** where the `Cargo.toml` file is located.

2.  **Build the executable:** (this will also download the required libraries)

    ```bash
    cargo build --release
    ```

3.  The compiled executable `g3fc_rust(.exe)` will be created in the release directory.
