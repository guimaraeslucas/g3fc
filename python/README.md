# G3FC Archiver - Python Implementation

This document provides instructions on how to set up and use the Python version of the G3FC command-line archiver.

---

## 1. Prerequisites

- **Python:** Version 3.8 or later.
- **Pip Packages:** The script relies on the following packages. You can install them using `pip`.
  - `cbor2`: For handling the CBOR-encoded file index.
  - `zstandard`: For Zstandard compression.
  - `pycryptodome`: For AES-GCM encryption and PBKDF2.
  - `reedsolo`: For Reed-Solomon Forward Error Correction (FEC).

---

## 2. Setup

1.  **Navigate to the project directory** where the Python script is located.
2.  **Install the required libraries** using `pip`:

    ```bash
    pip install cbor2 zstandard pycryptodome reedsolo
    ```

---

## 3. Usage

The application is run as a Python script from the command line.

**General Syntax:**
`python g3fc.py <command> [options] [paths...]`

