# G3FC Archiver - Go Implementation

This document provides instructions on how to compile and use the Go version of the G3FC command-line archiver.

---

## 1. Prerequisites

- **Go:** Version 1.24.2 or later.
- **Go Modules:** The project uses Go modules to manage dependencies. The required libraries are:
  - `github.com/google/uuid`
  - `github.com/fxamacker/cbor/v2`
  - `github.com/klauspost/compress/zstd`
  - `github.com/klauspost/reedsolomon`
  - `golang.org/x/crypto/pbkdf2`

---

## 2. Compilation

You can compile the application using standard Go tooling.

1.  **Navigate to the project directory** where the `go.mod` file is located.
2.  **Tidy dependencies:** This will download the required libraries.

    ```bash
    go mod tidy
    ```

3.  **Build the executable:**

    ```bash
    go build -o g3fc
    ```
    (On Windows, you can name it `g3fc.exe`).

4.  The compiled executable `g3fc` will be created in the current directory.
