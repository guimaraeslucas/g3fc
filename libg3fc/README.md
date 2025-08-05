# G3FC Archiver - Rust FFI Library

This document provides instructions on how to build, install, and use the Rust version of the G3FC library. This is a dynamic library intended to be called from other programming languages through a C-compatible Application Binary Interface (ABI).

-----

## 1\. Prerequisites

  - **Rust:** A recent Rust toolchain that supports the 2024 edition or later.
  - **Dependencies:** The project relies on several crates. They are managed automatically by Cargo and do not require manual installation. The primary dependencies are:
      - anyhow
      - byteorder
      - chrono
      - crc32fast
      - pbkdf2
      - rand
      - reed-solomon-erasure
      - serde / serde\_cbor / serde\_json
      - sha2
      - uuid
      - walkdir
      - aes-gcm
      - regex
      - zstd
      - lazy\_static

-----

## 2\. Compilation

You can compile the library using standard Cargo tooling.

1.  **Navigate to the project directory** where the `Cargo.toml` file is located.

2.  **Build the dynamic library:** (this will also download and compile all required dependencies)

    ```bash
    cargo build --release
    ```

3.  The compiled library will be created in the `target/release` directory.

      - On Linux: `libg3fc.so`
      - On Windows: `g3fc.dll`
      - On macOS: `libg3fc.dylib`

-----

## 3\. Installation

Once compiled, the library file must be placed in a location where the system's dynamic linker can find it.

  - **Linux:**

      - Copy the `libg3fc.so` file to a standard library directory, such as `/usr/lib` or `/usr/local/lib`.

    <!-- end list -->

    ```bash
    sudo cp target/release/libg3fc.so /usr/lib/
    ```

      - You may need to run `ldconfig` to update the linker's cache.

    <!-- end list -->

    ```bash
    sudo ldconfig
    ```

  - **Windows:**

      - Place the `g3fc.dll` file in the same directory as the executable that will be calling it.
      - Alternatively, place it in a directory that is part of the system's `PATH` environment variable.

  - **Debian-based Systems (amd64):**

      - A pre-compiled Debian package (`.deb`) is available for the `amd64` architecture. This package will install the library to the correct location automatically.

-----

## 4\. Usage - C ABI Headers

To use the library from a C/C++ application or any language with a C FFI interface (like PHP, Python, C\#, etc.), you can use the following header definitions. All functions return `0` or a valid pointer on success. On failure, they return `-1` or `NULL` and set an internal error message that can be retrieved with `g3fc_last_error_message()`. Remember to free any strings returned by the library using `g3fc_free_string()`.

```c
#include <stdint.h>
#include <stdbool.h>

/*
 * =======================
 * Memory and Error API
 * =======================
 */

/**
 * @brief Frees a string pointer that was returned by a g3fc_* function.
 * @param s The pointer to the string to be freed.
 */
void g3fc_free_string(char* s);

/**
 * @brief Retrieves the last error message that occurred in a g3fc_* function.
 * @return A pointer to the error message string. This pointer MUST be freed with g3fc_free_string(). Returns NULL if no error occurred.
 */
char* g3fc_last_error_message();

/*
 * =======================
 * Core Archiver API
 * =======================
 */

/**
 * @brief Creates an archive based on JSON-formatted arguments.
 * @param json_args A C string containing the arguments in JSON format.
 * @return 0 on success, -1 on failure.
 */
int32_t g3fc_create_archive(const char* json_args);

/**
 * @brief Extracts an entire archive to a specified directory.
 * @param archive_path Path to the .g3fc archive file.
 * @param output_dir Path to the destination directory.
 * @param password The archive password. Use NULL for unencrypted archives.
 * @return 0 on success, -1 on failure.
 */
int32_t g3fc_extract_archive(const char* archive_path, const char* output_dir, const char* password);

/**
 * @brief Extracts a single file or directory from an archive.
 * @param archive_path Path to the .g3fc archive file.
 * @param file_in_archive The exact path of the file to extract from the archive.
 * @param output_dir Path to the destination directory.
 * @param password The archive password. Use NULL for unencrypted archives.
 * @return 0 on success, -1 on failure.
 */
int32_t g3fc_extract_single(const char* archive_path, const char* file_in_archive, const char* output_dir, const char* password);

/*
 * =======================
 * Information API
 * =======================
 */

/**
 * @brief Lists the files stored in the archive.
 * @param archive_path Path to the .g3fc archive file.
 * @param password The archive password. Use NULL for unencrypted archives.
 * @return A JSON string of file entries. The string must be freed with g3fc_free_string(). Returns NULL on error.
 */
char* g3fc_list_files(const char* archive_path, const char* password);

/**
 * @brief Exports the full, detailed file metadata index to a JSON string.
 * @param archive_path Path to the .g3fc archive file.
 * @param password The archive password. Use NULL for unencrypted archives.
 * @return A detailed JSON string of all metadata. The string must be freed with g3fc_free_string(). Returns NULL on error.
 */
char* g3fc_info_export_json(const char* archive_path, const char* password);

/**
 * @brief Finds files within an archive by a pattern.
 * @param archive_path Path to the .g3fc archive file.
 * @param pattern The search pattern (substring or regex).
 * @param password The archive password. Use NULL for unencrypted archives.
 * @param is_regex Set to true if the pattern is a regular expression, false for simple substring matching.
 * @return A JSON string of matching file entries. The string must be freed with g3fc_free_string(). Returns NULL on error.
 */
char* g3fc_find_files(const char* archive_path, const char* pattern, const char* password, bool is_regex);
