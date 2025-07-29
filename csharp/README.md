# G3FC Archiver - C# Implementation

This document provides instructions on how to compile and use the C# version of the G3FC command-line archiver. This implementation serves as the reference for the G3FC specification.

---

## 1. Prerequisites

- **.NET SDK:** Version 9.0 or later.
- **NuGet Packages:** The project relies on the following packages, which will be restored automatically by the .NET build tools:
  - `ZstdSharp.Port`: For Zstandard compression.
  - `Witteborn.ReedSolomon`: For Reed-Solomon Forward Error Correction (FEC).
  - `System.Formats.Cbor`: For handling the file index.

---

## 2. Compilation

You can compile the application using the standard .NET CLI.

1.  **Navigate to the project directory** where the `.csproj` file is located.
2.  **Restore dependencies and build the project:**

    ```bash
    dotnet build --configuration Release
    ```

3.  The compiled executable will be located in the `bin/Release/net9.0/` directory. You can run it directly from there or publish it as a self-contained application.

    **To publish for your platform:**
    ```bash
    dotnet publish --configuration Release --runtime <RID> --self-contained true
    ```
    (Replace `<RID>` with your platform's Runtime Identifier, e.g., `win-x64`, `linux-x64`, `osx-x64`).

---

## 3. Usage

The application is controlled via command-line arguments.

**General Syntax:**
`G3FC.exe <command> [options] [paths...]`

### Commands

-   `create` (or `c`): Creates a new G3FC archive.
-   `extract` (or `x`): Extracts files from an existing G3FC archive.

### Options for `create`

| Flag                      | Alias | Description                                                                 |
| ------------------------- | ----- | --------------------------------------------------------------------------- |
| `--output <path>`         | `-o`  | **Required.** Path for the output `.g3fc` file.                             |
| `--password <password>`   | `-p`  | Optional. Encrypts the archive with the specified password.                 |
| `--compression-level <1-22>`| `-cl` | Optional. Sets the Zstandard compression level. Default: `3`.               |
| `--global-compression`    | `-gc` | Optional. Compresses all files as a single block. Default: individual files.|
| `--fec-level <0-50>`      | `-fl` | Optional. Enables Reed-Solomon FEC with a given percentage of parity data.  |
| `--split <size>`          |       | Optional. Splits data into blocks of a specified size (e.g., `100MB`, `2GB`). |
| `[paths...]`              |       | **Required.** One or more files or folders to add to the archive.           |

**Example (Create):**
```bash
# Create a password-protected, split archive from a file and a folder
G3FC.exe create -o myarchive.g3fc -p "SecretPass123!" --split 500MB C:\data\report.docx C:\project\images# G3FC Archiver - C# Implementation

This document provides instructions on how to compile and use the C# version of the G3FC command-line archiver. This implementation serves as the reference for the G3FC specification.

---

## 1. Prerequisites

- **.NET SDK:** Version 9.0 or later.
- **NuGet Packages:** The project relies on the following packages, which will be restored automatically by the .NET build tools:
  - `ZstdSharp.Port`: For Zstandard compression.
  - `Witteborn.ReedSolomon`: For Reed-Solomon Forward Error Correction (FEC).
  - `System.Formats.Cbor`: For handling the file index.

---

## 2. Compilation

You can compile the application using the standard .NET CLI.

1.  **Navigate to the project directory** where the `.csproj` file is located.
2.  **Restore dependencies and build the project:**

    ```bash
    dotnet build --configuration Release
    ```

3.  The compiled executable will be located in the `bin/Release/net9.0/` directory. You can run it directly from there or publish it as a self-contained application.

    **To publish for your platform:**
    ```bash
    dotnet publish --configuration Release --runtime <RID> --self-contained true
    ```
    (Replace `<RID>` with your platform's Runtime Identifier, e.g., `win-x64`, `linux-x64`, `osx-x64`).

---

## 3. Usage

The application is controlled via command-line arguments.

**General Syntax:**
`G3FC.exe <command> [options] [paths...]`

### Commands

-   `create` (or `c`): Creates a new G3FC archive.
-   `extract` (or `x`): Extracts files from an existing G3FC archive.

### Options for `create`

| Flag                      | Alias | Description                                                                 |
| ------------------------- | ----- | --------------------------------------------------------------------------- |
| `--output <path>`         | `-o`  | **Required.** Path for the output `.g3fc` file.                             |
| `--password <password>`   | `-p`  | Optional. Encrypts the archive with the specified password.                 |
| `--compression-level <1-22>`| `-cl` | Optional. Sets the Zstandard compression level. Default: `3`.               |
| `--global-compression`    | `-gc` | Optional. Compresses all files as a single block. Default: individual files.|
| `--fec-level <0-50>`      | `-fl` | Optional. Enables Reed-Solomon FEC with a given percentage of parity data.  |
| `--split <size>`          |       | Optional. Splits data into blocks of a specified size (e.g., `100MB`, `2GB`). |
| `[paths...]`              |       | **Required.** One or more files or folders to add to the archive.           |

**Example (Create):**
```bash
# Create a password-protected, split archive from a file and a folder
G3FC.exe create -o myarchive.g3fc -p "SecretPass123!" --split 500MB C:\data\report.docx C:\project\images
