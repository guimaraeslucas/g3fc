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
