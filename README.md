<p align="center">
  <img src="https://g3pix.com.br/g3fc/g3fc.jpeg" alt="G3FC Logo" width="275"/>
</p>

<h1 align="center">G3FC Archiver Tool</h1>

<p align="center">
  <strong>The Modern, Secure, and Resilient File Archive Format</strong>
</p>

<p align="center">
    <a href="https://github.com/guimaraeslucas/g3fc/releases/tag/1"><img src="https://img.shields.io/github/v/release/guimaraeslucas/g3fc?style=for-the-badge&label=Latest%20Release" alt="Latest Release"></a>
    <a href="https://github.com/guimaraeslucas/g3fc/blob/main/LICENSE"><img src="https://img.shields.io/github/license/guimaraeslucas/g3fc?style=for-the-badge&label=License" alt="License"></a>
</p>

<p align="center">
  <a href="#-why-g3fc-is-the-superior-choice">Key Features</a> •
  <a href="#-g3fc-vs-legacy-formats">Comparison</a> •
  <a href="#-performance-benchmarks">Benchmarks</a> •
  <a href="#-getting-started">Get Started</a> •
  <a href="#-implementations">Implementations</a> •
  <a href="#-technical-specification">Specification</a> •
  <a href="https://github.com/guimaraeslucas/g3fc/wiki">Wiki</a>
</p>

---

Stop settling for slow, insecure, and outdated archive formats. **G3FC (G3 File Container)** is an open-source file archiver built for today's data challenges, delivering elite speed, security, and resilience for any workflow. It's the perfect solution for everything from **short-term data transfer** to **long-term cold storage**.

## ✨ Why G3FC is the Superior Choice

Engineered from the ground up to outperform legacy formats in every key area.

* 🚀 **Extreme Speed & Efficiency**: Powered by modern **Zstandard (Zstd)** compression, G3FC crushes legacy formats with lightning-fast compression and decompression speeds, saving you valuable time and resources. The Python implementation is particularly fast due to its use of native library bindings.
* 🛡️ **Bulletproof Security**: Your data deserves the best protection. G3FC uses military-grade **AES-256-GCM authenticated encryption**  to ensure your archives are both confidential and tamper-proof.
* 📦 **Versatile & Resilient Storage**: Perfect for both **long-term cold storage** and **short-term active use**. Built-in **Forward Error Correction (FEC)** guards against bit rot and data corruption over time, while the smart footer allows for instant file indexing without reading the entire archive—a massive advantage over TAR for large datasets.
* 💻 **Truly Cross-Platform**: G3FC is fully open-source and runs anywhere. Use our native implementations on **Mac, Windows, and Linux**. You're never locked into a single platform or vendor.

## 📊 G3FC vs. Legacy Formats

See how G3FC stacks up against the archives you're used to.

| Feature                   | G3FC                     | ZIP                             | TAR (tar.gz)                      |
| ------------------------- | ------------------------ | ------------------------------- | --------------------------------- |
| **Compression** | ✅ **Modern (Zstd)**       | ⚠️ Legacy (Deflate)              | ⚠️ Varies (Gzip)                   |
| **Security** | ✅ **AES-256-GCM**         | ⚠️ AES-256 (often weaker legacy) | ❌ None (requires external tools)  |
| **Data Resilience (FEC)** | ✅ **Built-in**             | ❌ None                         | ❌ None                           |
| **Archive Splitting** | ✅ **Built-in**              | ⚠️ Basic (Zipx)                 | ❌ Manual (via `split` command)     |
| **Fast Indexing** | ✅ **Yes (Footer)**          | ✅ Yes (Central Directory)      | ❌ No (Sequential Read)           |
| **Ideal Storage Use** | ✅ **Long & Short-Term**   | ⚠️ Short-Term                   | ⚠️ Varies                         |

## ⚡ Performance Benchmarks

G3FC with Zstd isn't just more feature-rich; it's faster and more efficient.

*(Benchmarks are representative and may vary based on data, hardware, and specific implementation.)*

#### Compression Ratio (Smaller is Better)

| Algorithm       | Compressed Size (1GB Text Data) |
| --------------- | ------------------------------- |
| Gzip (tar.gz)   | ~350 MB                         |
| **Zstd (G3FC)** | **~280 MB** |

#### CPU Usage (Lower is Better)

| Tool / Algorithm  | Compression (Relative) | Decompression (Relative) |
| ----------------- | ---------------------- | ------------------------ |
| 7-Zip (LZMA2)     | 100%                   | 85%                      |
| **Zstd (G3FC)** | **~70%** | **~40%** |

## 🚀 Getting Started

Download the latest pre-compiled binaries for your operating system from the releases page.

➡️ **[Download Latest Release](https://github.com/guimaraeslucas/g3fc/releases)**

## 🛠️ Implementations

G3FC is designed for broad compatibility. Explore our official open-source libraries to integrate G3FC into your own projects.

* **[C# / .NET](https://github.com/guimaraeslucas/g3fc/tree/main/csharp)**: A fully-featured .NET command line interface for integration into your C# applications.
* **[Go (Golang)](https://github.com/guimaraeslucas/g3fc/tree/main/golang)**: A high-performance Go command-line tool for maximum speed.
* **[Rust](https://github.com/guimaraeslucas/g3fc/tree/main/rust)**: Experience ultimate performance and memory safety with our Rust command-line tool.
* **[Python](https://github.com/guimaraeslucas/g3fc/tree/main/python)**: A flexible Python command line interface using native bindings for incredible speed, perfect for scripting and data science.

## 📄 Technical Specification

The G3FC format is built on an open, detailed specification to ensure cross-platform compatibility and encourage community implementation.

| Format | Link                                          |
| :----- | :-------------------------------------------- |
| PDF    | [https://g3pix.com.br/g3fc/g3fc_file_format_specification.pdf](https://g3pix.com.br/g3fc/g3fc_file_format_specification.pdf) |
| XML    | [https://g3pix.com.br/g3fc/g3fc_file_format_specification.xml](https://g3pix.com.br/g3fc/g3fc_file_format_specification.xml) |
| TXT    | [https://g3pix.com.br/g3fc/g3fc_file_format_specification.txt](https://g3pix.com.br/g3fc/g3fc_file_format_specification.txt) |
| HTML   | [https://g3pix.com.br/g3fc/g3fc_file_format_specification.html](https://g3pix.com.br/g3fc/g3fc_file_format_specification.html) |

## 📜 License

This project is licensed under the **GNU General Public License v2.0**. Please see the [LICENSE](https://github.com/guimaraeslucas/g3fc/blob/main/LICENSE) file for details.

## 📞 Contact
<img src="https://g3pix.com.br/favicon.svg" alt="G3pix Logo" width="48"/>
This project is maintained by G3Pix.

* **Author**: G3Pix / Lucas Guimarães - Proudly made in Brazil to the World
* **Website**: [g3pix.com.br/g3fc](https://g3pix.com.br/g3fc/)

---
