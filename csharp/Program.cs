//
// G3FC Archiver Tool - C# Version
//
// @author  Lucas Guimarães - G3Pix <https://github.com/guimaraeslucas/>
// @license GNU General Public License v2.0
// @version 1.1.3
//
// Copyright 2025, Lucas Guimarães - G3Pix Ltda <https://g3pix.com.br>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// SECURITY NOTICE AND IMPLEMENTATION GUIDANCE:
//
// While this C# implementation includes mitigations against the security vulnerabilities
// described below, any other implementation based on the G3FC specification MUST
// independently address these critical security concerns.
//
// For example and implementation purposes, this C# code shall always be considered
// the most up-to-date and secure reference.
//
// 1. Path Traversal: A maliciously crafted archive could contain paths intended
//    to overwrite sensitive system files (e.g., a path traversal attack using ../../..).
//    Implementations MUST rigorously validate and sanitize all path information from the
//    file index before writing any data to the local filesystem. File paths MUST be
//    treated as relative to the designated extraction directory, and any attempts to
//    write outside of this directory must be prevented.
//
// 2. Decompression Bomb: Implementations that parse this format SHOULD mitigate
//    the risk of decompression bombs by first checking the `uncompressed_size` field
//    in the file's metadata index and enforcing reasonable limits on resource
//    allocation before attempting decompression.

// ===================================================================================
// DEPENDENCY NOTES:
// This implementation requires .NET Core 9.0 for System.Formats.Cbor.
// Before running, you must install the necessary NuGet packages:
// 1. ZstdSharp.Port - For Zstandard compression
//    PM> Install-Package ZstdSharp.Port
// 2. Witteborn.ReedSolomon - For Forward Error Correction (FEC)
//    PM> Install-Package Witteborn.ReedSolomon
// 3. System.Text.Json - For JSON operations (usually included in .NET SDK)
// ===================================================================================

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Witteborn.ReedSolomon;

namespace G3FC
{
    #region 1. Data Structures and Constants
    public static class Constants
    {
        public const string MagicNumber = "G3FC";
        public const string FooterMagic = "G3CE";
        public const int HeaderSize = 331;
        public const int FooterSize = 40;
        public const string CreatingSystem = "G3Pix C# G3FC Archiver";
        public const string SoftwareVersion = "1.1.3";
        public const int MaxFECLibShards = 255;
        public const int MinFECShards = 1;
        public const int MaxFECShards = 254;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
    public struct MainHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] MagicNumber;
        public ushort FormatVersionMajor;
        public ushort FormatVersionMinor;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ContainerUUID;
        public long CreationTimestamp;
        public long ModificationTimestamp;
        public uint EditVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] CreatingSystem;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] SoftwareVersion;
        public ulong FileIndexOffset;
        public ulong FileIndexLength;
        public byte FileIndexCompression;
        public byte GlobalCompression;
        public byte EncryptionMode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ReadSalt;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] WriteSalt;
        public uint KDFIterations;
        public byte FECScheme;
        public byte FECLevel;
        public ulong FECDataOffset;
        public ulong FECDataLength;
        public uint HeaderChecksum;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        public byte[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Footer
    {
        public ulong MainIndexOffset;
        public ulong MainIndexLength;
        public ulong MetadataFECBlockOffset;
        public ulong MetadataFECBlockLength;
        public uint FooterChecksum;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] FooterMagic;
    }

    public class FileEntry
    {
        public string Path { get; set; }
        public string Type { get; set; }
        public byte[] UUID { get; set; }
        public long CreationTime { get; set; }
        public long ModificationTime { get; set; }
        public ushort Permissions { get; set; }
        public uint OwnerID { get; set; }
        public uint GroupID { get; set; }
        public byte Status { get; set; }
        public string OriginalFilename { get; set; }
        public ulong DataOffset { get; set; }
        public ulong DataSize { get; set; }
        public ulong UncompressedSize { get; set; }
        public byte Compression { get; set; }
        public uint Checksum { get; set; }
        public uint BlockFileIndex { get; set; }
        public byte[] ChunkGroupId { get; set; }
        public uint ChunkIndex { get; set; }
        public uint TotalChunks { get; set; }
        public Dictionary<string, object> CustomMetadata { get; set; }
    }

    public class Config
    {
        public int CompressionLevel { get; set; } = 6;
        public bool GlobalCompression { get; set; } = false;
        public byte EncryptionMode { get; set; } = 0;
        public string ReadPassword { get; set; } = "";
        public string WritePassword { get; set; } = "";
        public uint KDFIterations { get; set; } = 100000;
        public byte FECScheme { get; set; } = 0;
        public byte FECLevel { get; set; } = 0;
        public long SplitSize { get; set; } = 0;
    }
    #endregion

    #region 2. G3FC Writer
    public static class G3FCWriter
    {
        public static void CreateG3FCArchive(string outputFilePath, List<Tuple<string, string>> sourceFiles, Config config)
        {
            var fileIndex = new List<FileEntry>();
            var dataBlockStream = new MemoryStream();
            foreach (var fileTuple in sourceFiles)
            {
                string fullPath = fileTuple.Item1;
                string relativePath = fileTuple.Item2;

                if (!File.Exists(fullPath))
                {
                    Console.WriteLine($"Warning: Skipping non-existent file {fullPath}");
                    continue;
                }

                Console.WriteLine($"Adding: {relativePath}");
                var fileInfo = new FileInfo(fullPath);
                var fileData = File.ReadAllBytes(fullPath);

                var entry = new FileEntry
                {
                    Path = relativePath.Replace('\\', '/'),
                    Type = "file",
                    UUID = Guid.NewGuid().ToByteArray(),
                    CreationTime = fileInfo.CreationTimeUtc.Ticks,
                    ModificationTime = fileInfo.LastWriteTimeUtc.Ticks,
                    Permissions = PermissionsHelper.GetPermissions(fullPath),
                    Status = 0,
                    OriginalFilename = fileInfo.Name,
                    UncompressedSize = (ulong)fileData.Length,
                    Checksum = Crc32.Compute(fileData)
                };

                byte[] dataToAdd;
                if (config.GlobalCompression)
                {
                    dataToAdd = fileData;
                    entry.Compression = 0;
                }
                else
                {
                    using var compressor = new ZstdSharp.Compressor(config.CompressionLevel);
                    dataToAdd = compressor.Wrap(fileData).ToArray();
                    entry.Compression = 1;
                }

                entry.DataOffset = (ulong)dataBlockStream.Position;
                entry.DataSize = (ulong)dataToAdd.Length;
                dataBlockStream.Write(dataToAdd, 0, dataToAdd.Length);

                fileIndex.Add(entry);
            }

            byte[] readKey = null;
            byte[] readSalt = null;
            byte[] writeSalt = null;
            if (config.EncryptionMode > 0)
            {
                readSalt = RandomNumberGenerator.GetBytes(64);
                readKey = new Rfc2898DeriveBytes(config.ReadPassword, readSalt, (int)config.KDFIterations, HashAlgorithmName.SHA256).GetBytes(32);
                writeSalt = config.EncryptionMode == 2 ? RandomNumberGenerator.GetBytes(64) : readSalt;
            }

            if (config.SplitSize > 0)
            {
                WriteSplitArchive(outputFilePath, fileIndex, dataBlockStream.ToArray(), config, readKey, readSalt, writeSalt);
            }
            else
            {
                WriteSingleArchive(outputFilePath, fileIndex, dataBlockStream.ToArray(), config, readKey, readSalt, writeSalt);
            }
        }

        private static void WriteSingleArchive(string outputFilePath, List<FileEntry> fileIndex, byte[] fileDataBlockBytes, Config config, byte[] readKey, byte[] readSalt, byte[] writeSalt)
        {
            if (config.GlobalCompression)
            {
                Console.WriteLine("\nApplying global compression to data block...");
                using var compressor = new ZstdSharp.Compressor(config.CompressionLevel);
                fileDataBlockBytes = compressor.Wrap(fileDataBlockBytes).ToArray();
            }
            if (config.EncryptionMode > 0)
            {
                fileDataBlockBytes = G3FCHelpers.EncryptAESGCM(fileDataBlockBytes, readKey);
            }

            byte[] uncompressedIndexBytes = G3FCHelpers.SerializeIndex(fileIndex);
            using var indexCompressor = new ZstdSharp.Compressor();
            byte[] compressedIndexBytes = indexCompressor.Wrap(uncompressedIndexBytes).ToArray();
            byte[] indexBlockBytes = compressedIndexBytes;
            if (config.EncryptionMode > 0)
            {
                indexBlockBytes = G3FCHelpers.EncryptAESGCM(compressedIndexBytes, readKey);
            }

            var header = CreateHeader(config, readSalt, writeSalt);
            ulong currentOffset = Constants.HeaderSize;
            header.FileIndexOffset = currentOffset;
            header.FileIndexLength = (ulong)indexBlockBytes.Length;
            currentOffset += header.FileIndexLength;
            currentOffset += (ulong)fileDataBlockBytes.Length;
            header.FECDataOffset = currentOffset;

            byte[] dataFECBytes = config.FECScheme == 1 ? G3FCHelpers.CreateFEC(fileDataBlockBytes, config.FECLevel) : new byte[0];
            header.FECDataLength = (ulong)dataFECBytes.Length;
            currentOffset += header.FECDataLength;

            byte[] metadataFECBytes = new byte[0];
            if (config.FECScheme == 1)
            {
                byte[] tempHeaderBytes = G3FCHelpers.StructToBytes(header);
                var metadataToProtect = tempHeaderBytes.Concat(uncompressedIndexBytes).ToArray();
                metadataFECBytes = G3FCHelpers.CreateFEC(metadataToProtect, 10);
            }

            var footer = CreateFooter(header, currentOffset, (ulong)metadataFECBytes.Length);

            header.ModificationTimestamp = DateTime.UtcNow.Ticks;
            byte[] finalHeaderBytes = G3FCHelpers.StructToBytes(header);
            header.HeaderChecksum = Crc32.Compute(finalHeaderBytes.Take(finalHeaderBytes.Length - 54).ToArray());

            using (var fileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                fileStream.Write(G3FCHelpers.StructToBytes(header), 0, Constants.HeaderSize);
                fileStream.Write(indexBlockBytes, 0, indexBlockBytes.Length);
                fileStream.Write(fileDataBlockBytes, 0, fileDataBlockBytes.Length);
                fileStream.Write(dataFECBytes, 0, dataFECBytes.Length);
                fileStream.Write(metadataFECBytes, 0, metadataFECBytes.Length);
                fileStream.Write(G3FCHelpers.StructToBytes(footer), 0, Constants.FooterSize);
            }

            Console.WriteLine($"\nFile '{outputFilePath}' created successfully.");
        }

        private static void WriteSplitArchive(string outputFilePath, List<FileEntry> originalFileIndex, byte[] combinedData, Config config, byte[] readKey, byte[] readSalt, byte[] writeSalt)
        {
            Console.WriteLine($"\nSplitting data into blocks of max {config.SplitSize / 1024 / 1024} MB...");
            long splitSize = config.SplitSize;
            int blockIndex = 0;
            var finalFileIndex = new List<FileEntry>();

            using var currentBlockStream = new MemoryStream();

            foreach (var entry in originalFileIndex)
            {
                var entryData = new byte[entry.DataSize];
                Array.Copy(combinedData, (long)entry.DataOffset, entryData, 0, (long)entry.DataSize);

                var chunkGroupId = Guid.NewGuid().ToByteArray();
                long entryDataOffset = 0;
                uint chunkIndex = 0;

                uint totalChunks = (uint)((entryData.Length + splitSize - 1) / splitSize);
                if (totalChunks == 0 && entryData.Length > 0) totalChunks = 1;
                if (totalChunks == 0 && entryData.Length == 0) totalChunks = 0;

                while (entryDataOffset < entryData.Length)
                {
                    long spaceInCurrentBlock = splitSize - currentBlockStream.Length;

                    if (spaceInCurrentBlock <= 0 && currentBlockStream.Length > 0)
                    {
                        WriteDataBlock(outputFilePath, blockIndex, currentBlockStream.ToArray(), config, readKey);
                        blockIndex++;
                        currentBlockStream.SetLength(0);
                        spaceInCurrentBlock = splitSize;
                    }

                    long bytesToWrite = Math.Min(entryData.Length - entryDataOffset, spaceInCurrentBlock);

                    var chunkEntry = new FileEntry
                    {
                        Path = entry.Path,
                        Type = entry.Type,
                        UUID = entry.UUID,
                        CreationTime = entry.CreationTime,
                        ModificationTime = entry.ModificationTime,
                        Permissions = entry.Permissions,
                        Status = entry.Status,
                        OriginalFilename = entry.OriginalFilename,
                        UncompressedSize = entry.UncompressedSize,
                        Checksum = entry.Checksum,
                        Compression = entry.Compression,
                        BlockFileIndex = (uint)blockIndex,
                        DataOffset = (ulong)currentBlockStream.Position,
                        DataSize = (ulong)bytesToWrite,
                        ChunkGroupId = chunkGroupId,
                        ChunkIndex = chunkIndex,
                        TotalChunks = totalChunks
                    };
                    finalFileIndex.Add(chunkEntry);

                    currentBlockStream.Write(entryData, (int)entryDataOffset, (int)bytesToWrite);
                    entryDataOffset += bytesToWrite;
                    chunkIndex++;
                }
            }

            if (currentBlockStream.Length > 0)
            {
                WriteDataBlock(outputFilePath, blockIndex, currentBlockStream.ToArray(), config, readKey);
            }

            byte[] uncompressedIndexBytes = G3FCHelpers.SerializeIndex(finalFileIndex);
            using var indexCompressor = new ZstdSharp.Compressor();
            byte[] compressedIndexBytes = indexCompressor.Wrap(uncompressedIndexBytes).ToArray();
            byte[] indexBlockBytes = compressedIndexBytes;
            if (config.EncryptionMode > 0)
            {
                indexBlockBytes = G3FCHelpers.EncryptAESGCM(compressedIndexBytes, readKey);
            }

            var header = CreateHeader(config, readSalt, writeSalt);
            header.FileIndexOffset = Constants.HeaderSize;
            header.FileIndexLength = (ulong)indexBlockBytes.Length;
            header.FECDataOffset = 0;
            header.FECDataLength = 0;

            ulong currentOffset = Constants.HeaderSize + (ulong)indexBlockBytes.Length;

            byte[] metadataFECBytes = new byte[0];
            if (config.FECScheme == 1)
            {
                byte[] tempHeaderBytes = G3FCHelpers.StructToBytes(header);
                var metadataToProtect = tempHeaderBytes.Concat(uncompressedIndexBytes).ToArray();
                metadataFECBytes = G3FCHelpers.CreateFEC(metadataToProtect, 10);
            }

            var footer = CreateFooter(header, currentOffset, (ulong)metadataFECBytes.Length);

            header.ModificationTimestamp = DateTime.UtcNow.Ticks;
            byte[] finalHeaderBytes = G3FCHelpers.StructToBytes(header);
            header.HeaderChecksum = Crc32.Compute(finalHeaderBytes.Take(finalHeaderBytes.Length - 54).ToArray());

            using (var fileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                fileStream.Write(G3FCHelpers.StructToBytes(header), 0, Constants.HeaderSize);
                fileStream.Write(indexBlockBytes, 0, indexBlockBytes.Length);
                fileStream.Write(metadataFECBytes, 0, metadataFECBytes.Length);
                fileStream.Write(G3FCHelpers.StructToBytes(footer), 0, Constants.FooterSize);
            }
            Console.WriteLine($"\nIndex file '{outputFilePath}' and {blockIndex + 1} data block(s) created successfully.");
        }

        private static void WriteDataBlock(string baseFilePath, int blockIndex, byte[] data, Config config, byte[] readKey)
        {
            string blockPath = $"{baseFilePath}{blockIndex}";
            Console.WriteLine($"Writing block: {Path.GetFileName(blockPath)} ({data.Length} bytes)");

            if (config.GlobalCompression)
            {
                using var compressor = new ZstdSharp.Compressor(config.CompressionLevel);
                data = compressor.Wrap(data).ToArray();
            }
            if (config.EncryptionMode > 0)
            {
                data = G3FCHelpers.EncryptAESGCM(data, readKey);
            }

            File.WriteAllBytes(blockPath, data);
        }

        private static MainHeader CreateHeader(Config config, byte[] readSalt, byte[] writeSalt)
        {
            var header = new MainHeader
            {
                MagicNumber = Encoding.ASCII.GetBytes(Constants.MagicNumber),
                FormatVersionMajor = 1,
                FormatVersionMinor = 0,
                EditVersion = 1,
                CreationTimestamp = DateTime.UtcNow.Ticks,
                ContainerUUID = Guid.NewGuid().ToByteArray(),
                CreatingSystem = new byte[32],
                SoftwareVersion = new byte[32],
                EncryptionMode = config.EncryptionMode,
                KDFIterations = config.KDFIterations,
                FECScheme = config.FECScheme,
                FECLevel = config.FECLevel,
                FileIndexCompression = 1,
                GlobalCompression = (byte)(config.GlobalCompression ? 1 : 0),
                ReadSalt = new byte[64],
                WriteSalt = new byte[64],
                Reserved = new byte[50]
            };
            Encoding.UTF8.GetBytes(Constants.CreatingSystem).CopyTo(header.CreatingSystem, 0);
            Encoding.UTF8.GetBytes(Constants.SoftwareVersion).CopyTo(header.SoftwareVersion, 0);
            if (readSalt != null) readSalt.CopyTo(header.ReadSalt, 0);
            if (writeSalt != null) writeSalt.CopyTo(header.WriteSalt, 0);
            return header;
        }

        private static Footer CreateFooter(MainHeader header, ulong metadataFecOffset, ulong metadataFecLength)
        {
            var footer = new Footer
            {
                MainIndexOffset = header.FileIndexOffset,
                MainIndexLength = header.FileIndexLength,
                MetadataFECBlockOffset = metadataFecOffset,
                MetadataFECBlockLength = metadataFecLength,
                FooterMagic = Encoding.ASCII.GetBytes(Constants.FooterMagic)
            };

            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(footer.MainIndexOffset);
                writer.Write(footer.MainIndexLength);
                writer.Write(footer.MetadataFECBlockOffset);
                writer.Write(footer.MetadataFECBlockLength);
                footer.FooterChecksum = Crc32.Compute(ms.ToArray());
            }
            return footer;
        }
    }
    #endregion

    #region 3. G3FC Reader
    public static class G3FCReader
    {
        public static List<FileEntry> ReadFileIndex(string filePath, string readPassword)
        {
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(fileStream, 0, Constants.HeaderSize));
            var footer = G3FCHelpers.BytesToStruct<Footer>(G3FCHelpers.ReadBytes(fileStream, fileStream.Length - Constants.FooterSize, Constants.FooterSize));

            if (Encoding.ASCII.GetString(header.MagicNumber) != Constants.MagicNumber) throw new Exception("Invalid header magic number.");
            if (Encoding.ASCII.GetString(footer.FooterMagic) != Constants.FooterMagic) throw new Exception("Invalid footer magic number.");

            byte[] indexBlockBytes = G3FCHelpers.ReadBytes(fileStream, (long)header.FileIndexOffset, (int)header.FileIndexLength);

            if (header.EncryptionMode > 0)
            {
                if (string.IsNullOrEmpty(readPassword)) throw new Exception("Password required.");
                var readKey = new Rfc2898DeriveBytes(readPassword, header.ReadSalt, (int)header.KDFIterations, HashAlgorithmName.SHA256).GetBytes(32);
                indexBlockBytes = G3FCHelpers.DecryptAESGCM(indexBlockBytes, readKey);
            }

            if (header.FileIndexCompression == 1)
            {
                using var decompressor = new ZstdSharp.Decompressor();
                indexBlockBytes = decompressor.Unwrap(indexBlockBytes).ToArray();
            }

            return G3FCHelpers.DeserializeIndex(indexBlockBytes);
        }

        public static void ExtractFileFromChunks(string archivePath, List<FileEntry> chunks, string destDir, string readPassword)
        {
            if (chunks == null || chunks.Count == 0) return;

            var firstChunk = chunks.First();
            Console.WriteLine($"Extracting: {firstChunk.Path} ({chunks.Count} chunk(s))");

            var headerBytes = G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read), 0, Constants.HeaderSize);
            var header = G3FCHelpers.BytesToStruct<MainHeader>(headerBytes);

            using var reassembledStream = new MemoryStream();
            foreach (var chunk in chunks.OrderBy(c => c.ChunkIndex))
            {
                byte[] dataBlock;
                bool isSplit = header.FECDataOffset == 0 && header.FECDataLength == 0;

                if (isSplit)
                {
                    string blockPath = $"{archivePath}{chunk.BlockFileIndex}";
                    if (!File.Exists(blockPath)) throw new FileNotFoundException($"Data block not found: {blockPath}");
                    dataBlock = File.ReadAllBytes(blockPath);
                }
                else
                {
                    long dataBlockStart = (long)header.FileIndexOffset + (long)header.FileIndexLength;
                    long dataBlockEnd = (long)header.FECDataOffset;
                    if (dataBlockEnd == 0)
                    {
                        var fileInfo = new FileInfo(archivePath);
                        var footerBytes = G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read), fileInfo.Length - Constants.FooterSize, Constants.FooterSize);
                        var footer = G3FCHelpers.BytesToStruct<Footer>(footerBytes);
                        dataBlockEnd = (long)footer.MetadataFECBlockOffset;
                    }
                    dataBlock = G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read), dataBlockStart, (int)(dataBlockEnd - dataBlockStart));
                }

                if (header.EncryptionMode > 0)
                {
                    var readKey = new Rfc2898DeriveBytes(readPassword, header.ReadSalt, (int)header.KDFIterations, HashAlgorithmName.SHA256).GetBytes(32);
                    dataBlock = G3FCHelpers.DecryptAESGCM(dataBlock, readKey);
                }

                if (header.GlobalCompression == 1)
                {
                    using var decompressor = new ZstdSharp.Decompressor();
                    dataBlock = decompressor.Unwrap(dataBlock).ToArray();
                }

                var chunkData = dataBlock.Skip((int)chunk.DataOffset).Take((int)chunk.DataSize).ToArray();
                reassembledStream.Write(chunkData, 0, chunkData.Length);
            }

            byte[] finalData = reassembledStream.ToArray();
            ulong uncompressedSize = firstChunk.UncompressedSize;
            const long MAX_UNCOMPRESSED_SIZE_SAFE_LIMIT = 4L * 1024 * 1024 * 1024;

            try
            {
                DriveInfo driveInfo = new DriveInfo(Path.GetPathRoot(destDir));
                if ((long)uncompressedSize > driveInfo.AvailableFreeSpace)
                {
                    Console.WriteLine($"Error: Not enough disk space to extract {firstChunk.Path}. Required: {uncompressedSize / 1024.0 / 1024.0:F2} MB, Available: {driveInfo.AvailableFreeSpace / 1024.0 / 1024.0:F2} MB.");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not check disk space. {ex.Message}");
            }

            if (uncompressedSize > (ulong)MAX_UNCOMPRESSED_SIZE_SAFE_LIMIT)
            {
                Console.WriteLine($"\nWARNING: The file '{firstChunk.Path}' has a very large uncompressed size: {uncompressedSize / 1024.0 / 1024.0:F2} MB.");
                Console.WriteLine("Extracting it may consume a large amount of memory and cause system instability.");
                Console.Write("Do you want to proceed with the extraction? (y/n): ");
                string response = Console.ReadLine()?.ToLower();
                if (response != "y" && response != "yes")
                {
                    Console.WriteLine("Extraction cancelled by user.");
                    return;
                }
            }

            if (header.GlobalCompression == 0 && firstChunk.Compression == 1)
            {
                using var decompressor = new ZstdSharp.Decompressor();
                finalData = decompressor.Unwrap(finalData).ToArray();
            }

            if (Crc32.Compute(finalData) != firstChunk.Checksum)
            {
                throw new Exception($"Checksum mismatch for file {firstChunk.OriginalFilename}");
            }

            // CORRECTION: Robust path traversal check
            string normalizedDestDir = Path.GetFullPath(destDir);
            string destinationFileFullPath = Path.GetFullPath(Path.Combine(normalizedDestDir, firstChunk.Path));

            if (!destinationFileFullPath.StartsWith(normalizedDestDir + Path.DirectorySeparatorChar) && destinationFileFullPath != normalizedDestDir)
            {
                Console.WriteLine($"Error: Malicious path detected (Path Traversal attempt). Skipping file: {firstChunk.Path}");
                return;
            }

            string destPath = destinationFileFullPath;
            Directory.CreateDirectory(Path.GetDirectoryName(destPath));
            File.WriteAllBytes(destPath, finalData);

            PermissionsHelper.SetPermissions(destPath, firstChunk.Permissions);
        }
    }
    #endregion

    #region 4. G3FC Commands (New Functionality)
    public static class G3FCCommands
    {
        // DTO for clean JSON serialization in ExportInfo
        private class FileEntryJsonExport
        {
            public string Path { get; set; }
            public string Type { get; set; }
            public string UUID { get; set; }
            public string CreationTime { get; set; }
            public string ModificationTime { get; set; }
            public string Permissions { get; set; }
            public byte Status { get; set; }
            public string OriginalFilename { get; set; }
            public ulong UncompressedSize { get; set; }
            public uint Checksum { get; set; }
            public uint BlockFileIndex { get; set; }
            public string ChunkGroupId { get; set; }
            public uint ChunkIndex { get; set; }
            public uint TotalChunks { get; set; }
        }

        public static void ListFilesInContainer(string archivePath, string password, string sizeUnit = "KB", bool showDetails = false)
        {
            try
            {
                Console.WriteLine($"Listing contents of: {archivePath}\n");
                var fileIndex = G3FCReader.ReadFileIndex(archivePath, password);

                var fileGroups = fileIndex
                    .GroupBy(entry => entry.Path)
                    .Select(group => group.First())
                    .OrderBy(entry => entry.Path)
                    .ToList();

                Console.WriteLine($"{"Path",-60} {"Size",-15} {"Type",-12}" + (showDetails ? "Permissions  Creation Time            Checksum" : ""));
                Console.WriteLine(new string('-', 120));

                foreach (var entry in fileGroups)
                {
                    string formattedSize = FormatSize(entry.UncompressedSize, sizeUnit);
                    Console.Write($"{entry.Path,-60} {formattedSize,-15} {entry.Type,-12}");
                    if (showDetails)
                    {
                        long correctedTicks = CorrectTimestampIfNeeded(entry.CreationTime);
                        var creationTime = new DateTime(correctedTicks, DateTimeKind.Utc).ToLocalTime();
                        string permissions = PermissionsHelper.FormatPermissions(entry.Permissions);
                        Console.Write($" {permissions,-12} {creationTime:yyyy-MM-dd HH:mm:ss}  {entry.Checksum:X8}");
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing files: {ex.Message}");
            }
        }

        public static void ExportInfo(string archivePath, string password, string outputJsonPath)
        {
            try
            {
                var fileIndex = G3FCReader.ReadFileIndex(archivePath, password);

                var exportList = fileIndex.Select(entry => new FileEntryJsonExport
                {
                    Path = entry.Path,
                    Type = entry.Type,
                    UUID = new Guid(entry.UUID).ToString(),
                    CreationTime = new DateTime(CorrectTimestampIfNeeded(entry.CreationTime), DateTimeKind.Utc).ToString("o"),
                    ModificationTime = new DateTime(CorrectTimestampIfNeeded(entry.ModificationTime), DateTimeKind.Utc).ToString("o"),
                    Permissions = $"0o{Convert.ToString(entry.Permissions, 8)}",
                    Status = entry.Status,
                    OriginalFilename = entry.OriginalFilename,
                    UncompressedSize = entry.UncompressedSize,
                    Checksum = entry.Checksum,
                    BlockFileIndex = entry.BlockFileIndex,
                    ChunkGroupId = entry.ChunkGroupId != null && entry.ChunkGroupId.Length == 16 ? new Guid(entry.ChunkGroupId).ToString() : "N/A",
                    ChunkIndex = entry.ChunkIndex,
                    TotalChunks = entry.TotalChunks
                }).ToList();

                var options = new JsonSerializerOptions { WriteIndented = true };
                string jsonString = JsonSerializer.Serialize(exportList, options);
                File.WriteAllText(outputJsonPath, jsonString);
                Console.WriteLine($"File index successfully exported to {outputJsonPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting file info: {ex.Message}");
            }
        }

        public static void FindFilesInContainer(string archivePath, string password, string pattern, bool useRegex, string sizeUnit = "KB")
        {
            try
            {
                var fileIndex = G3FCReader.ReadFileIndex(archivePath, password);
                var fileGroups = fileIndex.GroupBy(entry => entry.Path).Select(g => g.First());

                IEnumerable<FileEntry> foundFiles;

                if (useRegex)
                {
                    var regex = new Regex(pattern, RegexOptions.IgnoreCase);
                    foundFiles = fileGroups.Where(entry => regex.IsMatch(entry.Path));
                }
                else
                {
                    foundFiles = fileGroups.Where(entry => entry.Path.Contains(pattern, StringComparison.OrdinalIgnoreCase));
                }

                Console.WriteLine($"\nFound {foundFiles.Count()} matching entries for pattern '{pattern}':");
                Console.WriteLine($"{"Path",-60} {"Size",-15} {"Creation Time"}");
                Console.WriteLine(new string('-', 100));

                foreach (var entry in foundFiles)
                {
                    string formattedSize = FormatSize(entry.UncompressedSize, sizeUnit);
                    long correctedTicks = CorrectTimestampIfNeeded(entry.CreationTime);
                    var creationTime = new DateTime(correctedTicks, DateTimeKind.Utc).ToLocalTime();
                    Console.WriteLine($"{entry.Path,-60} {formattedSize,-15} {creationTime:yyyy-MM-dd HH:mm:ss}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding files: {ex.Message}");
            }
        }

        public static void ExtractSingleFile(string archivePath, string password, string filePathInArchive, string destinationDir)
        {
            try
            {
                Console.WriteLine($"Attempting to extract '{filePathInArchive}' to '{destinationDir}'...");
                var fileIndex = G3FCReader.ReadFileIndex(archivePath, password);

                var chunksToExtract = fileIndex
                    .Where(entry => entry.Path.Equals(filePathInArchive, StringComparison.Ordinal))
                    .OrderBy(entry => entry.ChunkIndex)
                    .ToList();

                if (chunksToExtract.Count == 0)
                {
                    Console.WriteLine($"Error: File '{filePathInArchive}' not found in the archive.");
                    return;
                }

                var firstChunk = chunksToExtract.First();
                if (firstChunk.Type == "directory")
                {
                    string destPath = Path.Combine(destinationDir, firstChunk.Path);
                    Directory.CreateDirectory(destPath);
                    Console.WriteLine($"Successfully created directory: {destPath}");
                    return;
                }

                G3FCReader.ExtractFileFromChunks(archivePath, chunksToExtract, destinationDir, password);

                Console.WriteLine($"\nSuccessfully extracted '{filePathInArchive}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error extracting single file: {ex.Message}");
            }
        }

        private static string FormatSize(ulong bytes, string unit)
        {
            double size = bytes;
            switch (unit.ToUpper())
            {
                case "TB": return $"{size / (1024.0 * 1024.0 * 1024.0 * 1024.0):F2} TB";
                case "GB": return $"{size / (1024.0 * 1024.0 * 1024.0):F2} GB";
                case "MB": return $"{size / (1024.0 * 1024.0):F2} MB";
                case "KB": return $"{size / 1024.0:F2} KB";
                default: return $"{size} B";
            }
        }

        private static long CorrectTimestampIfNeeded(long ticks)
        {
            if (ticks > 3000000000000000000L)
            {
                const long dotNetEpochAsTicks = 621355968000000000L;
                long nanosecondsSinceEpoch = ticks;
                long ticksSinceEpoch = nanosecondsSinceEpoch / 100;
                return ticksSinceEpoch + dotNetEpochAsTicks;
            }
            return ticks;
        }
    }
    #endregion

    #region 5. Helper Methods
    internal static class Crc32
    {
        private static readonly uint[] table = new uint[256];
        static Crc32()
        {
            const uint poly = 0xEDB88320;
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 0; j < 8; j++)
                    crc = (crc & 1) == 1 ? (crc >> 1) ^ poly : crc >> 1;
                table[i] = crc;
            }
        }
        public static uint Compute(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            foreach (byte b in data)
                crc = (crc >> 8) ^ table[(crc & 0xFF) ^ b];
            return ~crc;
        }
    }

    internal static partial class G3FCHelpers
    {
        public static byte[] StructToBytes<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        public static T BytesToStruct<T>(byte[] arr) where T : struct
        {
            T structure = new T();
            int size = Marshal.SizeOf(structure);
            if (arr.Length < size)
            {
                throw new ArgumentException($"Byte array is smaller than the struct size. Expected {size}, got {arr.Length}", nameof(arr));
            }
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(arr, 0, ptr, size);
            structure = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            return structure;
        }

        public static byte[] ReadBytes(Stream stream, long offset, int count)
        {
            stream.Seek(offset, SeekOrigin.Begin);
            byte[] buffer = new byte[count];
            int bytesRead = stream.Read(buffer, 0, count);
            if (bytesRead < count)
            {
                Array.Resize(ref buffer, bytesRead);
            }
            return buffer;
        }

        public static byte[] EncryptAESGCM(byte[] plaintext, byte[] key)
        {
            using var aes = new AesGcm(key);
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
            return nonce.Concat(tag).Concat(ciphertext).ToArray();
        }

        public static byte[] DecryptAESGCM(byte[] ciphertext, byte[] key)
        {
            try
            {
                using var aes = new AesGcm(key);
                int nonceSize = AesGcm.NonceByteSizes.MaxSize;
                int tagSize = AesGcm.TagByteSizes.MaxSize;
                var nonce = ciphertext.Take(nonceSize).ToArray();
                var tag = ciphertext.Skip(nonceSize).Take(tagSize).ToArray();
                var encryptedData = ciphertext.Skip(nonceSize + tagSize).ToArray();
                var plaintext = new byte[encryptedData.Length];
                aes.Decrypt(nonce, encryptedData, tag, plaintext);
                return plaintext;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                throw new Exception("The password provided is incorrect or the encrypted data is corrupt.");
            }
        }

        public static byte[] CreateFEC(byte[] data, byte fecLevel)
        {
            if (data.Length == 0) return new byte[0];
            int parityShardsCount = (fecLevel * (Constants.MaxFECLibShards - 1)) / 100;
            if (parityShardsCount < Constants.MinFECShards) parityShardsCount = Constants.MinFECShards;
            if (parityShardsCount > Constants.MaxFECShards) parityShardsCount = Constants.MaxFECShards;
            int dataShardsCount = Constants.MaxFECLibShards - parityShardsCount;
            if (dataShardsCount <= 0) dataShardsCount = 1;
            var codec = new ReedSolomon(dataShardsCount, parityShardsCount);
            int shardSize = (data.Length + dataShardsCount - 1) / dataShardsCount;
            int paddedLength = shardSize * dataShardsCount;
            var paddedData = new byte[paddedLength];
            data.CopyTo(paddedData, 0);
            var shards = new byte[dataShardsCount + parityShardsCount][];
            for (int i = 0; i < dataShardsCount + parityShardsCount; i++)
            {
                shards[i] = new byte[shardSize];
            }
            for (int i = 0; i < dataShardsCount; i++)
            {
                Array.Copy(paddedData, i * shardSize, shards[i], 0, shardSize);
            }
            codec.EncodeParity(shards, 0, shardSize);
            var parityBytes = new MemoryStream();
            for (int i = dataShardsCount; i < dataShardsCount + parityShardsCount; i++)
            {
                parityBytes.Write(shards[i], 0, shards[i].Length);
            }
            return parityBytes.ToArray();
        }

        public static byte[] SerializeIndex(List<FileEntry> fileIndex)
        {
            var writer = new CborWriter();
            writer.WriteStartArray(fileIndex.Count);
            foreach (var entry in fileIndex)
            {
                writer.WriteStartMap(null);
                writer.WriteTextString("path"); writer.WriteTextString(entry.Path);
                writer.WriteTextString("type"); writer.WriteTextString(entry.Type);
                writer.WriteTextString("uuid"); writer.WriteByteString(entry.UUID);
                writer.WriteTextString("creation_time"); writer.WriteInt64(entry.CreationTime);
                writer.WriteTextString("modification_time"); writer.WriteInt64(entry.ModificationTime);
                writer.WriteTextString("permissions"); writer.WriteUInt32(entry.Permissions);
                writer.WriteTextString("uncompressed_size"); writer.WriteUInt64(entry.UncompressedSize);
                writer.WriteTextString("checksum"); writer.WriteUInt32(entry.Checksum);
                writer.WriteTextString("original_filename"); writer.WriteTextString(entry.OriginalFilename);
                writer.WriteTextString("data_offset"); writer.WriteUInt64(entry.DataOffset);
                writer.WriteTextString("data_size"); writer.WriteUInt64(entry.DataSize);
                writer.WriteTextString("compression"); writer.WriteUInt32(entry.Compression);
                writer.WriteTextString("block_file_index"); writer.WriteUInt32(entry.BlockFileIndex);
                writer.WriteTextString("chunk_group_id"); writer.WriteByteString(entry.ChunkGroupId ?? new byte[0]);
                writer.WriteTextString("chunk_index"); writer.WriteUInt32(entry.ChunkIndex);
                writer.WriteTextString("total_chunks"); writer.WriteUInt32(entry.TotalChunks);
                writer.WriteEndMap();
            }
            writer.WriteEndArray();
            return writer.Encode();
        }

        public static List<FileEntry> DeserializeIndex(byte[] data)
        {
            var fileIndex = new List<FileEntry>();
            var reader = new CborReader(data);
            reader.ReadStartArray();
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                var entry = new FileEntry();
                reader.ReadStartMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    string key = reader.ReadTextString();
                    switch (key)
                    {
                        case "path": entry.Path = reader.ReadTextString(); break;
                        case "type": entry.Type = reader.ReadTextString(); break;
                        case "uuid": entry.UUID = reader.ReadByteString(); break;
                        case "creation_time": entry.CreationTime = reader.ReadInt64(); break;
                        case "modification_time": entry.ModificationTime = reader.ReadInt64(); break;
                        case "permissions": entry.Permissions = (ushort)reader.ReadUInt32(); break;
                        case "uncompressed_size": entry.UncompressedSize = reader.ReadUInt64(); break;
                        case "checksum": entry.Checksum = reader.ReadUInt32(); break;
                        case "original_filename": entry.OriginalFilename = reader.ReadTextString(); break;
                        case "data_offset": entry.DataOffset = reader.ReadUInt64(); break;
                        case "data_size": entry.DataSize = reader.ReadUInt64(); break;
                        case "compression": entry.Compression = (byte)reader.ReadUInt32(); break;
                        case "block_file_index": entry.BlockFileIndex = reader.ReadUInt32(); break;
                        case "chunk_group_id": entry.ChunkGroupId = reader.ReadByteString(); break;
                        case "chunk_index": entry.ChunkIndex = reader.ReadUInt32(); break;
                        case "total_chunks": entry.TotalChunks = reader.ReadUInt32(); break;
                        default: reader.SkipValue(); break;
                    }
                }
                reader.ReadEndMap();
                fileIndex.Add(entry);
            }
            reader.ReadEndArray();
            return fileIndex;
        }
    }

    internal static class PermissionsHelper
    {
#if NETCOREAPP
        [DllImport("libc", SetLastError = true)]
        private static extern int stat(string pathname, out Stat stat);

        [DllImport("libc", SetLastError = true)]
        private static extern int chmod(string pathname, uint mode);

        [StructLayout(LayoutKind.Sequential)]
        private struct Stat
        {
            public ulong st_dev;
            public ulong st_ino;
            public uint st_mode;
        }
#endif

        public static ushort GetPermissions(string path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var fileInfo = new FileInfo(path);
                // CORRECTION: Use explicit conversion from octal string to avoid ambiguity.
                // "666" (octal) is for read/write, "444" (octal) is for read-only.
                return fileInfo.IsReadOnly ? (ushort)Convert.ToInt32("444", 8) : (ushort)Convert.ToInt32("666", 8);
            }
#if NETCOREAPP
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (stat(path, out var statbuf) == 0)
                {
                    return (ushort)(statbuf.st_mode & 0x1FF);
                }
            }
#endif
            return 0644;
        }

        public static void SetPermissions(string path, ushort permissions)
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var fileInfo = new FileInfo(path);
                    bool isReadOnly = (permissions & Convert.ToInt32("222", 8)) == 0;
                    fileInfo.IsReadOnly = isReadOnly;
                }
#if NETCOREAPP
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    chmod(path, permissions);
                }
#endif
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not set permissions for {path}. {ex.Message}");
            }
        }

        public static string FormatPermissions(ushort perms)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var r = (perms & 0b100_000_000) != 0 ? 'r' : '-';
                var w = (perms & 0b010_000_000) != 0 ? 'w' : '-';
                var x = (perms & 0b001_000_000) != 0 ? 'x' : '-';
                var gr = (perms & 0b000_100_000) != 0 ? 'r' : '-';
                var gw = (perms & 0b000_010_000) != 0 ? 'w' : '-';
                var gx = (perms & 0b000_001_000) != 0 ? 'x' : '-';
                var or = (perms & 0b000_000_100) != 0 ? 'r' : '-';
                var ow = (perms & 0b000_000_010) != 0 ? 'w' : '-';
                var ox = (perms & 0b000_000_001) != 0 ? 'x' : '-';
                return $"rwx{r}{w}{x}{gr}{gw}{gx}{or}{ow}{ox}";
            }
            return $"0o{Convert.ToString(perms, 8)}";
        }
    }
    #endregion

    #region 6. Main Program (Console Application)
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
            {
                ShowHelp();
                return;
            }

            try
            {
                string command = args[0].ToLower();
                switch (command)
                {
                    case "create":
                    case "c":
                        HandleCreateCommand(args.Skip(1).ToArray());
                        break;
                    case "extract":
                    case "x":
                        HandleExtractCommand(args.Skip(1).ToArray());
                        break;
                    case "list":
                    case "l":
                        HandleListCommand(args.Skip(1).ToArray());
                        break;
                    case "info":
                    case "i":
                        HandleInfoCommand(args.Skip(1).ToArray());
                        break;
                    case "find":
                    case "f":
                        HandleFindCommand(args.Skip(1).ToArray());
                        break;
                    case "extract-single":
                    case "xs":
                        HandleExtractSingleCommand(args.Skip(1).ToArray());
                        break;
                    default:
                        Console.WriteLine($"Error: Unknown command '{command}'. Use --help for usage.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn unexpected error occurred: {ex.Message}");
#if DEBUG
                Console.WriteLine(ex.StackTrace);
#endif
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("G3FC Archiver Tool");
            Console.WriteLine("Usage: G3FC.exe <command> [options] [arguments...]");
            Console.WriteLine("\nCommands:");
            Console.WriteLine("  create, c         Create a new G3FC archive.");
            Console.WriteLine("  extract, x        Extract all files from a G3FC archive.");
            Console.WriteLine("  list, l           List files and directories in an archive.");
            Console.WriteLine("  find, f           Find a file within an archive by name or regex.");
            Console.WriteLine("  info, i           Export the archive's file metadata to a JSON file.");
            Console.WriteLine("  extract-single, xs Extract a single file or directory from an archive.");

            Console.WriteLine("\n--- Options for 'create' ---");
            Console.WriteLine("  Usage: create -o <path> [options] [input_paths...]");
            Console.WriteLine("  -o, --output <path>         Required. Path for the output .g3fc file.");
            Console.WriteLine("  -p, --password <password>   Optional. Encrypt the archive with a password.");
            Console.WriteLine("  -cl, --compression-level    Optional. ZSTD level (1-22). Default: 6.");
            Console.WriteLine("  -gc, --global-compression   Optional. Use global compression. Default: false.");
            Console.WriteLine("  -fl, --fec-level <%>        Optional. Forward Error Correction level (0-50).");
            Console.WriteLine("  --split <size>              Optional. Split data into blocks of specified size (e.g., 100MB, 2GB).");

            Console.WriteLine("\n--- Options for 'extract' ---");
            Console.WriteLine("  Usage: extract <archive_path> -o <dir_path> [options]");
            Console.WriteLine("  -o, --output <dir_path>     Optional. Destination directory. Prompts if not set.");
            Console.WriteLine("  -p, --password <password>   Optional. Password for encrypted archives.");

            Console.WriteLine("\n--- Options for 'list' ---");
            Console.WriteLine("  Usage: list <archive_path> [options]");
            Console.WriteLine("  -p, --password <password>   Optional. Password for encrypted archives.");
            Console.WriteLine("  --details                   Optional. Show detailed info (permissions, timestamp, checksum).");
            Console.WriteLine("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.");

            Console.WriteLine("\n--- Options for 'info' ---");
            Console.WriteLine("  Usage: info <archive_path> -o <json_path> [options]");
            Console.WriteLine("  -o, --output <json_path>    Required. Path to save the output JSON file.");
            Console.WriteLine("  -p, --password <password>   Optional. Password for encrypted archives.");

            Console.WriteLine("\n--- Options for 'find' ---");
            Console.WriteLine("  Usage: find <archive_path> <pattern> [options]");
            Console.WriteLine("  -p, --password <password>   Optional. Password for encrypted archives.");
            Console.WriteLine("  --regex                     Optional. Treat the pattern as a regular expression.");
            Console.WriteLine("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.");

            Console.WriteLine("\n--- Options for 'extract-single' ---");
            Console.WriteLine("  Usage: extract-single <archive_path> <file_in_archive> -o <dir_path> [options]");
            Console.WriteLine("  -o, --output <dir_path>     Required. Destination directory.");
            Console.WriteLine("  -p, --password <password>   Optional. Password for encrypted archives.");

            Console.WriteLine("\nExamples:");
            Console.WriteLine("  G3FC.exe create -o myarchive.g3fc -p mypass --split 500MB C:\\docs\\file.txt C:\\photos");
            Console.WriteLine("  G3FC.exe list myarchive.g3fc --details --unit MB");
            Console.WriteLine("  G3FC.exe find myarchive.g3fc \"\\.txt$\" --regex");
            Console.WriteLine("  G3FC.exe extract-single myarchive.g3fc \"documents/report.docx\" -o C:\\extracted_files");
        }

        static string GetPasswordFromUser()
        {
            Console.Write("Password required. Enter password: ");
            string password = "";
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password.Substring(0, password.Length - 1);
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password += key.KeyChar;
                }
            }
            Console.WriteLine();
            return password;
        }

        static void HandleCreateCommand(string[] args)
        {
            var config = new Config();
            string outputPath = null;
            var inputPaths = new List<string>();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-o": case "--output": outputPath = args[++i]; break;
                    case "-p": case "--password": config.ReadPassword = args[++i]; config.EncryptionMode = 1; break;
                    case "-cl": case "--compression-level": config.CompressionLevel = int.Parse(args[++i]); break;
                    case "-gc": case "--global-compression": config.GlobalCompression = true; break;
                    case "-fl": case "--fec-level": config.FECScheme = 1; config.FECLevel = byte.Parse(args[++i]); break;
                    case "--split": config.SplitSize = ParseSize(args[++i]); break;
                    default: inputPaths.Add(args[i]); break;
                }
            }

            if (string.IsNullOrEmpty(outputPath) || inputPaths.Count == 0)
            {
                Console.WriteLine("Error: Output path and at least one input path are required for 'create'.");
                return;
            }

            // CORRECTION: Ensure output directory exists before creating archive parts.
            string outputDirectory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            var filesToProcess = new List<Tuple<string, string>>();
            foreach (var path in inputPaths)
            {
                if (File.Exists(path))
                {
                    filesToProcess.Add(Tuple.Create(path, Path.GetFileName(path)));
                }
                else if (Directory.Exists(path))
                {
                    var baseDir = new DirectoryInfo(path);
                    foreach (var file in baseDir.GetFiles("*", SearchOption.AllDirectories))
                    {
                        string relativePath = file.FullName.Substring(baseDir.FullName.Length).TrimStart(Path.DirectorySeparatorChar);
                        filesToProcess.Add(Tuple.Create(file.FullName, relativePath));
                    }
                }
            }
            G3FCWriter.CreateG3FCArchive(outputPath, filesToProcess, config);
        }

        static void HandleExtractCommand(string[] args)
        {
            if (args.Length == 0) { Console.WriteLine("Error: Archive path is required."); return; }
            string archivePath = args[0];
            string outputPath = null;
            string password = "";

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "-o" || args[i] == "--output") outputPath = args[++i];
                if (args[i] == "-p" || args[i] == "--password") password = args[++i];
            }

            if (string.IsNullOrEmpty(outputPath)) { Console.Write("Enter destination directory: "); outputPath = Console.ReadLine(); }
            Directory.CreateDirectory(outputPath);

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read), 0, Constants.HeaderSize));
            if (header.EncryptionMode > 0 && string.IsNullOrEmpty(password))
            {
                password = GetPasswordFromUser();
            }

            var fileIndex = G3FCReader.ReadFileIndex(archivePath, password);
            var fileGroups = fileIndex.GroupBy(entry => new Guid((entry.ChunkGroupId != null && entry.ChunkGroupId.Length == 16) ? entry.ChunkGroupId : entry.UUID)).Select(group => group.OrderBy(entry => entry.ChunkIndex).ToList()).ToList();
            foreach (var chunkGroup in fileGroups)
            {
                G3FCReader.ExtractFileFromChunks(archivePath, chunkGroup, outputPath, password);
            }
            Console.WriteLine("\nExtraction complete.");
        }

        static void HandleListCommand(string[] args)
        {
            if (args.Length == 0) { Console.WriteLine("Error: Archive path is required for 'list'."); return; }
            string archivePath = args[0];
            string password = "";
            string unit = "KB";
            bool details = false;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "-p" || args[i] == "--password") password = args[++i];
                if (args[i] == "--unit") unit = args[++i];
                if (args[i] == "--details") details = true;
            }

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read), 0, Constants.HeaderSize));
            if (header.EncryptionMode > 0 && string.IsNullOrEmpty(password))
            {
                password = GetPasswordFromUser();
            }

            G3FCCommands.ListFilesInContainer(archivePath, password, unit, details);
        }

        static void HandleInfoCommand(string[] args)
        {
            if (args.Length < 2) { Console.WriteLine("Error: Archive path and output path are required for 'info'."); return; }
            string archivePath = args[0];
            string outputPath = null;
            string password = "";

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "-o" || args[i] == "--output") outputPath = args[++i];
                if (args[i] == "-p" || args[i] == "--password") password = args[++i];
            }

            if (string.IsNullOrEmpty(outputPath)) { Console.WriteLine("Error: Output path (-o) is required."); return; }

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read), 0, Constants.HeaderSize));
            if (header.EncryptionMode > 0 && string.IsNullOrEmpty(password))
            {
                password = GetPasswordFromUser();
            }

            G3FCCommands.ExportInfo(archivePath, password, outputPath);
        }

        static void HandleFindCommand(string[] args)
        {
            if (args.Length < 2) { Console.WriteLine("Error: Archive path and search pattern are required for 'find'."); return; }
            string archivePath = args[0];
            string pattern = args[1];
            string password = "";
            string unit = "KB";
            bool useRegex = false;

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "-p" || args[i] == "--password") password = args[++i];
                if (args[i] == "--unit") unit = args[++i];
                if (args[i] == "--regex") useRegex = true;
            }

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read), 0, Constants.HeaderSize));
            if (header.EncryptionMode > 0 && string.IsNullOrEmpty(password))
            {
                password = GetPasswordFromUser();
            }

            G3FCCommands.FindFilesInContainer(archivePath, password, pattern, useRegex, unit);
        }

        static void HandleExtractSingleCommand(string[] args)
        {
            if (args.Length < 3) { Console.WriteLine("Error: Archive path, file path in archive, and output directory are required."); return; }
            string archivePath = args[0];
            string fileInArchive = args[1];
            string outputPath = null;
            string password = "";

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "-o" || args[i] == "--output") outputPath = args[++i];
                if (args[i] == "-p" || args[i] == "--password") password = args[++i];
            }

            if (string.IsNullOrEmpty(outputPath)) { Console.WriteLine("Error: Output path (-o) is required."); return; }
            Directory.CreateDirectory(outputPath);

            var header = G3FCHelpers.BytesToStruct<MainHeader>(G3FCHelpers.ReadBytes(new FileStream(archivePath, FileMode.Open, FileAccess.Read), 0, Constants.HeaderSize));
            if (header.EncryptionMode > 0 && string.IsNullOrEmpty(password))
            {
                password = GetPasswordFromUser();
            }

            G3FCCommands.ExtractSingleFile(archivePath, password, fileInArchive, outputPath);
        }

        static long ParseSize(string sizeStr)
        {
            var match = Regex.Match(sizeStr.ToUpper(), @"^(\d+)(MB|GB)$");
            if (!match.Success)
            {
                throw new ArgumentException("Invalid size format. Use a number followed by MB or GB (e.g., 100MB).");
            }
            long size = long.Parse(match.Groups[1].Value);
            string unit = match.Groups[2].Value;
            return unit == "MB" ? size * 1024 * 1024 : size * 1024 * 1024 * 1024;
        }
    }
    #endregion
}
