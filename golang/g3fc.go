//
// G3FC Archiver Tool - Go Version
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
// While this Go implementation includes mitigations against the security vulnerabilities
// described below, any other implementation based on the G3FC specification MUST
// independently address these critical security concerns.
//
// For example and implementation purposes, the C# code shall always be considered
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

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/reedsolomon"
	"golang.org/x/crypto/pbkdf2"
)

// ===================================================================================
// 1. CONSTANTS AND DATA STRUCTURES
// ===================================================================================

const (
	MagicNumber      = "G3FC"
	FooterMagic      = "G3CE"
	HeaderSize       = 331
	FooterSize       = 40
	CreatingSystem   = "G3Pix GoLang G3FC Archiver"
	SoftwareVersion  = "1.1.3"
	MaxFECLibShards  = 255
	MinFECShards     = 1
	MaxFECShards     = 254
	AESNonceSize     = 12
	AESTagSize       = 16
	DotNetEpochTicks = 621355968000000000
)

type MainHeader struct {
	MagicNumber           [4]byte
	FormatVersionMajor    uint16
	FormatVersionMinor    uint16
	ContainerUUID         [16]byte
	CreationTimestamp     int64
	ModificationTimestamp int64
	EditVersion           uint32
	CreatingSystem        [32]byte
	SoftwareVersion       [32]byte
	FileIndexOffset       uint64
	FileIndexLength       uint64
	FileIndexCompression  byte
	GlobalCompression     byte
	EncryptionMode        byte
	ReadSalt              [64]byte
	WriteSalt             [64]byte
	KDFIterations         uint32
	FECScheme             byte
	FECLevel              byte
	FECDataOffset         uint64
	FECDataLength         uint64
	HeaderChecksum        uint32
	Reserved              [50]byte
}

type Footer struct {
	MainIndexOffset        uint64
	MainIndexLength        uint64
	MetadataFECBlockOffset uint64
	MetadataFECBlockLength uint64
	FooterChecksum         uint32
	FooterMagic            [4]byte
}

type FileEntry struct {
	Path             string `cbor:"path"`
	Type             string `cbor:"type"`
	UUID             []byte `cbor:"uuid"`
	CreationTime     int64  `cbor:"creation_time"`
	ModificationTime int64  `cbor:"modification_time"`
	Permissions      uint16 `cbor:"permissions"`
	Status           byte   `cbor:"status"`
	OriginalFilename string `cbor:"original_filename"`
	UncompressedSize uint64 `cbor:"uncompressed_size"`
	Checksum         uint32 `cbor:"checksum"`
	DataOffset       uint64 `cbor:"data_offset"`
	DataSize         uint64 `cbor:"data_size"`
	Compression      byte   `cbor:"compression"`
	BlockFileIndex   uint32 `cbor:"block_file_index"`
	ChunkGroupId     []byte `cbor:"chunk_group_id"`
	ChunkIndex       uint32 `cbor:"chunk_index"`
	TotalChunks      uint32 `cbor:"total_chunks"`
}

type FileEntryJsonExport struct {
	Path             string `json:"Path"`
	Type             string `json:"Type"`
	UUID             string `json:"UUID"`
	CreationTime     string `json:"CreationTime"`
	ModificationTime string `json:"ModificationTime"`
	Permissions      string `json:"Permissions"`
	Status           byte   `json:"Status"`
	OriginalFilename string `json:"OriginalFilename"`
	UncompressedSize uint64 `json:"UncompressedSize"`
	Checksum         uint32 `json:"Checksum"`
	BlockFileIndex   uint32 `json:"BlockFileIndex"`
	ChunkGroupId     string `json:"ChunkGroupId"`
	ChunkIndex       uint32 `json:"ChunkIndex"`
	TotalChunks      uint32 `json:"TotalChunks"`
}

type Config struct {
	CompressionLevel  int
	GlobalCompression bool
	EncryptionMode    byte
	ReadPassword      string
	KDFIterations     uint32
	FECScheme         byte
	FECLevel          byte
	SplitSize         int64
}

// ===================================================================================
// 2. HELPER METHODS (G3FCHelpers)
// ===================================================================================

var crc32Table = crc32.MakeTable(crc32.IEEE)

func Crc32Compute(data []byte) uint32 {
	return crc32.Checksum(data, crc32Table)
}

func DeriveKey(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, AESNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext := sealed[:len(plaintext)]
	tag := sealed[len(plaintext):]
	result := make([]byte, 0, AESNonceSize+AESTagSize+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, tag...)
	result = append(result, ciphertext...)
	return result, nil
}

func DecryptAESGCM(payload, key []byte) ([]byte, error) {
	if len(payload) < AESNonceSize+AESTagSize {
		return nil, errors.New("invalid encryption data: payload too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := payload[:AESNonceSize]
	tag := payload[AESNonceSize : AESNonceSize+AESTagSize]
	ciphertext := payload[AESNonceSize+AESTagSize:]
	ciphertextAndTag := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, errors.New("decryption failed: the password may be incorrect or the data corrupted")
	}
	return plaintext, nil
}

func CreateFEC(data []byte, fecLevel byte) ([]byte, error) {
	if len(data) == 0 || fecLevel == 0 {
		return []byte{}, nil
	}
	parityShardsCount := (int(fecLevel) * (MaxFECLibShards - 1)) / 100
	if parityShardsCount < MinFECShards {
		parityShardsCount = MinFECShards
	}
	if parityShardsCount > MaxFECShards {
		parityShardsCount = MaxFECShards
	}
	dataShardsCount := MaxFECLibShards - parityShardsCount
	if dataShardsCount <= 0 {
		dataShardsCount = 1
	}
	enc, err := reedsolomon.New(dataShardsCount, parityShardsCount)
	if err != nil {
		return nil, err
	}
	shards, err := enc.Split(data)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	var parityBytes bytes.Buffer
	for _, shard := range shards[dataShardsCount:] {
		parityBytes.Write(shard)
	}
	return parityBytes.Bytes(), nil
}

func SerializeIndex(fileIndex []FileEntry) ([]byte, error) { return cbor.Marshal(fileIndex) }
func DeserializeIndex(data []byte) ([]FileEntry, error) {
	var fileIndex []FileEntry
	err := cbor.Unmarshal(data, &fileIndex)
	return fileIndex, err
}

func TimeToNetTicks(t time.Time) int64 {
	return t.UnixNano()/100 + DotNetEpochTicks
}

func NetTicksToTime(ticks int64) time.Time {
	return time.Unix(0, (ticks-DotNetEpochTicks)*100)
}

func parseSize(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, nil
	}
	re := regexp.MustCompile(`^(\d+)(MB|GB)$`)
	matches := re.FindStringSubmatch(strings.ToUpper(sizeStr))
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid size format. Use a number followed by MB or GB (e.g., 100MB)")
	}
	size, _ := strconv.ParseInt(matches[1], 10, 64)
	unit := matches[2]
	if unit == "MB" {
		return size * 1024 * 1024, nil
	}
	if unit == "GB" {
		return size * 1024 * 1024 * 1024, nil
	}
	return 0, nil
}

// ===================================================================================
// 3. G3FC WRITER
// ===================================================================================

func CreateG3FCArchive(outputFilePath string, sourcePaths []string, config Config) error {
	var filesToProcess []struct{ FullPath, RelativePath string }
	for _, path := range sourcePaths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			fmt.Printf("Warning: Input path '%s' does not exist and will be skipped.\n", path)
			continue
		}
		if !info.IsDir() {
			filesToProcess = append(filesToProcess, struct{ FullPath, RelativePath string }{path, filepath.Base(path)})
		} else {
			baseDir := filepath.Dir(path)
			filepath.Walk(path, func(p string, i os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !i.IsDir() {
					relPath, _ := filepath.Rel(baseDir, p)
					filesToProcess = append(filesToProcess, struct{ FullPath, RelativePath string }{p, relPath})
				}
				return nil
			})
		}
	}
	if len(filesToProcess) == 0 {
		return errors.New("no valid files found in the input paths")
	}

	var fileIndex []FileEntry
	dataBlockStream := new(bytes.Buffer)
	zstdEncoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(config.CompressionLevel)))
	fmt.Println("Collecting files and preparing data...")
	for _, file := range filesToProcess {
		fmt.Printf("Adding: %s\n", file.RelativePath)
		fileData, err := os.ReadFile(file.FullPath)
		if err != nil {
			fmt.Printf("Warning: Failed to read file %s: %v\n", file.FullPath, err)
			continue
		}
		fileInfo, _ := os.Stat(file.FullPath)
		permissions := uint16(fileInfo.Mode().Perm() & 0777)
		modTimeTicks := TimeToNetTicks(fileInfo.ModTime())
		newUUID, _ := uuid.NewRandom()
		entry := FileEntry{
			Path:             filepath.ToSlash(file.RelativePath),
			Type:             "file",
			UUID:             newUUID[:],
			CreationTime:     modTimeTicks,
			ModificationTime: modTimeTicks,
			Permissions:      permissions,
			Status:           0,
			OriginalFilename: fileInfo.Name(),
			UncompressedSize: uint64(len(fileData)),
			Checksum:         Crc32Compute(fileData),
			ChunkGroupId:     make([]byte, 0),
		}
		var dataToAdd []byte
		if config.GlobalCompression {
			dataToAdd = fileData
			entry.Compression = 0
		} else {
			dataToAdd = zstdEncoder.EncodeAll(fileData, nil)
			entry.Compression = 1
		}
		entry.DataOffset = uint64(dataBlockStream.Len())
		entry.DataSize = uint64(len(dataToAdd))
		dataBlockStream.Write(dataToAdd)
		fileIndex = append(fileIndex, entry)
	}

	var readKey, readSalt, writeSalt []byte
	if config.EncryptionMode > 0 {
		readSalt = make([]byte, 64)
		rand.Read(readSalt)
		readKey = DeriveKey(config.ReadPassword, readSalt, int(config.KDFIterations))
		writeSalt = readSalt
	}

	if config.SplitSize > 0 {
		return writeSplitArchive(outputFilePath, fileIndex, dataBlockStream.Bytes(), config, readKey, readSalt, writeSalt)
	}
	return writeSingleArchive(outputFilePath, fileIndex, dataBlockStream.Bytes(), config, readKey, readSalt, writeSalt)
}

func createHeader(config Config, readSalt, writeSalt []byte) MainHeader {
	ticksNow := TimeToNetTicks(time.Now())
	containerUUID, _ := uuid.NewRandom()
	header := MainHeader{
		FormatVersionMajor:    1,
		FormatVersionMinor:    0,
		CreationTimestamp:     ticksNow,
		ModificationTimestamp: ticksNow,
		EditVersion:           1,
		FileIndexCompression:  1,
		GlobalCompression:     0,
		EncryptionMode:        config.EncryptionMode,
		KDFIterations:         config.KDFIterations,
		FECScheme:             config.FECScheme,
		FECLevel:              config.FECLevel,
	}
	copy(header.MagicNumber[:], []byte(MagicNumber))
	copy(header.ContainerUUID[:], containerUUID[:])
	copy(header.CreatingSystem[:], []byte(CreatingSystem))
	copy(header.SoftwareVersion[:], []byte(SoftwareVersion))
	if config.GlobalCompression {
		header.GlobalCompression = 1
	}
	if readSalt != nil {
		copy(header.ReadSalt[:], readSalt)
	}
	if writeSalt != nil {
		copy(header.WriteSalt[:], writeSalt)
	}
	return header
}

func writeSingleArchive(outputFilePath string, fileIndex []FileEntry, fileDataBlockBytes []byte, config Config, readKey, readSalt, writeSalt []byte) error {
	var err error
	if config.GlobalCompression {
		fmt.Println("\nApplying global compression...")
		zstdEncoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(config.CompressionLevel)))
		fileDataBlockBytes = zstdEncoder.EncodeAll(fileDataBlockBytes, nil)
	}
	if config.EncryptionMode > 0 {
		fileDataBlockBytes, err = EncryptAESGCM(fileDataBlockBytes, readKey)
		if err != nil {
			return err
		}
	}
	uncompressedIndexBytes, _ := SerializeIndex(fileIndex)
	zstdEncoder, _ := zstd.NewWriter(nil)
	compressedIndexBytes := zstdEncoder.EncodeAll(uncompressedIndexBytes, nil)
	indexBlockBytes := compressedIndexBytes
	if config.EncryptionMode > 0 {
		indexBlockBytes, err = EncryptAESGCM(indexBlockBytes, readKey)
		if err != nil {
			return err
		}
	}
	header := createHeader(config, readSalt, writeSalt)
	currentOffset := uint64(HeaderSize)
	header.FileIndexOffset = currentOffset
	header.FileIndexLength = uint64(len(indexBlockBytes))
	currentOffset += header.FileIndexLength
	currentOffset += uint64(len(fileDataBlockBytes))
	header.FECDataOffset = currentOffset
	var dataFECBytes []byte
	if config.FECScheme == 1 {
		dataFECBytes, err = CreateFEC(fileDataBlockBytes, config.FECLevel)
		if err != nil {
			return err
		}
	}
	header.FECDataLength = uint64(len(dataFECBytes))
	currentOffset += header.FECDataLength
	var metadataFECBytes []byte
	if config.FECScheme == 1 {
		var tempHeaderBuf bytes.Buffer
		binary.Write(&tempHeaderBuf, binary.LittleEndian, header)
		metadataToProtect := append(tempHeaderBuf.Bytes(), uncompressedIndexBytes...)
		metadataFECBytes, err = CreateFEC(metadataToProtect, 10)
		if err != nil {
			return err
		}
	}
	footer := Footer{
		MainIndexOffset:        header.FileIndexOffset,
		MainIndexLength:        header.FileIndexLength,
		MetadataFECBlockOffset: currentOffset,
		MetadataFECBlockLength: uint64(len(metadataFECBytes)),
	}
	copy(footer.FooterMagic[:], []byte(FooterMagic))
	var footerChecksumBuf bytes.Buffer
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MainIndexOffset)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MainIndexLength)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MetadataFECBlockOffset)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MetadataFECBlockLength)
	footer.FooterChecksum = Crc32Compute(footerChecksumBuf.Bytes())
	header.ModificationTimestamp = TimeToNetTicks(time.Now())
	var headerBuf bytes.Buffer
	binary.Write(&headerBuf, binary.LittleEndian, &header)
	headerBytes := headerBuf.Bytes()
	header.HeaderChecksum = Crc32Compute(headerBytes[:277])
	f, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := binary.Write(f, binary.LittleEndian, &header); err != nil {
		return err
	}
	if _, err := f.Write(indexBlockBytes); err != nil {
		return err
	}
	if _, err := f.Write(fileDataBlockBytes); err != nil {
		return err
	}
	if _, err := f.Write(dataFECBytes); err != nil {
		return err
	}
	if _, err := f.Write(metadataFECBytes); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, &footer); err != nil {
		return err
	}
	fmt.Printf("\nFile '%s' created successfully.\n", outputFilePath)
	return nil
}

func writeSplitArchive(outputFilePath string, originalFileIndex []FileEntry, combinedData []byte, config Config, readKey, readSalt, writeSalt []byte) error {
	fmt.Printf("\nSplitting data into blocks of max %d MB...\n", config.SplitSize/1024/1024)
	splitSize := config.SplitSize
	blockIndex := 0
	var finalFileIndex []FileEntry
	currentBlockStream := new(bytes.Buffer)
	for _, entry := range originalFileIndex {
		entryData := combinedData[entry.DataOffset : entry.DataOffset+entry.DataSize]
		chunkGroupId, _ := uuid.NewRandom()
		entryDataOffset := int64(0)
		chunkIndex := uint32(0)
		totalChunks := uint32((int64(len(entryData)) + splitSize - 1) / splitSize)
		if totalChunks == 0 && len(entryData) > 0 {
			totalChunks = 1
		}
		for entryDataOffset < int64(len(entryData)) || (len(entryData) == 0 && chunkIndex == 0) {
			spaceInCurrentBlock := splitSize - int64(currentBlockStream.Len())
			if spaceInCurrentBlock <= 0 && currentBlockStream.Len() > 0 {
				writeDataBlock(outputFilePath, blockIndex, currentBlockStream.Bytes(), config, readKey)
				blockIndex++
				currentBlockStream.Reset()
				spaceInCurrentBlock = splitSize
			}
			bytesToWrite := min(int64(len(entryData))-entryDataOffset, spaceInCurrentBlock)
			chunkEntry := entry
			chunkEntry.BlockFileIndex = uint32(blockIndex)
			chunkEntry.DataOffset = uint64(currentBlockStream.Len())
			chunkEntry.DataSize = uint64(bytesToWrite)
			chunkEntry.ChunkGroupId = chunkGroupId[:]
			chunkEntry.ChunkIndex = chunkIndex
			chunkEntry.TotalChunks = totalChunks
			finalFileIndex = append(finalFileIndex, chunkEntry)
			currentBlockStream.Write(entryData[entryDataOffset : entryDataOffset+bytesToWrite])
			entryDataOffset += bytesToWrite
			chunkIndex++
			if len(entryData) == 0 {
				break
			}
		}
	}
	if currentBlockStream.Len() > 0 {
		writeDataBlock(outputFilePath, blockIndex, currentBlockStream.Bytes(), config, readKey)
	}
	uncompressedIndexBytes, _ := SerializeIndex(finalFileIndex)
	zstdEncoder, _ := zstd.NewWriter(nil)
	compressedIndexBytes := zstdEncoder.EncodeAll(uncompressedIndexBytes, nil)
	indexBlockBytes := compressedIndexBytes
	var err error
	if config.EncryptionMode > 0 {
		indexBlockBytes, err = EncryptAESGCM(indexBlockBytes, readKey)
		if err != nil {
			return err
		}
	}
	header := createHeader(config, readSalt, writeSalt)
	header.FileIndexOffset = HeaderSize
	header.FileIndexLength = uint64(len(indexBlockBytes))
	header.FECDataOffset = 0
	header.FECDataLength = 0
	currentOffset := uint64(HeaderSize) + header.FileIndexLength
	var metadataFECBytes []byte
	if config.FECScheme == 1 {
		var tempHeaderBuf bytes.Buffer
		binary.Write(&tempHeaderBuf, binary.LittleEndian, header)
		metadataToProtect := append(tempHeaderBuf.Bytes(), uncompressedIndexBytes...)
		metadataFECBytes, err = CreateFEC(metadataToProtect, 10)
		if err != nil {
			return err
		}
	}
	footer := Footer{
		MainIndexOffset:        header.FileIndexOffset,
		MainIndexLength:        header.FileIndexLength,
		MetadataFECBlockOffset: currentOffset,
		MetadataFECBlockLength: uint64(len(metadataFECBytes)),
	}
	copy(footer.FooterMagic[:], []byte(FooterMagic))
	var footerChecksumBuf bytes.Buffer
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MainIndexOffset)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MainIndexLength)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MetadataFECBlockOffset)
	binary.Write(&footerChecksumBuf, binary.LittleEndian, footer.MetadataFECBlockLength)
	footer.FooterChecksum = Crc32Compute(footerChecksumBuf.Bytes())
	header.ModificationTimestamp = TimeToNetTicks(time.Now())
	var headerBuf bytes.Buffer
	binary.Write(&headerBuf, binary.LittleEndian, &header)
	headerBytes := headerBuf.Bytes()
	header.HeaderChecksum = Crc32Compute(headerBytes[:277])
	f, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	binary.Write(f, binary.LittleEndian, &header)
	f.Write(indexBlockBytes)
	f.Write(metadataFECBytes)
	binary.Write(f, binary.LittleEndian, &footer)
	fmt.Printf("\nIndex file '%s' and %d data block(s) created successfully.\n", outputFilePath, blockIndex+1)
	return nil
}

func writeDataBlock(baseFilePath string, blockIndex int, data []byte, config Config, readKey []byte) {
	blockPath := fmt.Sprintf("%s%d", baseFilePath, blockIndex)
	fmt.Printf("Writing block: %s (%d bytes)\n", filepath.Base(blockPath), len(data))
	var err error
	if config.GlobalCompression {
		zstdEncoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(config.CompressionLevel)))
		data = zstdEncoder.EncodeAll(data, nil)
	}
	if config.EncryptionMode > 0 {
		data, err = EncryptAESGCM(data, readKey)
		if err != nil {
			fmt.Printf("ERROR encrypting block %d: %v\n", blockIndex, err)
			return
		}
	}
	os.WriteFile(blockPath, data, 0644)
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// ===================================================================================
// 4. G3FC READER
// ===================================================================================

func ReadFileIndex(filePath, password string) ([]FileEntry, MainHeader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, MainHeader{}, err
	}
	defer f.Close()
	var header MainHeader
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, MainHeader{}, fmt.Errorf("failed to read header: %w", err)
	}
	if string(header.MagicNumber[:]) != MagicNumber {
		return nil, MainHeader{}, errors.New("invalid header magic number")
	}
	indexBlockBytes := make([]byte, header.FileIndexLength)
	_, err = f.ReadAt(indexBlockBytes, int64(header.FileIndexOffset))
	if err != nil {
		return nil, header, fmt.Errorf("failed to read index block: %w", err)
	}
	if header.EncryptionMode > 0 {
		if password == "" {
			return nil, header, errors.New("password required for this archive")
		}
		key := DeriveKey(password, header.ReadSalt[:], int(header.KDFIterations))
		indexBlockBytes, err = DecryptAESGCM(indexBlockBytes, key)
		if err != nil {
			return nil, header, fmt.Errorf("failed to decrypt index: %w", err)
		}
	}
	if header.FileIndexCompression == 1 {
		zstdDecoder, _ := zstd.NewReader(nil)
		indexBlockBytes, err = zstdDecoder.DecodeAll(indexBlockBytes, nil)
		if err != nil {
			return nil, header, fmt.Errorf("failed to decompress index: %w", err)
		}
	}
	fileIndex, err := DeserializeIndex(indexBlockBytes)
	if err != nil {
		return nil, header, fmt.Errorf("failed to deserialize index: %w", err)
	}
	return fileIndex, header, nil
}

func ExtractArchive(archivePath, destDir, password string) error {
	fmt.Println("Reading archive index...")
	fileIndex, header, err := ReadFileIndex(archivePath, password)
	if err != nil {
		return err
	}
	fmt.Printf("Found %d file entries. Grouping and starting extraction...\n", len(fileIndex))
	fileGroups := make(map[string][]FileEntry)
	for _, entry := range fileIndex {
		var groupID string
		if len(entry.ChunkGroupId) == 16 {
			groupID = string(entry.ChunkGroupId)
		} else {
			groupID = string(entry.UUID)
		}
		if _, ok := fileGroups[groupID]; !ok {
			fileGroups[groupID] = make([]FileEntry, 0)
		}
		fileGroups[groupID] = append(fileGroups[groupID], entry)
	}
	for _, chunks := range fileGroups {
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].ChunkIndex < chunks[j].ChunkIndex })
		err := extractFileFromChunks(archivePath, destDir, chunks, header, password)
		if err != nil {
			fmt.Printf("ERROR extracting %s: %v\n", chunks[0].Path, err)
		}
	}
	fmt.Println("\nExtraction complete.")
	return nil
}

func extractFileFromChunks(archivePath, destDir string, chunks []FileEntry, header MainHeader, password string) error {
	if len(chunks) == 0 {
		return nil
	}
	firstChunk := chunks[0]
	fmt.Printf("Extracting: %s (%d chunk(s))\n", firstChunk.Path, len(chunks))
	var readKey []byte
	if header.EncryptionMode > 0 {
		readKey = DeriveKey(password, header.ReadSalt[:], int(header.KDFIterations))
	}
	reassembledStream := new(bytes.Buffer)
	isSplit := header.FECDataOffset == 0 && header.FECDataLength == 0
	dataBlocksCache := make(map[uint32][]byte)
	zstdDecoder, _ := zstd.NewReader(nil)
	for _, chunk := range chunks {
		dataBlock, cached := dataBlocksCache[chunk.BlockFileIndex]
		if !cached {
			var rawDataBlock []byte
			var err error
			if isSplit {
				blockPath := fmt.Sprintf("%s%d", archivePath, chunk.BlockFileIndex)
				rawDataBlock, err = os.ReadFile(blockPath)
				if err != nil {
					return fmt.Errorf("data block not found: %s", blockPath)
				}
			} else {
				f, err := os.Open(archivePath)
				if err != nil {
					return err
				}
				dataBlockStart := int64(header.FileIndexOffset + header.FileIndexLength)
				dataBlockLength := int64(header.FECDataOffset) - dataBlockStart
				rawDataBlock = make([]byte, dataBlockLength)
				_, err = f.ReadAt(rawDataBlock, dataBlockStart)
				f.Close()
				if err != nil {
					return err
				}
			}
			if header.EncryptionMode > 0 {
				rawDataBlock, err = DecryptAESGCM(rawDataBlock, readKey)
				if err != nil {
					return err
				}
			}
			if header.GlobalCompression == 1 {
				rawDataBlock, err = zstdDecoder.DecodeAll(rawDataBlock, nil)
				if err != nil {
					return err
				}
			}
			dataBlock = rawDataBlock
			dataBlocksCache[chunk.BlockFileIndex] = dataBlock
		}
		chunkData := dataBlock[chunk.DataOffset : chunk.DataOffset+chunk.DataSize]
		reassembledStream.Write(chunkData)
	}
	finalData := reassembledStream.Bytes()
	var err error
	uncompressedSize := firstChunk.UncompressedSize
	const maxSafeSize = 4 * 1024 * 1024 * 1024
	if uncompressedSize > maxSafeSize {
		fmt.Printf("\nWARNING: The file '%s' has a very large uncompressed size (%d MB).\n", firstChunk.Path, uncompressedSize/1024/1024)
		fmt.Print("Extracting it may consume a large amount of memory and could cause system instability. Do you want to continue? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Extraction cancelled by the user.")
			return nil
		}
	}
	if header.GlobalCompression == 0 && firstChunk.Compression == 1 {
		finalData, err = zstdDecoder.DecodeAll(finalData, make([]byte, 0, uncompressedSize))
		if err != nil {
			return err
		}
	}
	if Crc32Compute(finalData) != firstChunk.Checksum {
		return fmt.Errorf("checksum mismatch for file %s", firstChunk.OriginalFilename)
	}
	destDirAbs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("could not determine absolute destination path: %w", err)
	}
	destPath := filepath.Join(destDirAbs, firstChunk.Path)
	if !strings.HasPrefix(destPath, destDirAbs+string(os.PathSeparator)) && destPath != destDirAbs {
		return fmt.Errorf("path traversal attempt detected: '%s' tries to escape the destination directory", firstChunk.Path)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	perm := os.FileMode(firstChunk.Permissions)
	if perm == 0 {
		perm = 0644
	}
	if err := os.WriteFile(destPath, finalData, perm); err != nil {
		return err
	}
	return nil
}

// ===================================================================================
// 5. NEW COMMANDS LOGIC
// ===================================================================================

func ListFilesInContainer(archivePath, password, sizeUnit string, showDetails bool) error {
	fmt.Printf("Listing contents of: %s\n\n", archivePath)
	fileIndex, _, err := ReadFileIndex(archivePath, password)
	if err != nil {
		return fmt.Errorf("error listing files: %w", err)
	}
	logicalFiles := make(map[string]FileEntry)
	for _, entry := range fileIndex {
		if _, exists := logicalFiles[entry.Path]; !exists {
			logicalFiles[entry.Path] = entry
		}
	}
	var paths []string
	for path := range logicalFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	header := fmt.Sprintf("%-60s %-15s %-12s", "Path", "Size", "Type")
	if showDetails {
		header += fmt.Sprintf(" %-12s %-22s %s", "Permissions", "Creation Time", "Checksum")
	}
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", 120))
	for _, path := range paths {
		entry := logicalFiles[path]
		formattedSize := formatSize(entry.UncompressedSize, sizeUnit)
		line := fmt.Sprintf("%-60s %-15s %-12s", entry.Path, formattedSize, entry.Type)
		if showDetails {
			creationTime := NetTicksToTime(entry.CreationTime).Local()
			permissions := fmt.Sprintf("0o%o", entry.Permissions)
			checksum := fmt.Sprintf("%08X", entry.Checksum)
			line += fmt.Sprintf(" %-12s %-22s %s", permissions, creationTime.Format("2006-01-02 15:04:05"), checksum)
		}
		fmt.Println(line)
	}
	return nil
}

func ExportInfo(archivePath, password, outputJsonPath string) error {
	fileIndex, _, err := ReadFileIndex(archivePath, password)
	if err != nil {
		return fmt.Errorf("error exporting info: %w", err)
	}
	jsonEntries := make([]FileEntryJsonExport, len(fileIndex))
	for i, entry := range fileIndex {
		chunkGroupIdStr := "N/A"
		if len(entry.ChunkGroupId) == 16 {
			if parsedUUID, err := uuid.FromBytes(entry.ChunkGroupId); err == nil {
				chunkGroupIdStr = parsedUUID.String()
			}
		}
		parsedUUID, _ := uuid.FromBytes(entry.UUID)
		jsonEntries[i] = FileEntryJsonExport{
			Path:             entry.Path,
			Type:             entry.Type,
			UUID:             parsedUUID.String(),
			CreationTime:     NetTicksToTime(entry.CreationTime).Format(time.RFC3339),
			ModificationTime: NetTicksToTime(entry.ModificationTime).Format(time.RFC3339),
			Permissions:      fmt.Sprintf("0o%o", entry.Permissions),
			Status:           entry.Status,
			OriginalFilename: entry.OriginalFilename,
			UncompressedSize: entry.UncompressedSize,
			Checksum:         entry.Checksum,
			BlockFileIndex:   entry.BlockFileIndex,
			ChunkGroupId:     chunkGroupIdStr,
			ChunkIndex:       entry.ChunkIndex,
			TotalChunks:      entry.TotalChunks,
		}
	}
	jsonData, err := json.MarshalIndent(jsonEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index to JSON: %w", err)
	}
	err = os.WriteFile(outputJsonPath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}
	fmt.Printf("File index successfully exported to %s\n", outputJsonPath)
	return nil
}

func FindFilesInContainer(archivePath, password, pattern string, useRegex bool, sizeUnit string) error {
	fileIndex, _, err := ReadFileIndex(archivePath, password)
	if err != nil {
		return fmt.Errorf("error finding files: %w", err)
	}
	logicalFiles := make(map[string]FileEntry)
	for _, entry := range fileIndex {
		if _, exists := logicalFiles[entry.Path]; !exists {
			logicalFiles[entry.Path] = entry
		}
	}
	var foundFiles []FileEntry
	if useRegex {
		regex, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		for _, entry := range logicalFiles {
			if regex.MatchString(entry.Path) {
				foundFiles = append(foundFiles, entry)
			}
		}
	} else {
		for _, entry := range logicalFiles {
			if strings.Contains(strings.ToLower(entry.Path), strings.ToLower(pattern)) {
				foundFiles = append(foundFiles, entry)
			}
		}
	}
	fmt.Printf("\nFound %d matching entries for pattern '%s':\n", len(foundFiles), pattern)
	fmt.Printf("%-60s %-15s %-22s\n", "Path", "Size", "Creation Time")
	fmt.Println(strings.Repeat("-", 100))
	for _, entry := range foundFiles {
		formattedSize := formatSize(entry.UncompressedSize, sizeUnit)
		creationTime := NetTicksToTime(entry.CreationTime).Local()
		fmt.Printf("%-60s %-15s %-22s\n", entry.Path, formattedSize, creationTime.Format("2006-01-02 15:04:05"))
	}
	return nil
}

func ExtractSingleFile(archivePath, password, filePathInArchive, destinationDir string) error {
	fmt.Printf("Attempting to extract '%s' to '%s'...\n", filePathInArchive, destinationDir)
	fileIndex, header, err := ReadFileIndex(archivePath, password)
	if err != nil {
		return fmt.Errorf("error extracting single file: %w", err)
	}
	var chunksToExtract []FileEntry
	for _, entry := range fileIndex {
		if entry.Path == filePathInArchive {
			chunksToExtract = append(chunksToExtract, entry)
		}
	}
	if len(chunksToExtract) == 0 {
		return fmt.Errorf("file '%s' not found in the archive", filePathInArchive)
	}
	if chunksToExtract[0].Type == "directory" {
		destPath := filepath.Join(destinationDir, chunksToExtract[0].Path)
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", destPath, err)
		}
		fmt.Printf("Successfully created directory: %s\n", destPath)
		return nil
	}
	err = extractFileFromChunks(archivePath, destinationDir, chunksToExtract, header, password)
	if err != nil {
		return err
	}
	fmt.Printf("\nSuccessfully extracted '%s'.\n", filePathInArchive)
	return nil
}

func formatSize(bytes uint64, unit string) string {
	size := float64(bytes)
	switch strings.ToUpper(unit) {
	case "TB":
		return fmt.Sprintf("%.2f TB", size/(1024*1024*1024*1024))
	case "GB":
		return fmt.Sprintf("%.2f GB", size/(1024*1024*1024))
	case "MB":
		return fmt.Sprintf("%.2f MB", size/(1024*1024))
	case "KB":
		return fmt.Sprintf("%.2f KB", size/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// ===================================================================================
// 6. MAIN PROGRAM (CLI)
// ===================================================================================

func showHelp() {
	fmt.Printf("G3FC Archiver Tool - Go Version %s\n", SoftwareVersion)
	fmt.Printf("Usage: %s <command> [options] [arguments...]\n", filepath.Base(os.Args[0]))
	fmt.Println("\nCommands:")
	fmt.Println("  create, c         Create a new G3FC archive.")
	fmt.Println("  extract, x        Extract all files from a G3FC archive.")
	fmt.Println("  list, l           List files and directories in an archive.")
	fmt.Println("  find, f           Find a file within an archive by name or regex.")
	fmt.Println("  info, i           Export the archive's file metadata to a JSON file.")
	fmt.Println("  extract-single, xs Extract a single file or directory from an archive.")

	fmt.Println("\n--- Options for 'create' ---")
	fmt.Println("  Usage: create [options] <input_paths...>")
	fmt.Println("  -o, --output <path>         Required. Path for the output .g3fc file.")
	fmt.Println("  -p, --password <password>   Optional. Encrypt the archive with a password.")
	fmt.Println("  -cl, --compression-level    Optional. ZSTD level (1-22). Default: 6.")
	fmt.Println("  -gc, --global-compression   Optional. Use global compression. Default: false.")
	fmt.Println("  -fl, --fec-level <%>        Optional. Forward Error Correction level (0-50).")
	fmt.Println("  --split <size>              Optional. Split data into blocks of specified size (e.g., 100MB, 2GB).")

	fmt.Println("\n--- Options for 'extract' ---")
	fmt.Println("  Usage: extract [options] <archive_path>")
	fmt.Println("  -o, --output <dir_path>     Required. Destination directory for extracted files.")
	fmt.Println("  -p, --password <password>   Optional. Password for encrypted archives.")

	fmt.Println("\n--- Options for 'list' ---")
	fmt.Println("  Usage: list [options] <archive_path>")
	fmt.Println("  -p, --password <password>   Optional. Password for encrypted archives.")
	fmt.Println("  --details                   Optional. Show detailed info (permissions, timestamp, checksum).")
	fmt.Println("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.")

	fmt.Println("\n--- Options for 'info' ---")
	fmt.Println("  Usage: info [options] <archive_path>")
	fmt.Println("  -o, --output <json_path>    Required. Path to save the output JSON file.")
	fmt.Println("  -p, --password <password>   Optional. Password for encrypted archives.")

	fmt.Println("\n--- Options for 'find' ---")
	fmt.Println("  Usage: find [options] <archive_path> <pattern>")
	fmt.Println("  -p, --password <password>   Optional. Password for encrypted archives.")
	fmt.Println("  --regex                     Optional. Treat the pattern as a regular expression.")
	fmt.Println("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.")

	fmt.Println("\n--- Options for 'extract-single' ---")
	fmt.Println("  Usage: extract-single [options] <archive_path> <file_in_archive>")
	fmt.Println("  -o, --output <dir_path>     Required. Destination directory.")
	fmt.Println("  -p, --password <password>   Optional. Password for encrypted archives.")

	fmt.Println("\nExamples:")
	fmt.Printf("  %s create -o my_archive.g3fc -p mypassword C:\\Users\\user\\Documents\n", filepath.Base(os.Args[0]))
	fmt.Printf("  %s list -p mypassword my_archive.g3fc --details\n", filepath.Base(os.Args[0]))
	fmt.Printf("  %s find -p mypassword my_archive.g3fc \"\\.txt$\" --regex\n", filepath.Base(os.Args[0]))
	fmt.Printf("  %s extract-single -o C:\\extracted -p mypassword my_archive.g3fc \"docs/report.docx\"\n", filepath.Base(os.Args[0]))
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		showHelp()
		return
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "create", "c":
		cmd := flag.NewFlagSet("create", flag.ExitOnError)
		output := cmd.String("o", "", "Required. Path for the output .g3fc file.")
		password := cmd.String("p", "", "Optional. Encrypt the archive with a password.")
		compLevel := cmd.Int("cl", 6, "Optional. ZSTD compression level (1-22).")
		globalComp := cmd.Bool("gc", false, "Optional. Use global compression.")
		fecLevel := cmd.Int("fl", 0, "Optional. Forward Error Correction level (0-50).")
		splitSizeStr := cmd.String("split", "", "Optional. Split data into blocks of specified size (e.g., 100MB, 2GB).")
		cmd.Parse(args)

		if *output == "" || cmd.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: Output path and at least one input path are required for 'create'.")
			return
		}
		if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			return
		}

		splitSize, err := parseSize(*splitSizeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		config := Config{
			CompressionLevel: *compLevel, GlobalCompression: *globalComp, ReadPassword: *password,
			KDFIterations: 100000, FECLevel: byte(*fecLevel), SplitSize: splitSize,
		}
		if config.ReadPassword != "" {
			config.EncryptionMode = 1
		}
		if config.FECLevel > 0 {
			config.FECScheme = 1
		}

		err = CreateG3FCArchive(*output, cmd.Args(), config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	case "extract", "x":
		cmd := flag.NewFlagSet("extract", flag.ExitOnError)
		output := cmd.String("o", "", "Required. Destination directory.")
		password := cmd.String("p", "", "Optional. Password for encrypted archives.")
		cmd.Parse(args)
		if *output == "" || cmd.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: Archive path and output directory are required.")
			return
		}
		if err := os.MkdirAll(*output, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			return
		}
		err := ExtractArchive(cmd.Arg(0), *output, *password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	case "list", "l":
		cmd := flag.NewFlagSet("list", flag.ExitOnError)
		password := cmd.String("p", "", "Optional. Password.")
		details := cmd.Bool("details", false, "Optional. Show detailed info.")
		unit := cmd.String("unit", "KB", "Optional. Unit for file sizes (B, KB, MB, GB, TB).")
		cmd.Parse(args)
		if cmd.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: Archive path is required.")
			return
		}
		err := ListFilesInContainer(cmd.Arg(0), *password, *unit, *details)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	case "info", "i":
		cmd := flag.NewFlagSet("info", flag.ExitOnError)
		output := cmd.String("o", "", "Required. Path to save the output JSON file.")
		password := cmd.String("p", "", "Optional. Password.")
		cmd.Parse(args)
		if *output == "" || cmd.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: Archive path and output path are required.")
			return
		}
		if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			return
		}
		err := ExportInfo(cmd.Arg(0), *password, *output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	case "find", "f":
		cmd := flag.NewFlagSet("find", flag.ExitOnError)
		password := cmd.String("p", "", "Optional. Password.")
		useRegex := cmd.Bool("regex", false, "Optional. Treat pattern as regex.")
		unit := cmd.String("unit", "KB", "Optional. Unit for file sizes.")
		cmd.Parse(args)
		if cmd.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Error: Archive path and search pattern are required.")
			return
		}
		err := FindFilesInContainer(cmd.Arg(0), *password, cmd.Arg(1), *useRegex, *unit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	case "extract-single", "xs":
		cmd := flag.NewFlagSet("extract-single", flag.ExitOnError)
		output := cmd.String("o", "", "Required. Destination directory.")
		password := cmd.String("p", "", "Optional. Password.")
		cmd.Parse(args)
		if *output == "" || cmd.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Error: Archive path, file path, and output directory are required.")
			return
		}
		if err := os.MkdirAll(*output, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			return
		}
		err := ExtractSingleFile(cmd.Arg(0), *password, cmd.Arg(1), *output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nAn unexpected error occurred: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'.\n\n", command)
		showHelp()
	}
}
