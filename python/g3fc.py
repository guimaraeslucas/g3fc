#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# G3FC Archiver Tool - Python Version
#
# @author  Lucas Guimarães - G3Pix <https:#github.com/guimaraeslucas/>
# @license GNU General Public License v2.0
# @version 1.0.2
#
# Copyright 2025, Lucas Guimarães - G3Pix Ltda <https:#g3pix.com.br>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# SECURITY WARNING: This is a basic reader/writer implementation.
# It is the developer's responsibility to implement security checks.
#
# 1. Path Traversal: A maliciously crafted archive could contain paths intended
#    to overwrite sensitive system files (e.g., a path traversal attack using ../../..).
#    Implementations MUST rigorously validate and sanitize all path information from the
#    file index before writing any data to the local filesystem. File paths MUST be
#    treated as relative to the designated extraction directory, and any attempts to
#    write outside of this directory must be prevented.
#
# 2. Decompression Bomb: Implementations that parse this format SHOULD mitigate
#    the risk of decompression bombs by first checking the `uncompressed_size` field
#    in the file's metadata index and enforcing reasonable limits on resource
#    allocation before attempting decompression.

import os
import sys
import struct
import zlib
import uuid
import time
import argparse
import re
from datetime import datetime

# Import installed dependencies
import zstandard as zstd
import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from reedsolo import RSCodec

# ===================================================================================
# 1. DATA STRUCTURES AND CONSTANTS
# ===================================================================================

class Constants:
    MAGIC_NUMBER = b"G3FC"
    FOOTER_MAGIC = b"G3CE"
    HEADER_SIZE = 331
    FOOTER_SIZE = 40
    CREATING_SYSTEM = "G3Pix Py Lib"
    SOFTWARE_VERSION = "1.0.2" # Version updated
    MAX_FEC_LIB_SHARDS = 255
    MIN_FEC_SHARDS = 1
    MAX_FEC_SHARDS = 254
    
    # Struct format for the header, compatible with C# [StructLayout(LayoutKind.Sequential, Pack = 1)]
    # '<' means little-endian, which is the standard for interoperability with C# on Windows/Linux.
    HEADER_FORMAT = (
        "<"
        "4s"      # MagicNumber
        "H"       # FormatVersionMajor
        "H"       # FormatVersionMinor
        "16s"     # ContainerUUID
        "q"       # CreationTimestamp
        "q"       # ModificationTimestamp
        "I"       # EditVersion
        "32s"     # CreatingSystem
        "32s"     # SoftwareVersion
        "Q"       # FileIndexOffset
        "Q"       # FileIndexLength
        "B"       # FileIndexCompression
        "B"       # GlobalCompression
        "B"       # EncryptionMode
        "64s"     # ReadSalt
        "64s"     # WriteSalt
        "I"       # KDFIterations
        "B"       # FECScheme
        "B"       # FECLevel
        "Q"       # FECDataOffset
        "Q"       # FECDataLength
        "I"       # HeaderChecksum
        "50s"     # Reserved
    )

    # Struct format for the footer
    FOOTER_FORMAT = (
        "<"
        "Q"      # MainIndexOffset
        "Q"      # MainIndexLength
        "Q"      # MetadataFECBlockOffset
        "Q"      # MetadataFECBlockLength
        "I"      # FooterChecksum
        "4s"     # FooterMagic
    )

# ===================================================================================
# 2. HELPER METHODS (G3FCHelpers)
# ===================================================================================

def get_header_keys():
    """Returns a list of header key names in the correct order for struct.pack."""
    return [
        'MagicNumber', 'FormatVersionMajor', 'FormatVersionMinor', 'ContainerUUID', 
        'CreationTimestamp', 'ModificationTimestamp', 'EditVersion', 'CreatingSystem',
        'SoftwareVersion', 'FileIndexOffset', 'FileIndexLength', 'FileIndexCompression',
        'GlobalCompression', 'EncryptionMode', 'ReadSalt', 'WriteSalt', 'KDFIterations',
        'FECScheme', 'FECLevel', 'FECDataOffset', 'FECDataLength', 'HeaderChecksum', 'Reserved'
    ]

def crc32_compute(data: bytes) -> int:
    """Computes the CRC32 checksum, compatible with the C# implementation."""
    return zlib.crc32(data) & 0xFFFFFFFF # Ensures it's an unsigned integer

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derives a 32-byte key from the password using PBKDF2-SHA256."""
    if not password:
        raise ValueError("Password cannot be empty for key derivation.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes = 256 bits
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-256-GCM with a .NET-compatible payload layout.
    Layout: Nonce (12 bytes) + Tag (16 bytes) + Ciphertext
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # The 'cryptography' library returns ciphertext + tag
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    
    # Separate the tag (last 16 bytes) from the ciphertext
    tag = ciphertext_and_tag[-16:]
    ciphertext = ciphertext_and_tag[:-16]
    
    # Reassemble in the C#-compatible order: Nonce + Tag + Ciphertext
    return nonce + tag + ciphertext

def decrypt_aes_gcm(payload: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-256-GCM data from a .NET-formatted payload.
    Layout: Nonce (12 bytes) + Tag (16 bytes) + Ciphertext
    """
    aesgcm = AESGCM(key)
    
    # Disassemble the payload in C# order
    nonce = payload[:12]
    tag = payload[12:28] # 12 + 16 = 28
    ciphertext = payload[28:]
    
    # The 'cryptography' library expects the format: ciphertext + tag
    ciphertext_and_tag = ciphertext + tag
    
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag:
        raise ValueError("Decryption failed: the password may be incorrect or the data corrupted (invalid authentication tag).")

def create_fec(data: bytes, fec_level: int) -> bytes:
    """Creates Forward Error Correction (FEC) data using Reed-Solomon."""
    if not data or fec_level == 0:
        return b''

    parity_shards_count = (fec_level * (Constants.MAX_FEC_LIB_SHARDS - 1)) // 100
    if parity_shards_count < Constants.MIN_FEC_SHARDS:
        parity_shards_count = Constants.MIN_FEC_SHARDS
    if parity_shards_count > Constants.MAX_FEC_SHARDS:
        parity_shards_count = Constants.MAX_FEC_SHARDS
    
    data_shards_count = Constants.MAX_FEC_LIB_SHARDS - parity_shards_count
    if data_shards_count <= 0:
        data_shards_count = 1

    shard_size = (len(data) + data_shards_count - 1) // data_shards_count
    padded_length = shard_size * data_shards_count
    padded_data = data.ljust(padded_length, b'\0')

    rs = RSCodec(parity_shards_count)
    encoded_data = rs.encode(padded_data)
    parity_bytes_as_array = encoded_data[len(padded_data):]
    
    return bytes(parity_bytes_as_array)

def serialize_index(file_index: list) -> bytes:
    """Serializes the file index to CBOR."""
    return cbor2.dumps(file_index)

def deserialize_index(data: bytes) -> list:
    """Deserializes the file index from CBOR."""
    return cbor2.loads(data)

def parse_split_size(size_str: str) -> int:
    """Converts strings like '100MB' or '2GB' to bytes."""
    if not size_str:
        return 0
    match = re.match(r'^(\d+)(MB|GB)$', size_str.upper())
    if not match:
        raise ValueError("Invalid size format. Use a number followed by MB or GB (e.g., 100MB).")
    size = int(match.group(1))
    unit = match.group(2)
    if unit == "MB":
        return size * 1024 * 1024
    elif unit == "GB":
        return size * 1024 * 1024 * 1024
    return 0

def get_permissions(path: str) -> int:
    """Gets file permissions compatibly."""
    try:
        return os.stat(path).st_mode & 0o777
    except:
        return 0o644 # Default fallback

def set_permissions(path: str, permissions: int):
    """Sets file permissions."""
    try:
        os.chmod(path, permissions)
    except Exception as e:
        print(f"Warning: Could not set permissions for {path}. {e}")

# ===================================================================================
# 3. G3FC WRITER
# ===================================================================================

class G3FCWriter:
    def __init__(self, config):
        self.config = config

    def create_g3fc_archive(self, output_path: str, source_files: list):
        file_index = []
        data_block_stream = bytearray()
        
        print("Collecting files and preparing data...")
        for full_path, relative_path in source_files:
            if not os.path.exists(full_path):
                print(f"Warning: Skipping non-existent file {full_path}")
                continue

            print(f"Adding: {relative_path}")
            
            file_info = os.stat(full_path)
            with open(full_path, 'rb') as f:
                file_data = f.read()

            entry = {
                'path': relative_path.replace('\\', '/'),
                'type': "file",
                'uuid': uuid.uuid4().bytes,
                'creation_time': int(file_info.st_ctime * 1_000_000_000),
                'modification_time': int(file_info.st_mtime * 1_000_000_000),
                'permissions': get_permissions(full_path),
                'status': 0,
                'original_filename': os.path.basename(full_path),
                'uncompressed_size': len(file_data),
                'checksum': crc32_compute(file_data)
            }
            
            data_to_add = file_data
            if self.config.get('global_compression'):
                entry['compression'] = 0
            else:
                cctx = zstd.ZstdCompressor(level=self.config.get('compression_level', 3))
                data_to_add = cctx.compress(file_data)
                entry['compression'] = 1

            entry['data_offset'] = len(data_block_stream)
            entry['data_size'] = len(data_to_add)
            data_block_stream.extend(data_to_add)
            file_index.append(entry)

        read_key, read_salt, write_salt = None, None, None
        if self.config.get('encryption_mode', 0) > 0:
            read_salt = os.urandom(64)
            read_key = derive_key(self.config['read_password'], read_salt, self.config['kdf_iterations'])
            write_salt = os.urandom(64) if self.config['encryption_mode'] == 2 else read_salt

        if self.config.get('split_size', 0) > 0:
            self._write_split_archive(output_path, file_index, data_block_stream, read_key, read_salt, write_salt)
        else:
            self._write_single_archive(output_path, file_index, data_block_stream, read_key, read_salt, write_salt)

    def _create_header(self, read_salt, write_salt) -> dict:
        ticks_now = int(time.time() * 10_000_000) + 621355968000000000 # Convert Unix epoch to .NET Ticks
        header = {
            'MagicNumber': Constants.MAGIC_NUMBER,
            'FormatVersionMajor': 1,
            'FormatVersionMinor': 0,
            'ContainerUUID': uuid.uuid4().bytes,
            'CreationTimestamp': ticks_now,
            'ModificationTimestamp': ticks_now,
            'EditVersion': 1,
            'CreatingSystem': Constants.CREATING_SYSTEM.encode('utf-8').ljust(32, b'\0'),
            'SoftwareVersion': Constants.SOFTWARE_VERSION.encode('utf-8').ljust(32, b'\0'),
            'EncryptionMode': self.config.get('encryption_mode', 0),
            'KDFIterations': self.config.get('kdf_iterations', 100000),
            'FECScheme': self.config.get('fec_scheme', 0),
            'FECLevel': self.config.get('fec_level', 0),
            'FileIndexCompression': 1,
            'GlobalCompression': 1 if self.config.get('global_compression') else 0,
            'ReadSalt': (read_salt or b'').ljust(64, b'\0'),
            'WriteSalt': (write_salt or b'').ljust(64, b'\0'),
            'Reserved': b'\0' * 50
        }
        return header

    def _write_single_archive(self, output_path, file_index, file_data_block_bytes, read_key, read_salt, write_salt):
        if self.config.get('global_compression'):
            print("\nApplying global compression...")
            cctx = zstd.ZstdCompressor(level=self.config.get('compression_level', 3))
            file_data_block_bytes = cctx.compress(file_data_block_bytes)

        if self.config.get('encryption_mode', 0) > 0:
            assert read_key is not None
            file_data_block_bytes = encrypt_aes_gcm(file_data_block_bytes, read_key)

        uncompressed_index_bytes = serialize_index(file_index)
        cctx_index = zstd.ZstdCompressor()
        compressed_index_bytes = cctx_index.compress(uncompressed_index_bytes)
        index_block_bytes = compressed_index_bytes
        if self.config.get('encryption_mode', 0) > 0:
            assert read_key is not None
            index_block_bytes = encrypt_aes_gcm(compressed_index_bytes, read_key)

        header = self._create_header(read_salt, write_salt)
        current_offset = Constants.HEADER_SIZE
        
        header['FileIndexOffset'] = current_offset
        header['FileIndexLength'] = len(index_block_bytes)
        current_offset += len(index_block_bytes)
        current_offset += len(file_data_block_bytes)
        
        header['FECDataOffset'] = current_offset
        data_fec_bytes = create_fec(file_data_block_bytes, self.config.get('fec_level', 0)) if self.config.get('fec_scheme') == 1 else b''
        header['FECDataLength'] = len(data_fec_bytes)
        current_offset += len(data_fec_bytes)
        
        header['HeaderChecksum'] = 0
        ordered_values = [header[key] for key in get_header_keys()]
        header_bytes_for_checksum_calc = struct.pack(Constants.HEADER_FORMAT, *ordered_values)
        header['HeaderChecksum'] = crc32_compute(header_bytes_for_checksum_calc[:-54])
        
        header_bytes_for_fec = struct.pack(Constants.HEADER_FORMAT, *[header[key] for key in get_header_keys()])
        metadata_to_protect = header_bytes_for_fec + uncompressed_index_bytes
        metadata_fec_bytes = create_fec(metadata_to_protect, 10) if self.config.get('fec_scheme') == 1 else b''

        footer = {
            'MainIndexOffset': header['FileIndexOffset'], 'MainIndexLength': header['FileIndexLength'],
            'MetadataFECBlockOffset': current_offset, 'MetadataFECBlockLength': len(metadata_fec_bytes),
            'FooterChecksum': 0, 'FooterMagic': Constants.FOOTER_MAGIC
        }
        
        footer_bytes_for_checksum = struct.pack("<QQQ", footer['MainIndexOffset'], footer['MainIndexLength'], footer['MetadataFECBlockOffset'])
        footer['FooterChecksum'] = crc32_compute(footer_bytes_for_checksum)
        
        with open(output_path, 'wb') as f:
            final_ordered_values = [header[key] for key in get_header_keys()]
            f.write(struct.pack(Constants.HEADER_FORMAT, *final_ordered_values))
            f.write(index_block_bytes)
            f.write(file_data_block_bytes)
            f.write(data_fec_bytes)
            f.write(metadata_fec_bytes)
            f.write(struct.pack(Constants.FOOTER_FORMAT, *footer.values()))
        
        print(f"\nFile '{output_path}' created successfully.")

    def _write_split_archive(self, output_path, original_file_index, combined_data, read_key, read_salt, write_salt):
        print(f"\nSplitting data into blocks of max {self.config['split_size'] // 1024 // 1024} MB...")
        split_size = self.config['split_size']
        block_index = 0
        final_file_index = []
        current_block_stream = bytearray()
        
        for entry in original_file_index:
            entry_data = combined_data[entry['data_offset']:entry['data_offset'] + entry['data_size']]
            chunk_group_id = uuid.uuid4().bytes
            entry_data_offset = 0
            chunk_index = 0
            total_chunks = (len(entry_data) + split_size - 1) // split_size if len(entry_data) > 0 else 0
            if total_chunks == 0 and len(entry_data) > 0: total_chunks = 1
            while entry_data_offset < len(entry_data) or (len(entry_data) == 0 and chunk_index == 0):
                space_in_current_block = split_size - len(current_block_stream)
                bytes_to_write = min(len(entry_data) - entry_data_offset, space_in_current_block)
                if bytes_to_write <= 0 and len(current_block_stream) > 0:
                    self._write_data_block(output_path, block_index, bytes(current_block_stream), read_key)
                    block_index += 1
                    current_block_stream.clear()
                    continue
                chunk_entry = {**entry, 'block_file_index': block_index, 'data_offset': len(current_block_stream), 'data_size': bytes_to_write, 'chunk_group_id': chunk_group_id, 'chunk_index': chunk_index, 'total_chunks': total_chunks}
                final_file_index.append(chunk_entry)
                current_block_stream.extend(entry_data[entry_data_offset : entry_data_offset + bytes_to_write])
                entry_data_offset += bytes_to_write
                chunk_index += 1
                if len(current_block_stream) >= split_size:
                    self._write_data_block(output_path, block_index, bytes(current_block_stream), read_key)
                    block_index += 1
                    current_block_stream.clear()
                if len(entry_data) == 0: break
        if len(current_block_stream) > 0:
            self._write_data_block(output_path, block_index, bytes(current_block_stream), read_key)

        uncompressed_index_bytes = serialize_index(final_file_index)
        cctx_index = zstd.ZstdCompressor()
        compressed_index_bytes = cctx_index.compress(uncompressed_index_bytes)
        index_block_bytes = compressed_index_bytes
        if self.config.get('encryption_mode', 0) > 0:
            assert read_key is not None
            index_block_bytes = encrypt_aes_gcm(compressed_index_bytes, read_key)

        header = self._create_header(read_salt, write_salt)
        header['FileIndexOffset'] = Constants.HEADER_SIZE
        header['FileIndexLength'] = len(index_block_bytes)
        header['FECDataOffset'] = 0 
        header['FECDataLength'] = 0
        current_offset = Constants.HEADER_SIZE + len(index_block_bytes)

        header['HeaderChecksum'] = 0
        ordered_values_for_checksum = [header[key] for key in get_header_keys()]
        header_bytes_for_checksum_calc = struct.pack(Constants.HEADER_FORMAT, *ordered_values_for_checksum)
        header['HeaderChecksum'] = crc32_compute(header_bytes_for_checksum_calc[:-54])

        ordered_values_for_fec = [header[key] for key in get_header_keys()]
        header_bytes_for_fec = struct.pack(Constants.HEADER_FORMAT, *ordered_values_for_fec)
        metadata_to_protect = header_bytes_for_fec + uncompressed_index_bytes
        metadata_fec_bytes = create_fec(metadata_to_protect, 10) if self.config.get('fec_scheme') == 1 else b''

        footer = {
            'MainIndexOffset': header['FileIndexOffset'], 'MainIndexLength': header['FileIndexLength'],
            'MetadataFECBlockOffset': current_offset, 'MetadataFECBlockLength': len(metadata_fec_bytes),
            'FooterChecksum': 0, 'FooterMagic': Constants.FOOTER_MAGIC
        }
        
        footer_bytes_for_checksum = struct.pack("<QQQ", footer['MainIndexOffset'], footer['MainIndexLength'], footer['MetadataFECBlockOffset'])
        footer['FooterChecksum'] = crc32_compute(footer_bytes_for_checksum)
        
        with open(output_path, 'wb') as f:
            final_ordered_values = [header[key] for key in get_header_keys()]
            final_header_bytes = struct.pack(Constants.HEADER_FORMAT, *final_ordered_values)
            f.write(final_header_bytes)
            f.write(index_block_bytes)
            f.write(metadata_fec_bytes)
            f.write(struct.pack(Constants.FOOTER_FORMAT, *footer.values()))
        
        print(f"\nIndex file '{output_path}' and {block_index + 1} data block(s) created successfully.")

    def _write_data_block(self, base_path, block_index, data, read_key):
        block_path = f"{base_path}{block_index}"
        print(f"Writing block: {os.path.basename(block_path)} ({len(data)} bytes)")

        if self.config.get('global_compression'):
            cctx = zstd.ZstdCompressor(level=self.config.get('compression_level', 3))
            data = cctx.compress(data)
        
        if self.config.get('encryption_mode', 0) > 0:
            assert read_key is not None
            data = encrypt_aes_gcm(data, read_key)
            
        with open(block_path, 'wb') as f:
            f.write(data)

# ===================================================================================
# 4. G3FC READER
# ===================================================================================

class G3FCReader:
    def __init__(self, archive_path, password=""):
        self.archive_path = archive_path
        self.password = password
        self.header = self._read_header()

    def _read_header(self) -> dict:
        with open(self.archive_path, 'rb') as f:
            header_bytes = f.read(Constants.HEADER_SIZE)
        header_values = struct.unpack(Constants.HEADER_FORMAT, header_bytes)
        return dict(zip(get_header_keys(), header_values))

    def read_file_index(self) -> list:
        with open(self.archive_path, 'rb') as f:
            f.seek(self.header['FileIndexOffset'])
            index_block_bytes = f.read(self.header['FileIndexLength'])
        
        if self.header['EncryptionMode'] > 0:
            if not self.password:
                raise ValueError("Password required for this archive.")
            read_key = derive_key(self.password, self.header['ReadSalt'], self.header['KDFIterations'])
            index_block_bytes = decrypt_aes_gcm(index_block_bytes, read_key)
        
        if self.header['FileIndexCompression'] == 1:
            dctx = zstd.ZstdDecompressor()
            index_block_bytes = dctx.decompress(index_block_bytes)
        
        return deserialize_index(index_block_bytes)

    def extract_files(self, dest_dir: str):
        print("Reading archive index...")
        file_index = self.read_file_index()
        print(f"Found {len(file_index)} file entries. Grouping and starting extraction...")

        file_groups = {}
        for entry in file_index:
            group_id_bytes = entry.get('chunk_group_id') or entry.get('uuid')
            # CBOR can deserialize to string, so we convert if necessary
            if isinstance(group_id_bytes, str):
                group_id_bytes = group_id_bytes.encode('utf-8')
            
            group_id = uuid.UUID(bytes=group_id_bytes)
            if group_id not in file_groups:
                file_groups[group_id] = []
            file_groups[group_id].append(entry)

        for group_id, chunks in file_groups.items():
            chunks.sort(key=lambda c: c['chunk_index'])
            self._extract_file_from_chunks(chunks, dest_dir)
        
        print("\nExtraction complete.")

    def _extract_file_from_chunks(self, chunks: list, dest_dir: str):
        if not chunks: return
        
        first_chunk = chunks[0]
        print(f"Extracting: {first_chunk['path']} ({len(chunks)} chunk(s))")

        read_key = None
        if self.header['EncryptionMode'] > 0:
            read_key = derive_key(self.password, self.header['ReadSalt'], self.header['KDFIterations'])

        reassembled_stream = bytearray()
        is_split = self.header['FECDataOffset'] == 0 and self.header['FECDataLength'] == 0
        
        data_blocks_cache = {}
        
        for chunk in chunks:
            block_file_index = chunk['block_file_index']
            
            if block_file_index not in data_blocks_cache:
                data_block = b''
                if is_split:
                    block_path = f"{self.archive_path}{block_file_index}"
                    if not os.path.exists(block_path):
                        raise FileNotFoundError(f"Data block not found: {block_path}")
                    with open(block_path, 'rb') as f:
                        data_block = f.read()
                else:
                    with open(self.archive_path, 'rb') as f:
                        data_block_start = self.header['FileIndexOffset'] + self.header['FileIndexLength']
                        data_block_end = self.header['FECDataOffset']
                        f.seek(data_block_start)
                        data_block = f.read(data_block_end - data_block_start)
                
                if self.header['EncryptionMode'] > 0:
                    assert read_key is not None
                    data_block = decrypt_aes_gcm(data_block, read_key)
                    
                if self.header['GlobalCompression'] == 1:
                    dctx = zstd.ZstdDecompressor()
                    data_block = dctx.decompress(data_block)
                
                data_blocks_cache[block_file_index] = data_block

            data_block = data_blocks_cache[block_file_index]
            chunk_data = data_block[chunk['data_offset'] : chunk['data_offset'] + chunk['data_size']]
            reassembled_stream.extend(chunk_data)

        final_data = bytes(reassembled_stream)
        if self.header['GlobalCompression'] == 0 and first_chunk['compression'] == 1:
            dctx = zstd.ZstdDecompressor()
            final_data = dctx.decompress(final_data)
        
        if crc32_compute(final_data) != first_chunk['checksum']:
            raise ValueError(f"Checksum mismatch for file {first_chunk['original_filename']}")

        dest_path = os.path.join(dest_dir, first_chunk['path'])
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        with open(dest_path, 'wb') as f:
            f.write(final_data)
        
        set_permissions(dest_path, first_chunk['permissions'])

# ===================================================================================
# 5. MAIN PROGRAM (Command Line Interface)
# ===================================================================================

def show_full_help(parser):
    """
    Displays a detailed help screen, showing options for all sub-commands.
    """
    print(parser.description)
    print(f"\nUsage: {os.path.basename(sys.argv[0])} <command> [options]")

    subparsers_action = next(
        (action for action in parser._actions if isinstance(action, argparse._SubParsersAction)),
        None
    )
    if not subparsers_action:
        return

    print("\nCommands:")
    for choice, sub_parser in subparsers_action.choices.items():
        help_text = sub_parser.description.splitlines()[0]
        print(f"  {choice:<22}{help_text}")

    print("\nOptions for Commands:")
    for choice, sub_parser in subparsers_action.choices.items():
        header = f"--- Options for '{choice}' ---"
        print(f"\n{header}")
        
        help_text = sub_parser.format_help()
        help_lines = help_text.splitlines()[1:]
        
        cleaned_lines = []
        started = False
        for line in help_lines:
            if line.strip():
                started = True
            if started:
                cleaned_lines.append(line)
        
        print("\n".join(cleaned_lines))

    if parser.epilog:
        print(f"\n{parser.epilog}")

def main():
    examples = """Examples:
  g3fc.py create -o my_archive.g3fc -p mypassword --split 500MB "C:\\docs\\file.txt" "C:\\photos"
  g3fc.py extract my_archive.g3fc -o "C:\\extracted_files" -p mypassword
"""

    parser = argparse.ArgumentParser(
        description="G3FC Archiver Tool - Python Version",
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    subparsers = parser.add_subparsers(dest="command", title="Commands", help="command description")

    parser_create = subparsers.add_parser(
        "create",
        aliases=['c'],
        help="Create a new G3FC archive.",
        description="Bundles files and folders into a .g3fc archive, with options for compression, encryption, and more.",
        add_help=False
    )
    parser_create.add_argument("input_paths", nargs='+', help="Required. One or more files or folders to add.")
    parser_create.add_argument("-o", "--output", required=True, help="Required. Path for the output .g3fc file.")
    parser_create.add_argument("-p", "--password", help="Optional. Encrypt the archive with a password.")
    parser_create.add_argument("-cl", "--compression-level", type=int, default=3, help="Optional. ZSTD compression level (1-22). Default: 3.")
    parser_create.add_argument("-gc", "--global-compression", action="store_true", help="Optional. Use global compression instead of per-file.")
    parser_create.add_argument("-fl", "--fec-level", type=int, default=0, choices=range(0, 51), help="Optional. Forward Error Correction level (0-50).")
    parser_create.add_argument("--split", type=str, help="Optional. Split data into blocks of specified size (e.g., 100MB, 2GB).")

    parser_extract = subparsers.add_parser(
        "extract",
        aliases=['x'],
        help="Extract files from a G3FC archive.",
        description="Extracts the contents of a .g3fc archive to a destination directory.",
        add_help=False
    )
    parser_extract.add_argument("archive_path", help="Required. The .g3fc file to extract.")
    parser_extract.add_argument("-o", "--output", required=True, help="Required. Destination directory for extracted files.")
    parser_extract.add_argument("-p", "--password", help="Optional. Password for encrypted archives.")

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        show_full_help(parser)
        sys.exit(0)

    args = parser.parse_args()
    
    if not args.command:
        print("Error: No command specified ('create' or 'extract').\n", file=sys.stderr)
        show_full_help(parser)
        sys.exit(1)

    try:
        if args.command in ["create", "c"]:
            config = {
                'compression_level': args.compression_level,
                'global_compression': args.global_compression,
                'encryption_mode': 1 if args.password else 0,
                'read_password': args.password or "",
                'kdf_iterations': 100000,
                'fec_scheme': 1 if args.fec_level > 0 else 0,
                'fec_level': args.fec_level,
                'split_size': parse_split_size(args.split)
            }
            
            files_to_process = []
            for path in args.input_paths:
                if not os.path.exists(path):
                    print(f"Warning: Input path '{path}' does not exist and will be skipped.")
                    continue
                if os.path.isfile(path):
                    files_to_process.append((path, os.path.basename(path)))
                elif os.path.isdir(path):
                    base_dir = os.path.abspath(os.path.join(path, os.pardir))
                    for root, _, files in os.walk(path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            relative_path = os.path.relpath(full_path, base_dir)
                            files_to_process.append((full_path, relative_path))

            if not files_to_process:
                print("Error: No valid files found in the input paths.", file=sys.stderr)
                sys.exit(1)

            writer = G3FCWriter(config)
            writer.create_g3fc_archive(args.output, files_to_process)

        elif args.command in ["extract", "x"]:
            if not os.path.exists(args.archive_path):
                raise FileNotFoundError(f"Input archive not found: {args.archive_path}")
            
            os.makedirs(args.output, exist_ok=True)
            
            reader = G3FCReader(args.archive_path, args.password or "")
            reader.extract_files(args.output)
            
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
