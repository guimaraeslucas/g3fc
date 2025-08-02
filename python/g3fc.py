#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# G3FC Archiver Tool - Python Version
#
# @author  Lucas Guimarães - G3Pix <https://github.com/guimaraeslucas/>
# @license GNU General Public License v2.0
# @version 1.1.3
#
# Copyright 2025, Lucas Guimarães - G3Pix Ltda <https://g3pix.com.br>
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
# SECURITY NOTICE AND IMPLEMENTATION GUIDANCE:
#
# While this Python implementation includes mitigations against the security vulnerabilities
# described below, any other implementation based on the G3FC specification MUST
# independently address these critical security concerns.
#
# For example and implementation purposes, the C# code shall always be considered
# the most up-to-date and secure reference.
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
import json
import getpass
from datetime import datetime, timezone

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
    CREATING_SYSTEM = "G3Pix Python G3FC Archiver"
    SOFTWARE_VERSION = "1.1.4"
    MAX_FEC_LIB_SHARDS = 255
    MIN_FEC_SHARDS = 1
    MAX_FEC_SHARDS = 254
    DOTNET_EPOCH_TICKS = 621355968000000000
    
    HEADER_FORMAT = (
        "<"
        "4s" "H" "H" "16s" "q" "q" "I" "32s" "32s" "Q" "Q" "B" "B" "B"
        "64s" "64s" "I" "B" "B" "Q" "Q" "I" "50s"
    )
    FOOTER_FORMAT = "<" "Q" "Q" "Q" "Q" "I" "4s"

# ===================================================================================
# 2. HELPER METHODS (G3FCHelpers)
# ===================================================================================

def get_header_keys():
    return [
        'MagicNumber', 'FormatVersionMajor', 'FormatVersionMinor', 'ContainerUUID', 
        'CreationTimestamp', 'ModificationTimestamp', 'EditVersion', 'CreatingSystem',
        'SoftwareVersion', 'FileIndexOffset', 'FileIndexLength', 'FileIndexCompression',
        'GlobalCompression', 'EncryptionMode', 'ReadSalt', 'WriteSalt', 'KDFIterations',
        'FECScheme', 'FECLevel', 'FECDataOffset', 'FECDataLength', 'HeaderChecksum', 'Reserved'
    ]

def crc32_compute(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty for key derivation.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext_and_tag[-16:]
    ciphertext = ciphertext_and_tag[:-16]
    return nonce + tag + ciphertext

def decrypt_aes_gcm(payload: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]
    ciphertext_and_tag = ciphertext + tag
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag:
        raise ValueError("Decryption failed: password may be incorrect or data is corrupted.")

def create_fec(data: bytes, fec_level: int) -> bytes:
    if not data or fec_level == 0: return b''
    parity_shards_count = max(Constants.MIN_FEC_SHARDS, min(Constants.MAX_FEC_SHARDS, (fec_level * (Constants.MAX_FEC_LIB_SHARDS - 1)) // 100))
    data_shards_count = max(1, Constants.MAX_FEC_LIB_SHARDS - parity_shards_count)
    rs = RSCodec(parity_shards_count)
    
    shard_size = (len(data) + data_shards_count - 1) // data_shards_count
    padded_len = shard_size * data_shards_count
    padded_data = data.ljust(padded_len, b'\0')
    
    encoded = rs.encode(padded_data)
    return bytes(encoded[padded_len:])

def serialize_index(file_index: list) -> bytes:
    return cbor2.dumps(file_index)

def deserialize_index(data: bytes) -> list:
    return cbor2.loads(data)

def parse_split_size(size_str: str) -> int:
    if not size_str: return 0
    match = re.match(r'^(\d+)(MB|GB)$', size_str.upper())
    if not match: raise ValueError("Invalid size format. Use a number followed by MB or GB.")
    size, unit = int(match.group(1)), match.group(2)
    return size * (1024**2 if unit == "MB" else 1024**3)

def get_permissions(path: str) -> int:
    try: return os.stat(path).st_mode & 0o777
    except: return 0o666 if os.name == 'nt' else 0o644

def set_permissions(path: str, permissions: int):
    try: os.chmod(path, permissions)
    except Exception as e: print(f"Warning: Could not set permissions for {path}. {e}")

def unix_to_dotnet_ticks(unix_timestamp: float) -> int:
    """Converts a Unix timestamp (seconds since 1970-01-01) to .NET Ticks."""
    return int(unix_timestamp * 10_000_000) + Constants.DOTNET_EPOCH_TICKS

def dotnet_ticks_to_datetime(ticks: int) -> datetime:
    """Converts .NET Ticks to a timezone-aware UTC datetime object."""
    if ticks < Constants.DOTNET_EPOCH_TICKS: return datetime(1, 1, 1, tzinfo=timezone.utc)
    return datetime.fromtimestamp((ticks - Constants.DOTNET_EPOCH_TICKS) / 10_000_000, tz=timezone.utc)

def correct_timestamp_if_needed(ticks: int) -> int:
    """
    Detects and corrects timestamps that might have been created by an older,
    buggy Python script that stored nanoseconds instead of .NET Ticks.
    """
    if ticks > 3_000_000_000_000_000_000:
        nanoseconds_since_epoch = ticks
        seconds_since_epoch = nanoseconds_since_epoch / 1_000_000_000
        return unix_to_dotnet_ticks(seconds_since_epoch)
    return ticks

# ===================================================================================
# 3. G3FC WRITER
# ===================================================================================

class G3FCWriter:
    def __init__(self, config):
        self.config = config

    def create_g3fc_archive(self, output_path: str, source_files: list):
        file_index, data_block_stream = [], bytearray()
        print("Collecting files and preparing data...")
        for full_path, relative_path in source_files:
            if not os.path.exists(full_path):
                print(f"Warning: Skipping non-existent file {full_path}")
                continue
            print(f"Adding: {relative_path}")
            file_info = os.stat(full_path)
            with open(full_path, 'rb') as f: file_data = f.read()
            entry = {
                'path': relative_path.replace('\\', '/'), 'type': "file", 'uuid': uuid.uuid4().bytes,
                'creation_time': unix_to_dotnet_ticks(file_info.st_ctime),
                'modification_time': unix_to_dotnet_ticks(file_info.st_mtime),
                'permissions': get_permissions(full_path), 'status': 0,
                'original_filename': os.path.basename(full_path),
                'uncompressed_size': len(file_data), 'checksum': crc32_compute(file_data)
            }
            data_to_add = file_data
            if self.config.get('global_compression'): entry['compression'] = 0
            else:
                cctx = zstd.ZstdCompressor(level=self.config.get('compression_level', 6))
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
            write_salt = os.urandom(64) if self.config.get('encryption_mode') == 2 else read_salt
        
        if self.config.get('split_size', 0) > 0: self._write_split_archive(output_path, file_index, data_block_stream, read_key, read_salt, write_salt)
        else: self._write_single_archive(output_path, file_index, data_block_stream, read_key, read_salt, write_salt)

    def _create_header(self, read_salt, write_salt) -> dict:
        return {
            'MagicNumber': Constants.MAGIC_NUMBER, 'FormatVersionMajor': 1, 'FormatVersionMinor': 0,
            'ContainerUUID': uuid.uuid4().bytes, 'CreationTimestamp': unix_to_dotnet_ticks(time.time()),
            'ModificationTimestamp': unix_to_dotnet_ticks(time.time()), 'EditVersion': 1,
            'CreatingSystem': Constants.CREATING_SYSTEM.encode('utf-8').ljust(32, b'\0'),
            'SoftwareVersion': Constants.SOFTWARE_VERSION.encode('utf-8').ljust(32, b'\0'),
            'EncryptionMode': self.config.get('encryption_mode', 0),
            'KDFIterations': self.config.get('kdf_iterations', 100000),
            'FECScheme': 1 if self.config.get('fec_level', 0) > 0 else 0,
            'FECLevel': self.config.get('fec_level', 0), 'FileIndexCompression': 1,
            'GlobalCompression': 1 if self.config.get('global_compression') else 0,
            'ReadSalt': (read_salt or b'').ljust(64, b'\0'),
            'WriteSalt': (write_salt or b'').ljust(64, b'\0'), 'Reserved': b'\0' * 50
        }

    def _write_single_archive(self, output_path, file_index, file_data_block_bytes, read_key, read_salt, write_salt):
        if self.config.get('global_compression'):
            print("\nApplying global compression...")
            cctx = zstd.ZstdCompressor(level=self.config.get('compression_level', 6))
            file_data_block_bytes = cctx.compress(file_data_block_bytes)
        if self.config.get('encryption_mode', 0) > 0: file_data_block_bytes = encrypt_aes_gcm(file_data_block_bytes, read_key)
        
        uncompressed_index_bytes = serialize_index(file_index)
        compressed_index_bytes = zstd.ZstdCompressor().compress(uncompressed_index_bytes)
        index_block_bytes = encrypt_aes_gcm(compressed_index_bytes, read_key) if self.config.get('encryption_mode', 0) > 0 else compressed_index_bytes
        
        header = self._create_header(read_salt, write_salt)
        current_offset = Constants.HEADER_SIZE
        header.update({'FileIndexOffset': current_offset, 'FileIndexLength': len(index_block_bytes)})
        current_offset += len(index_block_bytes) + len(file_data_block_bytes)
        
        data_fec_bytes = create_fec(file_data_block_bytes, self.config.get('fec_level', 0)) if header['FECScheme'] == 1 else b''
        header.update({'FECDataOffset': current_offset, 'FECDataLength': len(data_fec_bytes)})
        current_offset += len(data_fec_bytes)
        
        header['HeaderChecksum'] = 0
        header_bytes_for_fec = struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()])
        metadata_fec_bytes = create_fec(header_bytes_for_fec + uncompressed_index_bytes, 10) if header['FECScheme'] == 1 else b''
        
        footer = {'MainIndexOffset': header['FileIndexOffset'], 'MainIndexLength': header['FileIndexLength'], 'MetadataFECBlockOffset': current_offset, 'MetadataFECBlockLength': len(metadata_fec_bytes), 'FooterChecksum': 0, 'FooterMagic': Constants.FOOTER_MAGIC}
        footer_bytes_for_checksum = struct.pack("<QQQQ", footer['MainIndexOffset'], footer['MainIndexLength'], footer['MetadataFECBlockOffset'], footer['MetadataFECBlockLength'])
        footer['FooterChecksum'] = crc32_compute(footer_bytes_for_checksum)
        
        header_bytes_for_checksum = struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()])
        header['HeaderChecksum'] = crc32_compute(header_bytes_for_checksum[:-54])
        
        with open(output_path, 'wb') as f:
            f.write(struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()]))
            f.write(index_block_bytes)
            f.write(file_data_block_bytes)
            f.write(data_fec_bytes)
            f.write(metadata_fec_bytes)
            f.write(struct.pack(Constants.FOOTER_FORMAT, *footer.values()))
        print(f"\nFile '{output_path}' created successfully.")

    def _write_split_archive(self, output_path, original_file_index, combined_data, read_key, read_salt, write_salt):
        print(f"\nSplitting data into blocks of max {self.config['split_size'] // 1024 // 1024} MB...")
        split_size, block_index, final_file_index, current_block_stream = self.config['split_size'], 0, [], bytearray()
        
        for entry in original_file_index:
            entry_data = combined_data[entry['data_offset']:entry['data_offset'] + entry['data_size']]
            chunk_group_id, entry_data_offset, chunk_index = uuid.uuid4().bytes, 0, 0
            total_chunks = (len(entry_data) + split_size - 1) // split_size if len(entry_data) > 0 else 1
            
            while entry_data_offset < len(entry_data) or (len(entry_data) == 0 and chunk_index == 0):
                if len(current_block_stream) >= split_size:
                    self._write_data_block(output_path, block_index, bytes(current_block_stream), read_key)
                    block_index += 1; current_block_stream.clear()
                
                space_in_block = split_size - len(current_block_stream)
                bytes_to_write = min(len(entry_data) - entry_data_offset, space_in_block)
                chunk_entry = {**entry, 'block_file_index': block_index, 'data_offset': len(current_block_stream), 'data_size': bytes_to_write, 'chunk_group_id': chunk_group_id, 'chunk_index': chunk_index, 'total_chunks': total_chunks}
                final_file_index.append(chunk_entry)
                current_block_stream.extend(entry_data[entry_data_offset : entry_data_offset + bytes_to_write])
                entry_data_offset += bytes_to_write
                chunk_index += 1
                if len(entry_data) == 0: break
        
        if len(current_block_stream) > 0: self._write_data_block(output_path, block_index, bytes(current_block_stream), read_key)

        uncompressed_index_bytes = serialize_index(final_file_index)
        compressed_index_bytes = zstd.ZstdCompressor().compress(uncompressed_index_bytes)
        index_block_bytes = encrypt_aes_gcm(compressed_index_bytes, read_key) if self.config.get('encryption_mode', 0) > 0 else compressed_index_bytes
        
        header = self._create_header(read_salt, write_salt)
        header.update({'FileIndexOffset': Constants.HEADER_SIZE, 'FileIndexLength': len(index_block_bytes), 'FECDataOffset': 0, 'FECDataLength': 0})
        current_offset = Constants.HEADER_SIZE + len(index_block_bytes)
        
        header['HeaderChecksum'] = 0
        header_bytes_for_fec = struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()])
        metadata_fec_bytes = create_fec(header_bytes_for_fec + uncompressed_index_bytes, 10) if header['FECScheme'] == 1 else b''
        
        footer = {'MainIndexOffset': header['FileIndexOffset'], 'MainIndexLength': header['FileIndexLength'], 'MetadataFECBlockOffset': current_offset, 'MetadataFECBlockLength': len(metadata_fec_bytes), 'FooterChecksum': 0, 'FooterMagic': Constants.FOOTER_MAGIC}
        footer_bytes_for_checksum = struct.pack("<QQQQ", footer['MainIndexOffset'], footer['MainIndexLength'], footer['MetadataFECBlockOffset'], footer['MetadataFECBlockLength'])
        footer['FooterChecksum'] = crc32_compute(footer_bytes_for_checksum)
        
        header_bytes_for_checksum = struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()])
        header['HeaderChecksum'] = crc32_compute(header_bytes_for_checksum[:-54])
        
        with open(output_path, 'wb') as f:
            f.write(struct.pack(Constants.HEADER_FORMAT, *[header[k] for k in get_header_keys()]))
            f.write(index_block_bytes)
            f.write(metadata_fec_bytes)
            f.write(struct.pack(Constants.FOOTER_FORMAT, *footer.values()))
        print(f"\nIndex file '{output_path}' and {block_index + 1} data block(s) created successfully.")

    def _write_data_block(self, base_path, block_index, data, read_key):
        block_path = f"{base_path}{block_index}"
        print(f"Writing block: {os.path.basename(block_path)} ({len(data)} bytes)")
        if self.config.get('global_compression'): data = zstd.ZstdCompressor(level=self.config.get('compression_level', 6)).compress(data)
        if self.config.get('encryption_mode', 0) > 0: data = encrypt_aes_gcm(data, read_key)
        with open(block_path, 'wb') as f: f.write(data)

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
        return dict(zip(get_header_keys(), struct.unpack(Constants.HEADER_FORMAT, header_bytes)))

    def read_file_index(self) -> list:
        with open(self.archive_path, 'rb') as f:
            f.seek(self.header['FileIndexOffset'])
            index_block_bytes = f.read(self.header['FileIndexLength'])
        
        if self.header['EncryptionMode'] > 0:
            if not self.password: raise ValueError("Password required for this archive.")
            read_key = derive_key(self.password, self.header['ReadSalt'], self.header['KDFIterations'])
            index_block_bytes = decrypt_aes_gcm(index_block_bytes, read_key)
        
        if self.header['FileIndexCompression'] == 1:
            index_block_bytes = zstd.ZstdDecompressor().decompress(index_block_bytes)
        
        return deserialize_index(index_block_bytes)

    def _extract_file_from_chunks(self, chunks: list, dest_dir: str):
        if not chunks: return
        first_chunk = chunks[0]
        print(f"Extracting: {first_chunk['path']} ({len(chunks)} chunk(s))")
        
        uncompressed_size = first_chunk.get('uncompressed_size', 0)
        if uncompressed_size > 4 * 1024**3: # 4GB limit
            print(f"\nWARNING: File '{first_chunk['path']}' is very large ({uncompressed_size // 1024**2} MB).")
            if input("Continue? (y/n): ").lower() not in ['y', 'yes']:
                print("Extraction cancelled.")
                return

        read_key = derive_key(self.password, self.header['ReadSalt'], self.header['KDFIterations']) if self.header['EncryptionMode'] > 0 else None
        reassembled_stream, is_split = bytearray(), self.header['FECDataOffset'] == 0 and self.header['FECDataLength'] == 0
        data_blocks_cache = {}
        
        for chunk in sorted(chunks, key=lambda c: c['chunk_index']):
            block_idx = chunk['block_file_index']
            if block_idx not in data_blocks_cache:
                if is_split:
                    with open(f"{self.archive_path}{block_idx}", 'rb') as f: data_block = f.read()
                else:
                    with open(self.archive_path, 'rb') as f:
                        start = self.header['FileIndexOffset'] + self.header['FileIndexLength']
                        end = self.header['FECDataOffset']
                        f.seek(start)
                        data_block = f.read(end - start)
                
                if self.header['EncryptionMode'] > 0: data_block = decrypt_aes_gcm(data_block, read_key)
                if self.header['GlobalCompression'] == 1: 
                    # CORRECTION: Provide the uncompressed size for the entire block if possible.
                    # This is a limitation, as we don't store the uncompressed size of the whole block.
                    # We rely on the library's ability to stream or handle this.
                    # If this fails, a format change would be needed.
                    data_block = zstd.ZstdDecompressor().decompress(data_block)
                data_blocks_cache[block_idx] = data_block
            
            data_block = data_blocks_cache[block_idx]
            reassembled_stream.extend(data_block[chunk['data_offset'] : chunk['data_offset'] + chunk['data_size']])

        final_data = bytes(reassembled_stream)
        if self.header['GlobalCompression'] == 0 and first_chunk['compression'] == 1:
            # CORRECTION: Provide the known uncompressed size of the final file to the decompressor.
            final_data = zstd.ZstdDecompressor().decompress(final_data, max_output_size=first_chunk['uncompressed_size'])
        
        if crc32_compute(final_data) != first_chunk['checksum']:
            raise ValueError(f"Checksum mismatch for {first_chunk['original_filename']}")
        
        dest_path_abs = os.path.abspath(os.path.join(dest_dir, first_chunk['path']))
        dest_dir_abs = os.path.abspath(dest_dir)
        if not dest_path_abs.startswith(dest_dir_abs):
            raise PermissionError(f"Path traversal attempt detected: '{first_chunk['path']}'")

        os.makedirs(os.path.dirname(dest_path_abs), exist_ok=True)
        with open(dest_path_abs, 'wb') as f: f.write(final_data)
        set_permissions(dest_path_abs, first_chunk['permissions'])

# ===================================================================================
# 5. G3FC COMMANDS
# ===================================================================================

class G3FCCommands:
    def __init__(self, reader_instance):
        self.reader = reader_instance
        self._file_index_cache = None

    def _get_file_index(self):
        if self._file_index_cache is None:
            self._file_index_cache = self.reader.read_file_index()
        return self._file_index_cache

    def _get_logical_files(self):
        file_groups = {e['path']: e for e in self._get_file_index()}
        return sorted(file_groups.values(), key=lambda x: x['path'])

    def list_files_in_container(self, size_unit="KB", show_details=False):
        print(f"Listing contents of: {self.reader.archive_path}\n")
        try:
            header = f"{'Path':<60} {'Size':<15} {'Type':<12}" + (f"{'Permissions':<12} {'Creation Time':<22} {'Checksum'}" if show_details else "")
            print(header); print('-' * (len(header) + 5))
            for entry in self._get_logical_files():
                line = f"{entry.get('path', ''):<60} {self._format_size(entry.get('uncompressed_size', 0), size_unit):<15} {entry.get('type', ''):<12}"
                if show_details:
                    corrected_ticks = correct_timestamp_if_needed(entry.get('creation_time', 0))
                    dt = dotnet_ticks_to_datetime(corrected_ticks).astimezone()
                    permissions_val = entry.get('permissions', 0)
                    if permissions_val == 666: permissions_val = 438
                    permissions_str = f"0o{permissions_val:o}"
                    line += f" {permissions_str:<12} {dt.strftime('%Y-%m-%d %H:%M:%S'):<22} {entry.get('checksum', 0):08X}"
                print(line)
        except Exception as e: print(f"Error listing files: {e}")

    def export_info(self, output_json_path):
        print(f"Exporting metadata to {output_json_path}...")
        try:
            file_index = self._get_file_index()
            export_list = []
            for entry in file_index:
                export_list.append({
                    "Path": entry.get('path'), "Type": entry.get('type'),
                    "UUID": str(uuid.UUID(bytes=entry.get('uuid'))),
                    "CreationTime": dotnet_ticks_to_datetime(correct_timestamp_if_needed(entry.get('creation_time'))).isoformat(),
                    "ModificationTime": dotnet_ticks_to_datetime(correct_timestamp_if_needed(entry.get('modification_time'))).isoformat(),
                    "Permissions": f"0o{entry.get('permissions', 0):o}", "Status": entry.get('status'),
                    "OriginalFilename": entry.get('original_filename'),
                    "UncompressedSize": entry.get('uncompressed_size'), "Checksum": entry.get('checksum'),
                    "BlockFileIndex": entry.get('block_file_index'),
                    "ChunkGroupId": str(uuid.UUID(bytes=entry.get('chunk_group_id'))) if entry.get('chunk_group_id') else "N/A",
                    "ChunkIndex": entry.get('chunk_index'), "TotalChunks": entry.get('total_chunks')
                })
            with open(output_json_path, 'w', encoding='utf-8') as f:
                json.dump(export_list, f, indent=4, ensure_ascii=False)
            print(f"File index successfully exported.")
        except Exception as e: print(f"Error exporting file info: {e}")

    def find_files_in_container(self, pattern, use_regex=False, size_unit="KB"):
        print(f"\nSearching for pattern '{pattern}'...\n")
        try:
            files = self._get_logical_files()
            found = [e for e in files if (re.search(pattern, e.get('path',''), re.IGNORECASE) if use_regex else pattern.lower() in e.get('path','').lower())]
            print(f"Found {len(found)} matching entries:"); print(f"{'Path':<60} {'Size':<15} {'Creation Time'}"); print('-' * 100)
            for e in found:
                corrected_ticks = correct_timestamp_if_needed(e.get('creation_time', 0))
                dt = dotnet_ticks_to_datetime(corrected_ticks).astimezone()
                print(f"{e.get('path', ''):<60} {self._format_size(e.get('uncompressed_size', 0), size_unit):<15} {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e: print(f"Error finding files: {e}")

    def extract_single_file(self, file_path_in_archive, destination_dir):
        print(f"Attempting to extract '{file_path_in_archive}' to '{destination_dir}'...")
        try:
            chunks = [e for e in self._get_file_index() if e.get('path') == file_path_in_archive]
            if not chunks: return print(f"Error: File '{file_path_in_archive}' not found.")
            
            first_chunk = chunks[0]
            if first_chunk.get('type') == 'directory':
                dest_path = os.path.join(destination_dir, first_chunk['path'])
                os.makedirs(dest_path, exist_ok=True)
                print(f"Successfully created directory: {dest_path}")
                return

            self.reader._extract_file_from_chunks(chunks, destination_dir)
            print(f"\nSuccessfully extracted '{file_path_in_archive}'.")
        except Exception as e: print(f"Error extracting single file: {e}")

    def _format_size(self, size, unit):
        if size is None: return "N/A"
        unit = unit.upper()
        if unit == 'TB': return f"{size / (1024**4):.2f} TB"
        if unit == 'GB': return f"{size / (1024**3):.2f} GB"
        if unit == 'MB': return f"{size / (1024**2):.2f} MB"
        if unit == 'KB': return f"{size / 1024:.2f} KB"
        return f"{size} B"

# ===================================================================================
# 6. MAIN PROGRAM (Command Line Interface)
# ===================================================================================

def show_full_help(parser):
    print("G3FC Archiver Tool"); print(f"Usage: {os.path.basename(sys.argv[0])} <command> [options] [arguments...]")
    print("\nCommands:")
    sp_actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    for sp_action in sp_actions:
        for choice, subparser in sp_action.choices.items():
            print(f"  {choice:<18}{subparser.description}")
    
    print("\n--- Options for 'create' ---")
    print("  Usage: create -o <path> [options] [input_paths...]")
    print("  -o, --output <path>         Required. Path for the output .g3fc file.")
    print("  -p, --password <password>   Optional. Encrypt the archive with a password.")
    print("  -cl, --compression-level    Optional. ZSTD level (1-22). Default: 6.")
    print("  -gc, --global-compression   Optional. Use global compression. Default: false.")
    print("  -fl, --fec-level <%>        Optional. Forward Error Correction level (0-50).")
    print("  --split <size>              Optional. Split data into blocks of specified size (e.g., 100MB, 2GB).")

    print("\n--- Options for 'extract' ---")
    print("  Usage: extract <archive_path> -o <dir_path> [options]")
    print("  -o, --output <dir_path>     Required. Destination directory.")
    print("  -p, --password <password>   Optional. Password for encrypted archives.")

    print("\n--- Options for 'list' ---")
    print("  Usage: list <archive_path> [options]")
    print("  -p, --password <password>   Optional. Password for encrypted archives.")
    print("  --details                   Optional. Show detailed info (permissions, timestamp, checksum).")
    print("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.")

    print("\n--- Options for 'info' ---")
    print("  Usage: info <archive_path> -o <json_path> [options]")
    print("  -o, --output <json_path>    Required. Path to save the output JSON file.")
    print("  -p, --password <password>   Optional. Password for encrypted archives.")

    print("\n--- Options for 'find' ---")
    print("  Usage: find <archive_path> <pattern> [options]")
    print("  -p, --password <password>   Optional. Password for encrypted archives.")
    print("  --regex                     Optional. Treat the pattern as a regular expression.")
    print("  --unit <B|KB|MB|GB|TB>      Optional. Unit for file sizes. Default: KB.")
    
    print("\n--- Options for 'extract-single' ---")
    print("  Usage: extract-single <archive_path> <file_in_archive> -o <dir_path> [options]")
    print("  -o, --output <dir_path>     Required. Destination directory.")
    print("  -p, --password <password>   Optional. Password for encrypted archives.")

    print("\nExamples:")
    print("  g3fc.py create -o my.g3fc -p pass C:\\file.txt")
    print("  g3fc.py list my.g3fc --details")
    print("  g3fc.py extract-single my.g3fc \"file.txt\" -o C:\\extracted")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command")
    
    p_create = subparsers.add_parser("create", aliases=['c'], description="Create a new G3FC archive.", add_help=False)
    p_create.add_argument("input_paths", nargs='+'); p_create.add_argument("-o", "--output", required=True); p_create.add_argument("-p", "--password"); p_create.add_argument("-cl", "--compression-level", type=int, default=6); p_create.add_argument("-gc", "--global-compression", action="store_true"); p_create.add_argument("-fl", "--fec-level", type=int, default=0); p_create.add_argument("--split")

    p_extract = subparsers.add_parser("extract", aliases=['x'], description="Extract all files from a G3FC archive.", add_help=False)
    p_extract.add_argument("archive_path"); p_extract.add_argument("-o", "--output", required=True); p_extract.add_argument("-p", "--password")

    p_list = subparsers.add_parser("list", aliases=['l'], description="List files and directories in an archive.", add_help=False)
    p_list.add_argument("archive_path"); p_list.add_argument("-p", "--password"); p_list.add_argument("--details", action="store_true"); p_list.add_argument("--unit", default="KB")

    p_info = subparsers.add_parser("info", aliases=['i'], description="Export archive's metadata to a JSON file.", add_help=False)
    p_info.add_argument("archive_path"); p_info.add_argument("-o", "--output", required=True); p_info.add_argument("-p", "--password")

    p_find = subparsers.add_parser("find", aliases=['f'], description="Find a file within an archive.", add_help=False)
    p_find.add_argument("archive_path"); p_find.add_argument("pattern"); p_find.add_argument("-p", "--password"); p_find.add_argument("--regex", action="store_true"); p_find.add_argument("--unit", default="KB")

    p_extract_single = subparsers.add_parser("extract-single", aliases=['xs'], description="Extract a single file/directory.", add_help=False)
    p_extract_single.add_argument("archive_path"); p_extract_single.add_argument("file_in_archive"); p_extract_single.add_argument("-o", "--output", required=True); p_extract_single.add_argument("-p", "--password")

    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv: return show_full_help(parser)
    args = parser.parse_args()

    try:
        if args.command in ["create", "c"]:
            output_dir = os.path.dirname(args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            config = {'compression_level': args.compression_level, 'global_compression': args.global_compression, 'encryption_mode': 1 if args.password else 0, 'read_password': args.password or "", 'kdf_iterations': 100000, 'fec_level': args.fec_level, 'split_size': parse_split_size(args.split)}
            files_to_process = []
            for path in args.input_paths:
                if os.path.isfile(path): files_to_process.append((path, os.path.basename(path)))
                elif os.path.isdir(path):
                    base_dir = os.path.abspath(os.path.join(path, os.pardir))
                    for root, _, files in os.walk(path):
                        for file in files: files_to_process.append((os.path.join(root, file), os.path.relpath(os.path.join(root, file), base_dir)))
            G3FCWriter(config).create_g3fc_archive(args.output, files_to_process)
        
        else: # Commands that read an archive
            if not os.path.exists(args.archive_path): raise FileNotFoundError(f"Input archive not found: {args.archive_path}")
            password = args.password
            if not password:
                header_bytes = open(args.archive_path, 'rb').read(Constants.HEADER_SIZE)
                header_info = struct.unpack_from("<B", header_bytes, 126)[0]
                if header_info > 0: password = getpass.getpass("Password required: ")

            reader = G3FCReader(args.archive_path, password or "")
            commands = G3FCCommands(reader)

            if args.command in ["extract", "x"]:
                os.makedirs(args.output, exist_ok=True)
                print("Extracting all files...")
                logical_files = commands._get_logical_files()
                for logical_file in logical_files:
                    commands.extract_single_file(logical_file['path'], args.output)

            elif args.command in ["list", "l"]:
                commands.list_files_in_container(args.unit, args.details)
            elif args.command in ["info", "i"]:
                commands.export_info(args.output)
            elif args.command in ["find", "f"]:
                commands.find_files_in_container(args.pattern, args.regex, args.unit)
            elif args.command in ["extract-single", "xs"]:
                os.makedirs(args.output, exist_ok=True)
                commands.extract_single_file(args.file_in_archive, args.output)

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        # import traceback; traceback.print_exc() # Uncomment for debugging
        sys.exit(1)

if __name__ == "__main__":
    main()
