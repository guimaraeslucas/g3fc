// G3FC Archiver Tool - Rust FFI Library Version
//
// @author  Lucas Guimarães - G3Pix <https://github.com/guimaraeslucas/>
// @license GNU General Public License v2.0
// @version 1.0.0
//
// This version is refactored to be a dynamic library (`.so`, `.dll`)
// consumable by other languages via a C Foreign Function Interface (FFI),
// specifically optimized for PHP-FFI.

// Silence clippy warnings about missing safety documentation in FFI functions.
#![allow(clippy::missing_safety_doc)]

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use crc32fast::Hasher;
use lazy_static::lazy_static;
use pbkdf2::pbkdf2_hmac;
use reed_solomon_erasure::galois_8::Field as ReedSolomonField;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom, BufReader};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use uuid::Uuid;

// ===================================================================================
// FFI-SAFE ERROR HANDLING
// ===================================================================================

lazy_static! {
    static ref LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
}

/// Updates the last error message, to be retrieved by `g3fc_last_error_message`.
fn update_last_error(e: anyhow::Error) {
    let mut guard = LAST_ERROR.lock().unwrap();
    *guard = Some(e.to_string());
}

// ===================================================================================
// FFI-SAFE MEMORY MANAGEMENT
// ===================================================================================

/// In PHP-FFI, you would call this function like so:
///
/// ```php
/// // $ffi is the FFI object instance
/// // $resultPtr is a pointer returned by a g3fc_* function
/// $ffi->g3fc_free_string($resultPtr);
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

/// In PHP-FFI, you would call this function to get the last error details:
///
/// ```php
/// // cdef: char* g3fc_last_error_message();
///
/// $errorPtr = $ffi->g3fc_last_error_message();
/// if ($errorPtr !== null) {
///     $errorMessage = FFI::string($errorPtr);
///     echo "An error occurred: " . $errorMessage;
///     $ffi->g3fc_free_string($errorPtr); // Don't forget to free the error string
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_last_error_message() -> *mut c_char {
    let mut guard = LAST_ERROR.lock().unwrap();
    if let Some(err_msg) = guard.take() {
        match CString::new(err_msg) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(), // Should not happen
        }
    } else {
        std::ptr::null_mut()
    }
}

// ===================================================================================
// 1. DATA STRUCTURES (Unchanged, but now with some FFI-specific additions)
// ===================================================================================

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct MainHeader {
    magic_number: [u8; 4],
    format_version_major: u16,
    format_version_minor: u16,
    container_uuid: [u8; 16],
    creation_timestamp: i64,
    modification_timestamp: i64,
    edit_version: u32,
    creating_system: [u8; 32],
    software_version: [u8; 32],
    file_index_offset: u64,
    file_index_length: u64,
    file_index_compression: u8,
    global_compression: u8,
    encryption_mode: u8,
    read_salt: [u8; 64],
    write_salt: [u8; 64],
    kdf_iterations: u32,
    fec_scheme: u8,
    fec_level: u8,
    fec_data_offset: u64,
    fec_data_length: u64,
    header_checksum: u32,
    reserved: [u8; 50],
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct Footer {
    main_index_offset: u64,
    main_index_length: u64,
    metadata_fec_block_offset: u64,
    metadata_fec_block_length: u64,
    footer_checksum: u32,
    footer_magic: [u8; 4],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(with = "serde_bytes")]
    uuid: Vec<u8>,
    creation_time: i64,
    modification_time: i64,
    permissions: u16,
    #[serde(default)]
    status: u8,
    original_filename: String,
    uncompressed_size: u64,
    checksum: u32,
    data_offset: u64,
    data_size: u64,
    compression: u8,
    block_file_index: u32,
    #[serde(with = "serde_bytes")]
    chunk_group_id: Vec<u8>,
    chunk_index: u32,
    total_chunks: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEntryJsonExport {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Type")]
    entry_type: String,
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "CreationTime")]
    creation_time: String,
    #[serde(rename = "ModificationTime")]
    modification_time: String,
    #[serde(rename = "Permissions")]
    permissions: String,
    #[serde(rename = "Status")]
    status: u8,
    #[serde(rename = "OriginalFilename")]
    original_filename: String,
    #[serde(rename = "UncompressedSize")]
    uncompressed_size: u64,
    #[serde(rename = "Checksum")]
    checksum: u32,
    #[serde(rename = "BlockFileIndex")]
    block_file_index: u32,
    #[serde(rename = "ChunkGroupId")]
    chunk_group_id: String,
    #[serde(rename = "ChunkIndex")]
    chunk_index: u32,
    #[serde(rename = "TotalChunks")]
    total_chunks: u32,
}

// Struct for FFI arguments, passed as JSON
#[derive(Deserialize, Debug)]
struct FfiCreateArgs {
    input_paths: Vec<PathBuf>,
    output: PathBuf,
    password: Option<String>,
    #[serde(default = "default_compression_level")]
    compression_level: u8,
    #[serde(default)]
    global_compression: bool,
    #[serde(default)]
    fec_level: u8,
    split: Option<String>,
}
fn default_compression_level() -> u8 { 6 }

impl MainHeader {
    fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut header = Self {
            magic_number: [0; 4], format_version_major: 0, format_version_minor: 0,
            container_uuid: [0; 16], creation_timestamp: 0, modification_timestamp: 0,
            edit_version: 0, creating_system: [0; 32], software_version: [0; 32],
            file_index_offset: 0, file_index_length: 0, file_index_compression: 0,
            global_compression: 0, encryption_mode: 0, read_salt: [0; 64],
            write_salt: [0; 64], kdf_iterations: 0, fec_scheme: 0, fec_level: 0,
            fec_data_offset: 0, fec_data_length: 0, header_checksum: 0, reserved: [0; 50],
        };
        let mut rdr = BufReader::new(reader);
        rdr.read_exact(&mut header.magic_number)?;
        header.format_version_major = rdr.read_u16::<LittleEndian>()?;
        header.format_version_minor = rdr.read_u16::<LittleEndian>()?;
        rdr.read_exact(&mut header.container_uuid)?;
        header.creation_timestamp = rdr.read_i64::<LittleEndian>()?;
        header.modification_timestamp = rdr.read_i64::<LittleEndian>()?;
        header.edit_version = rdr.read_u32::<LittleEndian>()?;
        rdr.read_exact(&mut header.creating_system)?;
        rdr.read_exact(&mut header.software_version)?;
        header.file_index_offset = rdr.read_u64::<LittleEndian>()?;
        header.file_index_length = rdr.read_u64::<LittleEndian>()?;
        header.file_index_compression = rdr.read_u8()?;
        header.global_compression = rdr.read_u8()?;
        header.encryption_mode = rdr.read_u8()?;
        rdr.read_exact(&mut header.read_salt)?;
        rdr.read_exact(&mut header.write_salt)?;
        header.kdf_iterations = rdr.read_u32::<LittleEndian>()?;
        header.fec_scheme = rdr.read_u8()?;
        header.fec_level = rdr.read_u8()?;
        header.fec_data_offset = rdr.read_u64::<LittleEndian>()?;
        header.fec_data_length = rdr.read_u64::<LittleEndian>()?;
        header.header_checksum = rdr.read_u32::<LittleEndian>()?;
        rdr.read_exact(&mut header.reserved)?;
        Ok(header)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(constants::HEADER_SIZE as usize);
        buffer.write_all(&self.magic_number)?;
        buffer.write_u16::<LittleEndian>(self.format_version_major)?;
        buffer.write_u16::<LittleEndian>(self.format_version_minor)?;
        buffer.write_all(&self.container_uuid)?;
        buffer.write_i64::<LittleEndian>(self.creation_timestamp)?;
        buffer.write_i64::<LittleEndian>(self.modification_timestamp)?;
        buffer.write_u32::<LittleEndian>(self.edit_version)?;
        buffer.write_all(&self.creating_system)?;
        buffer.write_all(&self.software_version)?;
        buffer.write_u64::<LittleEndian>(self.file_index_offset)?;
        buffer.write_u64::<LittleEndian>(self.file_index_length)?;
        buffer.write_u8(self.file_index_compression)?;
        buffer.write_u8(self.global_compression)?;
        buffer.write_u8(self.encryption_mode)?;
        buffer.write_all(&self.read_salt)?;
        buffer.write_all(&self.write_salt)?;
        buffer.write_u32::<LittleEndian>(self.kdf_iterations)?;
        buffer.write_u8(self.fec_scheme)?;
        buffer.write_u8(self.fec_level)?;
        buffer.write_u64::<LittleEndian>(self.fec_data_offset)?;
        buffer.write_u64::<LittleEndian>(self.fec_data_length)?;
        buffer.write_u32::<LittleEndian>(self.header_checksum)?;
        buffer.write_all(&self.reserved)?;
        Ok(buffer)
    }
}

impl Footer {
     fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            main_index_offset: reader.read_u64::<LittleEndian>()?,
            main_index_length: reader.read_u64::<LittleEndian>()?,
            metadata_fec_block_offset: reader.read_u64::<LittleEndian>()?,
            metadata_fec_block_length: reader.read_u64::<LittleEndian>()?,
            footer_checksum: reader.read_u32::<LittleEndian>()?,
            footer_magic: { let mut buf = [0; 4]; reader.read_exact(&mut buf)?; buf },
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(constants::FOOTER_SIZE as usize);
        buffer.write_u64::<LittleEndian>(self.main_index_offset)?;
        buffer.write_u64::<LittleEndian>(self.main_index_length)?;
        buffer.write_u64::<LittleEndian>(self.metadata_fec_block_offset)?;
        buffer.write_u64::<LittleEndian>(self.metadata_fec_block_length)?;
        buffer.write_u32::<LittleEndian>(self.footer_checksum)?;
        buffer.write_all(&self.footer_magic)?;
        Ok(buffer)
    }
}


// ===================================================================================
// 2. CONSTANTS & 3. HELPERS (Mostly unchanged)
// ===================================================================================
mod constants {
    pub const MAGIC_NUMBER: &[u8; 4] = b"G3FC";
    pub const FOOTER_MAGIC: &[u8; 4] = b"G3CE";
    pub const HEADER_SIZE: u64 = 331;
    pub const FOOTER_SIZE: u64 = 40;
    pub const CREATING_SYSTEM: &str = "G3Pix Rust G3FC Lib"; // Lib name
    pub const SOFTWARE_VERSION: &str = "1.1.3";
    pub const MAX_FEC_LIB_SHARDS: usize = 255;
    pub const MIN_FEC_SHARDS: usize = 1;
    pub const MAX_FEC_SHARDS: usize = 254;
    pub const AES_NONCE_SIZE: usize = 12;
    pub const AES_TAG_SIZE: usize = 16;
    pub const DOTNET_EPOCH_TICKS: i64 = 621_355_968_000_000_000;
}

mod helpers {
    use super::*;
    use aes_gcm::aead::{Aead, AeadCore, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    pub fn crc32_compute(data: &[u8]) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    pub fn get_net_ticks_now() -> i64 {
        let now = Utc::now();
        let unix_nanos = now.timestamp_nanos_opt().unwrap_or(0);
        let unix_ticks = unix_nanos / 100;
        constants::DOTNET_EPOCH_TICKS + unix_ticks
    }
    
    pub fn system_time_to_net_ticks(sys_time: std::time::SystemTime) -> Result<i64> {
        let unix_time = sys_time.duration_since(std::time::UNIX_EPOCH)?;
        let unix_ticks = unix_time.as_nanos() as i64 / 100;
        Ok(constants::DOTNET_EPOCH_TICKS + unix_ticks)
    }

    pub fn net_ticks_to_datetime(ticks: i64) -> DateTime<Utc> {
        let unix_ticks = ticks - constants::DOTNET_EPOCH_TICKS;
        let unix_nanos = unix_ticks * 100;
        Utc.timestamp_nanos(unix_nanos)
    }

    pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        key
    }
    
    pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
        let ciphertext_and_tag = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        let ciphertext_len = ciphertext_and_tag.len() - constants::AES_TAG_SIZE;
        let ciphertext = &ciphertext_and_tag[..ciphertext_len];
        let tag = &ciphertext_and_tag[ciphertext_len..];
        let mut payload = Vec::with_capacity(constants::AES_NONCE_SIZE + constants::AES_TAG_SIZE + ciphertext.len());
        payload.extend_from_slice(nonce.as_slice());
        payload.extend_from_slice(tag);
        payload.extend_from_slice(ciphertext);
        Ok(payload)
    }

    pub fn decrypt_aes_gcm(payload: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        if payload.len() < constants::AES_NONCE_SIZE + constants::AES_TAG_SIZE {
            bail!("Invalid encrypted payload: too short.");
        }
        let cipher = Aes256Gcm::new(key.into());
        let nonce_bytes = &payload[..constants::AES_NONCE_SIZE];
        let tag = &payload[constants::AES_NONCE_SIZE..constants::AES_NONCE_SIZE + constants::AES_TAG_SIZE];
        let ciphertext = &payload[constants::AES_NONCE_SIZE + constants::AES_TAG_SIZE..];
        let nonce = Nonce::from_slice(nonce_bytes);
        let mut ciphertext_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ciphertext_and_tag.extend_from_slice(ciphertext);
        ciphertext_and_tag.extend_from_slice(tag);
        cipher.decrypt(nonce, ciphertext_and_tag.as_ref())
            .map_err(|_| anyhow!("Decryption failed: password may be incorrect or data is corrupt."))
    }

    pub fn create_fec(data: &[u8], fec_level: u8) -> Result<Vec<u8>> {
        if data.is_empty() || fec_level == 0 {
            return Ok(Vec::new());
        }
        let parity_shards_count = ((fec_level as usize * (constants::MAX_FEC_LIB_SHARDS - 1)) / 100)
            .max(constants::MIN_FEC_SHARDS)
            .min(constants::MAX_FEC_SHARDS);
        let data_shards_count = constants::MAX_FEC_LIB_SHARDS - parity_shards_count;
        let rs: reed_solomon_erasure::ReedSolomon<ReedSolomonField> = reed_solomon_erasure::ReedSolomon::new(data_shards_count, parity_shards_count)?;
        
        let shard_size = (data.len() + data_shards_count - 1) / data_shards_count;
        let mut shards = vec![vec![0; shard_size]; data_shards_count + parity_shards_count];
        for (i, byte) in data.iter().enumerate() {
            shards[i / shard_size][i % shard_size] = *byte;
        }

        rs.encode(&mut shards)?;
        
        let mut parity_bytes = Vec::new();
        for shard in shards.iter().skip(data_shards_count) {
             parity_bytes.extend_from_slice(shard);
        }
        Ok(parity_bytes)
    }

    pub fn get_permissions(path: &Path) -> Result<u16> {
        let metadata = fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok((metadata.permissions().mode() & 0o777) as u16)
        }
        #[cfg(not(unix))]
        {
            if metadata.permissions().readonly() { Ok(0o444) } else { Ok(0o666) }
        }
    }

    pub fn set_permissions(path: &Path, perms: u16) -> Result<()> {
         #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(perms as u32))?;
        }
        #[cfg(not(unix))]
        {
            let mut current_perms = fs::metadata(path)?.permissions();
            current_perms.set_readonly((perms & 0o222) == 0);
            fs::set_permissions(path, current_perms)?;
        }
        Ok(())
    }

    pub fn parse_split_size(size_str: &str) -> Result<i64> {
        let upper = size_str.to_uppercase();
        let (num_str, multiplier) = if let Some(s) = upper.strip_suffix("GB") {
            (s, 1024 * 1024 * 1024)
        } else if let Some(s) = upper.strip_suffix("MB") {
            (s, 1024 * 1024)
        } else {
            bail!("Invalid size format. Use a number followed by MB or GB (e.g., 100MB)");
        };
        let size = i64::from_str(num_str.trim())?;
        Ok(size * multiplier)
    }
}

// ===================================================================================
// 4. ARCHIVE WRITER LOGIC (Refactored to take structs)
// ===================================================================================
mod writer {
    use super::*;
    use rand::RngCore;

    fn create_header(args: &FfiCreateArgs, read_salt: &[u8], write_salt: &[u8]) -> MainHeader {
        let ticks_now = helpers::get_net_ticks_now();
        let container_uuid = Uuid::new_v4();
        let mut creating_system = [0u8; 32];
        let sys_bytes = constants::CREATING_SYSTEM.as_bytes();
        creating_system[..sys_bytes.len()].copy_from_slice(sys_bytes);
        let mut software_version = [0u8; 32];
        let ver_bytes = constants::SOFTWARE_VERSION.as_bytes();
        software_version[..ver_bytes.len()].copy_from_slice(ver_bytes);
        let mut final_read_salt = [0u8; 64];
        final_read_salt[..read_salt.len()].copy_from_slice(read_salt);
        let mut final_write_salt = [0u8; 64];
        final_write_salt[..write_salt.len()].copy_from_slice(write_salt);

        MainHeader {
            magic_number: *constants::MAGIC_NUMBER,
            format_version_major: 1,
            format_version_minor: 0,
            container_uuid: *container_uuid.as_bytes(),
            creation_timestamp: ticks_now,
            modification_timestamp: ticks_now,
            edit_version: 1,
            creating_system,
            software_version,
            file_index_offset: 0,
            file_index_length: 0,
            file_index_compression: 1,
            global_compression: if args.global_compression { 1 } else { 0 },
            encryption_mode: if args.password.is_some() { 1 } else { 0 },
            read_salt: final_read_salt,
            write_salt: final_write_salt,
            kdf_iterations: 100_000,
            fec_scheme: if args.fec_level > 0 { 1 } else { 0 },
            fec_level: args.fec_level,
            fec_data_offset: 0,
            fec_data_length: 0,
            header_checksum: 0,
            reserved: [0; 50],
        }
    }

    pub fn create_archive(args: &FfiCreateArgs) -> Result<()> {
        if let Some(parent) = args.output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create output directory '{}'", parent.display()))?;
        }

        let mut files_to_process = Vec::new();
        for path_str in &args.input_paths {
            let path = Path::new(path_str);
            if !path.exists() {
                bail!("Input path '{}' does not exist.", path.display());
            }
            if path.is_file() {
                let rel_path = path.file_name().unwrap_or_default().into();
                files_to_process.push((path.to_path_buf(), rel_path));
            } else if path.is_dir() {
                let base_dir = path.parent().unwrap_or(path);
                for entry in walkdir::WalkDir::new(path).into_iter().filter_map(Result::ok) {
                    if entry.file_type().is_file() {
                         let rel_path = entry.path().strip_prefix(base_dir)?.to_path_buf();
                         files_to_process.push((entry.into_path(), rel_path));
                    }
                }
            }
        }
        
        if files_to_process.is_empty() {
             bail!("No valid files found in the provided input paths.");
        }
        
        let mut file_index = Vec::new();
        let mut data_block_stream = Vec::new();

        for (full_path, relative_path) in &files_to_process {
            let file_data = fs::read(full_path).with_context(|| format!("Failed to read file {}", full_path.display()))?;
            let metadata = fs::metadata(full_path)?;
            let mod_time = helpers::system_time_to_net_ticks(metadata.modified()?)?;
            let creation_time = metadata.created().ok().and_then(|t| helpers::system_time_to_net_ticks(t).ok()).unwrap_or(mod_time);

            let entry = FileEntry {
                path: relative_path.to_str().unwrap_or_default().replace('\\', "/"),
                entry_type: "file".to_string(),
                uuid: Uuid::new_v4().as_bytes().to_vec(),
                creation_time,
                modification_time: mod_time,
                permissions: helpers::get_permissions(full_path)?,
                status: 0,
                original_filename: full_path.file_name().unwrap_or_default().to_str().unwrap_or_default().to_string(),
                uncompressed_size: file_data.len() as u64,
                checksum: helpers::crc32_compute(&file_data),
                data_offset: data_block_stream.len() as u64,
                data_size: 0,
                compression: if args.global_compression { 0 } else { 1 },
                block_file_index: 0,
                chunk_group_id: Vec::new(),
                chunk_index: 0,
                total_chunks: 1,
            };

            let data_to_add = if args.global_compression {
                file_data
            } else {
                zstd::encode_all(&*file_data, args.compression_level as i32)?
            };
            
            let mut final_entry = entry;
            final_entry.data_size = data_to_add.len() as u64;
            data_block_stream.extend(&data_to_add);
            file_index.push(final_entry);
        }
        
        let mut rng = rand::thread_rng();
        let read_salt = if args.password.is_some() {
            let mut salt = [0u8; 64]; rng.fill_bytes(&mut salt); salt
        } else { [0u8; 64] };
        let write_salt = if args.password.is_some() {
            let mut salt = [0u8; 64]; rng.fill_bytes(&mut salt); salt
        } else { [0u8; 64] };
        let read_key = if let Some(password) = &args.password {
            Some(helpers::derive_key(password, &read_salt, 100_000))
        } else { None };

        if let Some(split_str) = &args.split {
             let split_size = helpers::parse_split_size(split_str)?;
             write_split_archive(args, file_index, &data_block_stream, read_key, &read_salt, &write_salt, split_size)?;
        } else {
             write_single_archive(args, file_index, &data_block_stream, read_key, &read_salt, &write_salt)?;
        }

        Ok(())
    }
    
    fn write_single_archive(args: &FfiCreateArgs, file_index: Vec<FileEntry>, data_block: &[u8], read_key: Option<[u8;32]>, read_salt: &[u8], write_salt: &[u8]) -> Result<()> {
        let mut data_block = data_block.to_vec();
        
        if args.global_compression {
            data_block = zstd::encode_all(&*data_block, args.compression_level as i32)?;
        }
        if let Some(key) = read_key {
            data_block = helpers::encrypt_aes_gcm(&data_block, &key)?;
        }

        let uncompressed_index_bytes = serde_cbor::to_vec(&file_index)?;
        let mut index_block = zstd::encode_all(&*uncompressed_index_bytes, 3)?;
        if let Some(key) = read_key {
            index_block = helpers::encrypt_aes_gcm(&index_block, &key)?;
        }

        let mut header = create_header(args, read_salt, write_salt);
        let mut current_offset = constants::HEADER_SIZE;
        header.file_index_offset = current_offset;
        header.file_index_length = index_block.len() as u64;
        current_offset += header.file_index_length;
        let data_block_offset = current_offset;
        current_offset += data_block.len() as u64;

        let data_fec_bytes = if header.fec_scheme == 1 {
            helpers::create_fec(&data_block, header.fec_level)?
        } else { Vec::new() };
        header.fec_data_offset = data_block_offset + data_block.len() as u64;
        header.fec_data_length = data_fec_bytes.len() as u64;
        current_offset += header.fec_data_length;

        let metadata_fec_bytes = if header.fec_scheme == 1 {
             header.header_checksum = 0;
             let temp_header_bytes = header.to_bytes()?;
             let metadata_to_protect = [temp_header_bytes, uncompressed_index_bytes].concat();
             helpers::create_fec(&metadata_to_protect, 10)?
        } else { Vec::new() };
        let metadata_fec_offset = current_offset;

        let mut footer = Footer {
            main_index_offset: header.file_index_offset,
            main_index_length: header.file_index_length,
            metadata_fec_block_offset: metadata_fec_offset,
            metadata_fec_block_length: metadata_fec_bytes.len() as u64,
            footer_checksum: 0,
            footer_magic: *constants::FOOTER_MAGIC,
        };
        let footer_bytes = footer.to_bytes()?;
        footer.footer_checksum = helpers::crc32_compute(&footer_bytes[..32]);

        header.modification_timestamp = helpers::get_net_ticks_now();
        let final_header_bytes = header.to_bytes()?;
        header.header_checksum = helpers::crc32_compute(&final_header_bytes[..277]);
        
        let mut out_file = File::create(&args.output)?;
        out_file.write_all(&header.to_bytes()?)?;
        out_file.write_all(&index_block)?;
        out_file.write_all(&data_block)?;
        out_file.write_all(&data_fec_bytes)?;
        out_file.write_all(&metadata_fec_bytes)?;
        out_file.write_all(&footer.to_bytes()?)?;
        
        Ok(())
    }
    
    fn write_split_archive(args: &FfiCreateArgs, original_file_index: Vec<FileEntry>, combined_data: &[u8], read_key: Option<[u8;32]>, read_salt: &[u8], write_salt: &[u8], split_size: i64) -> Result<()> {
        let mut final_file_index: Vec<FileEntry> = Vec::new();
        let mut block_index: u32 = 0;
        let mut current_block_data = Vec::with_capacity(split_size as usize);

        for entry in original_file_index {
            let entry_data = &combined_data[entry.data_offset as usize .. (entry.data_offset + entry.data_size) as usize];
            let chunk_group_id = Uuid::new_v4().as_bytes().to_vec();
            let mut entry_data_offset = 0;
            let mut chunk_idx = 0;
            let num_chunks = ((entry_data.len() as i64 + split_size - 1) / split_size).max(1) as u32;

            while entry_data_offset < entry_data.len() {
                if current_block_data.len() >= split_size as usize {
                    write_data_block(&args.output, block_index, &current_block_data, args, read_key)?;
                    block_index += 1;
                    current_block_data.clear();
                }

                let space_in_block = split_size as usize - current_block_data.len();
                let bytes_to_write = (entry_data.len() - entry_data_offset).min(space_in_block);
                let mut chunk_entry = entry.clone();
                chunk_entry.block_file_index = block_index;
                chunk_entry.data_offset = current_block_data.len() as u64;
                chunk_entry.data_size = bytes_to_write as u64;
                chunk_entry.chunk_group_id = chunk_group_id.clone();
                chunk_entry.chunk_index = chunk_idx;
                chunk_entry.total_chunks = num_chunks;
                final_file_index.push(chunk_entry);
                current_block_data.extend_from_slice(&entry_data[entry_data_offset..entry_data_offset + bytes_to_write]);
                entry_data_offset += bytes_to_write;
                chunk_idx += 1;
            }
        }
        
        if !current_block_data.is_empty() {
             write_data_block(&args.output, block_index, &current_block_data, args, read_key)?;
        }
        
        let uncompressed_index_bytes = serde_cbor::to_vec(&final_file_index)?;
        let mut index_block = zstd::encode_all(&*uncompressed_index_bytes, 3)?;
        if let Some(key) = read_key {
            index_block = helpers::encrypt_aes_gcm(&index_block, &key)?;
        }
        
        let mut header = create_header(args, read_salt, write_salt);
        header.file_index_offset = constants::HEADER_SIZE;
        header.file_index_length = index_block.len() as u64;
        header.fec_data_offset = 0;
        header.fec_data_length = 0;
        let current_offset = header.file_index_offset + header.file_index_length;

        let metadata_fec_bytes = if header.fec_scheme == 1 {
             header.header_checksum = 0;
             let temp_header_bytes = header.to_bytes()?;
             let metadata_to_protect = [temp_header_bytes, uncompressed_index_bytes].concat();
             helpers::create_fec(&metadata_to_protect, 10)?
        } else { Vec::new() };
        
        let mut footer = Footer {
            main_index_offset: header.file_index_offset,
            main_index_length: header.file_index_length,
            metadata_fec_block_offset: current_offset,
            metadata_fec_block_length: metadata_fec_bytes.len() as u64,
            footer_checksum: 0,
            footer_magic: *constants::FOOTER_MAGIC,
        };
        let footer_bytes = footer.to_bytes()?;
        footer.footer_checksum = helpers::crc32_compute(&footer_bytes[..32]);
        header.modification_timestamp = helpers::get_net_ticks_now();
        let final_header_bytes = header.to_bytes()?;
        header.header_checksum = helpers::crc32_compute(&final_header_bytes[..277]);
        
        let mut out_file = File::create(&args.output)?;
        out_file.write_all(&header.to_bytes()?)?;
        out_file.write_all(&index_block)?;
        out_file.write_all(&metadata_fec_bytes)?;
        out_file.write_all(&footer.to_bytes()?)?;

        Ok(())
    }

    fn write_data_block(base_path: &Path, index: u32, data: &[u8], args: &FfiCreateArgs, key: Option<[u8;32]>) -> Result<()> {
        let block_path_str = format!("{}{}", base_path.display(), index);
        
        let mut final_data = data.to_vec();
        if args.global_compression {
            final_data = zstd::encode_all(data, args.compression_level as i32)?;
        }
        if let Some(k) = key {
            final_data = helpers::encrypt_aes_gcm(&final_data, &k)?;
        }
        fs::write(block_path_str, final_data)?;
        Ok(())
    }
}

// ===================================================================================
// 5. ARCHIVE READER LOGIC (Refactored to take paths and return results)
// ===================================================================================
mod reader {
    use super::*;

    pub fn extract_archive(archive_path: &Path, dest_dir: &Path, password: Option<&str>) -> Result<()> {
        fs::create_dir_all(dest_dir)
                .with_context(|| format!("Failed to create output directory '{}'", dest_dir.display()))?;

        let (header, file_index) = read_archive_metadata(archive_path, password)?;
        
        let mut file_groups: HashMap<Vec<u8>, Vec<FileEntry>> = HashMap::new();
        for entry in file_index {
            let group_id = if !entry.chunk_group_id.is_empty() {
                entry.chunk_group_id.clone()
            } else { entry.uuid.clone() };
            file_groups.entry(group_id).or_default().push(entry);
        }
        
        let read_key = if header.encryption_mode > 0 {
            let password = password.ok_or_else(|| anyhow!("Password is required for this encrypted archive."))?;
            Some(helpers::derive_key(password, &header.read_salt, header.kdf_iterations))
        } else { None };
        
        let mut data_blocks_cache: HashMap<u32, Vec<u8>> = HashMap::new();
        for (_group_id, mut chunks) in file_groups {
            chunks.sort_by_key(|c| c.chunk_index);
            if let Err(e) = extract_file_from_chunks(archive_path, dest_dir, &chunks, &header, read_key, &mut data_blocks_cache) {
                // Return the first error encountered
                return Err(anyhow!("Failed extracting {}: {}", chunks[0].path, e));
            }
        }
        
        Ok(())
    }

    pub fn read_archive_metadata(path: &Path, password: Option<&str>) -> Result<(MainHeader, Vec<FileEntry>)> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::End(-(constants::FOOTER_SIZE as i64)))?;
        let footer = Footer::from_reader(&mut file)?;
        if &footer.footer_magic != constants::FOOTER_MAGIC {
            bail!("Invalid footer magic number. File may be corrupt or not a G3FC archive.");
        }
        file.seek(SeekFrom::Start(0))?;
        let header = MainHeader::from_reader(&mut file)?;
        if &header.magic_number != constants::MAGIC_NUMBER {
            bail!("Invalid header magic number.");
        }
        file.seek(SeekFrom::Start(header.file_index_offset))?;
        let mut index_block = vec![0; header.file_index_length as usize];
        file.read_exact(&mut index_block)?;
        
        if header.encryption_mode > 0 {
            let pass = password.ok_or_else(|| anyhow!("Password required but not provided."))?;
            let key = helpers::derive_key(pass, &header.read_salt, header.kdf_iterations);
            index_block = helpers::decrypt_aes_gcm(&index_block, &key)?;
        }
        if header.file_index_compression == 1 {
            index_block = zstd::decode_all(&*index_block)?;
        }
        let file_index: Vec<FileEntry> = serde_cbor::from_slice(&index_block)?;
        Ok((header, file_index))
    }

    pub fn extract_file_from_chunks(
        archive_path: &Path, dest_dir: &Path, chunks: &[FileEntry], header: &MainHeader,
        read_key: Option<[u8; 32]>, cache: &mut HashMap<u32, Vec<u8>>
    ) -> Result<()> {
        if chunks.is_empty() { return Ok(()); }
        
        let first_chunk = &chunks[0];
        
        // Removed interactive prompt for library use
        // The calling application should handle large file warnings.
        
        let is_split = header.fec_data_offset == 0 && header.fec_data_length == 0;
        let mut reassembled_data = Vec::with_capacity(first_chunk.uncompressed_size as usize);

        for chunk in chunks {
            let data_block = if let Some(block) = cache.get(&chunk.block_file_index) {
                block
            } else {
                let mut raw_block = if is_split {
                    let block_path_str = format!("{}{}", archive_path.display(), chunk.block_file_index);
                    fs::read(&block_path_str).with_context(|| format!("Data block not found: {}", block_path_str))?
                } else {
                    let mut file = File::open(archive_path)?;
                    let data_block_start = header.file_index_offset + header.file_index_length;
                    file.seek(SeekFrom::Start(data_block_start))?;
                    let mut block_data = vec![0; (header.fec_data_offset - data_block_start) as usize];
                    file.read_exact(&mut block_data)?;
                    block_data
                };
                if header.encryption_mode > 0 {
                    raw_block = helpers::decrypt_aes_gcm(&raw_block, &read_key.unwrap())?;
                }
                if header.global_compression == 1 {
                    raw_block = zstd::decode_all(&*raw_block)?;
                }
                cache.insert(chunk.block_file_index, raw_block);
                cache.get(&chunk.block_file_index).unwrap()
            };
            let chunk_data = &data_block[chunk.data_offset as usize .. (chunk.data_offset + chunk.data_size) as usize];
            reassembled_data.extend_from_slice(chunk_data);
        }
        
        if header.global_compression == 0 && first_chunk.compression == 1 {
            reassembled_data = zstd::decode_all(&*reassembled_data)?;
        }
        if helpers::crc32_compute(&reassembled_data) != first_chunk.checksum {
            bail!("Checksum mismatch for file {}", first_chunk.path);
        }

        let dest_dir_abs = dest_dir.canonicalize().with_context(|| format!("Could not get absolute path for '{}'", dest_dir.display()))?;
        let mut final_path_abs = dest_dir_abs.clone();
        let unsafe_path = first_chunk.path.replace('\\', &std::path::MAIN_SEPARATOR.to_string());
        for component in Path::new(&unsafe_path).components() {
            if let std::path::Component::Normal(part) = component {
                final_path_abs.push(part);
            }
        }
        if !final_path_abs.starts_with(&dest_dir_abs) {
            bail!("Path traversal attempt detected. Malicious path: '{}'", first_chunk.path);
        }
        if let Some(parent) = final_path_abs.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&final_path_abs, &reassembled_data)?;
        helpers::set_permissions(&final_path_abs, first_chunk.permissions)?;
        Ok(())
    }
}


// ===================================================================================
// 6. FFI-EXPORTED FUNCTIONS
// ===================================================================================

/// Creates an archive based on JSON-formatted arguments.
/// Returns 0 on success, -1 on error. Call `g3fc_last_error_message` for details.
///
/// In PHP-FFI:
/// ```php
/// // cdef: int32_t g3fc_create_archive(const char* json_args);
/// $args = [
///     'input_paths' => ['/path/to/file.txt', '/path/to/folder'],
///     'output' => '/path/to/new_archive.g3fc',
///     'password' => 'secret123',
///     'compression_level' => 10,
///     'global_compression' => true,
///     'fec_level' => 10,
///     'split' => '100MB'
/// ];
/// $jsonArgs = json_encode($args);
/// $status = $ffi->g3fc_create_archive($jsonArgs);
/// if ($status !== 0) { /* handle error */ }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_create_archive(json_args: *const c_char) -> i32 {
    let result = (|| -> Result<()> {
        let args_str = unsafe { CStr::from_ptr(json_args) }.to_str()?;
        let args: FfiCreateArgs = serde_json::from_str(args_str)
            .with_context(|| "Failed to deserialize JSON arguments")?;
        writer::create_archive(&args)?;
        Ok(())
    })();

    match result {
        Ok(_) => 0,
        Err(e) => {
            update_last_error(e);
            -1
        }
    }
}


/// Extracts an entire archive to a specified directory.
/// Returns 0 on success, -1 on error.
///
/// In PHP-FFI:
/// ```php
/// // cdef: int32_t g3fc_extract_archive(const char* archive_path, const char* output_dir, const char* password);
/// $status = $ffi->g3fc_extract_archive('/path/to/archive.g3fc', '/path/to/extract_to', 'secret123');
/// if ($status !== 0) { /* handle error */ }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_extract_archive(archive_path: *const c_char, output_dir: *const c_char, password: *const c_char) -> i32 {
    let result = (|| -> Result<()> {
        let archive_p = PathBuf::from(unsafe { CStr::from_ptr(archive_path) }.to_str()?);
        let output_d = PathBuf::from(unsafe { CStr::from_ptr(output_dir) }.to_str()?);
        let pass = if password.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(password) }.to_str()?)
        };
        
        reader::extract_archive(&archive_p, &output_d, pass)?;
        Ok(())
    })();

    match result {
        Ok(_) => 0,
        Err(e) => {
            update_last_error(e);
            -1
        }
    }
}


/// Lists files in an archive and returns them as a JSON string.
/// Returns a pointer to the string on success, NULL on error. The string must be freed with `g3fc_free_string`.
///
/// In PHP-FFI:
/// ```php
/// // cdef: char* g3fc_list_files(const char* archive_path, const char* password);
/// $resultPtr = $ffi->g3fc_list_files('/path/to/archive.g3fc', 'secret123');
/// if ($resultPtr !== null) {
///     $json = FFI::string($resultPtr);
///     $files = json_decode($json, true);
///     $ffi->g3fc_free_string($resultPtr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_list_files(archive_path: *const c_char, password: *const c_char) -> *mut c_char {
    let result = (|| -> Result<String> {
        let path = PathBuf::from(unsafe { CStr::from_ptr(archive_path) }.to_str()?);
        let pass = if password.is_null() { None } else { Some(unsafe { CStr::from_ptr(password) }.to_str()?) };

        let (_header, file_index) = reader::read_archive_metadata(&path, pass)?;
        
        // Use a map to only show one entry for each logical file (in case of chunking)
        let mut logical_files = HashMap::new();
        for entry in file_index {
             logical_files.entry(entry.path.clone()).or_insert(entry);
        }
        
        let mut sorted_files: Vec<_> = logical_files.values().cloned().collect();
        sorted_files.sort_by(|a, b| a.path.cmp(&b.path));
        
        Ok(serde_json::to_string_pretty(&sorted_files)?)
    })();

    match result {
        Ok(json_string) => CString::new(json_string).unwrap().into_raw(),
        Err(e) => {
            update_last_error(e);
            std::ptr::null_mut()
        }
    }
}


/// Exports the full, detailed file metadata index to a JSON file.
/// This is equivalent to the original `info` command.
/// Returns a pointer to the JSON string on success, NULL on error. The string must be freed.
///
/// In PHP-FFI:
/// ```php
/// // cdef: char* g3fc_info_export_json(const char* archive_path, const char* password);
/// $resultPtr = $ffi->g3fc_info_export_json('/path/to/archive.g3fc', 'secret123');
/// if ($resultPtr !== null) {
///     // process json...
///     $ffi->g3fc_free_string($resultPtr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_info_export_json(archive_path: *const c_char, password: *const c_char) -> *mut c_char {
    let result = (|| -> Result<String> {
        let path = PathBuf::from(unsafe { CStr::from_ptr(archive_path) }.to_str()?);
        let pass = if password.is_null() { None } else { Some(unsafe { CStr::from_ptr(password) }.to_str()?) };

        let (_header, file_index) = reader::read_archive_metadata(&path, pass)?;
        
        let export_list: Vec<FileEntryJsonExport> = file_index.into_iter().map(|entry| {
            FileEntryJsonExport {
                path: entry.path,
                entry_type: entry.entry_type,
                uuid: Uuid::from_slice(&entry.uuid).unwrap_or_default().to_string(),
                creation_time: helpers::net_ticks_to_datetime(entry.creation_time).to_rfc3339(),
                modification_time: helpers::net_ticks_to_datetime(entry.modification_time).to_rfc3339(),
                permissions: format!("0o{:o}", entry.permissions),
                status: entry.status,
                original_filename: entry.original_filename,
                uncompressed_size: entry.uncompressed_size,
                checksum: entry.checksum,
                block_file_index: entry.block_file_index,
                chunk_group_id: if entry.chunk_group_id.len() == 16 { Uuid::from_slice(&entry.chunk_group_id).unwrap_or_default().to_string() } else { "N/A".to_string() },
                chunk_index: entry.chunk_index,
                total_chunks: entry.total_chunks,
            }
        }).collect();

        Ok(serde_json::to_string_pretty(&export_list)?)
    })();
    
    match result {
        Ok(json_string) => CString::new(json_string).unwrap().into_raw(),
        Err(e) => {
            update_last_error(e);
            std::ptr::null_mut()
        }
    }
}


/// Finds files within an archive by a pattern (substring or regex).
/// Returns a JSON string of matching files on success, NULL on error. The string must be freed.
///
/// In PHP-FFI:
/// ```php
/// // cdef: char* g3fc_find_files(const char* archive_path, const char* pattern, const char* password, bool is_regex);
/// $resultPtr = $ffi->g3fc_find_files('/path/to/archive.g3fc', 'report.*\.pdf', 'secret123', true);
/// if ($resultPtr !== null) {
///     // process json...
///     $ffi->g3fc_free_string($resultPtr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_find_files(archive_path: *const c_char, pattern: *const c_char, password: *const c_char, is_regex: bool) -> *mut c_char {
     let result = (|| -> Result<String> {
        let path = PathBuf::from(unsafe { CStr::from_ptr(archive_path) }.to_str()?);
        let patt_str = unsafe { CStr::from_ptr(pattern) }.to_str()?;
        let pass = if password.is_null() { None } else { Some(unsafe { CStr::from_ptr(password) }.to_str()?) };

        let (_header, file_index) = reader::read_archive_metadata(&path, pass)?;
        
        let mut logical_files = HashMap::new();
        for entry in file_index {
            logical_files.entry(entry.path.clone()).or_insert(entry);
        }
        let files_to_search: Vec<_> = logical_files.values().cloned().collect();

        let found_files: Vec<_> = if is_regex {
            let re = Regex::new(patt_str).with_context(|| "Invalid regex pattern")?;
            files_to_search.into_iter().filter(|e| re.is_match(&e.path)).collect()
        } else {
            let lower_pattern = patt_str.to_lowercase();
            files_to_search.into_iter().filter(|e| e.path.to_lowercase().contains(&lower_pattern)).collect()
        };
        
        Ok(serde_json::to_string_pretty(&found_files)?)
    })();
    
    match result {
        Ok(json_string) => CString::new(json_string).unwrap().into_raw(),
        Err(e) => {
            update_last_error(e);
            std::ptr::null_mut()
        }
    }
}


/// Extracts a single file from an archive to a specified directory.
/// Returns 0 on success, -1 on error.
///
/// In PHP-FFI:
/// ```php
/// // cdef: int32_t g3fc_extract_single(const char* archive_path, const char* file_in_archive, const char* output_dir, const char* password);
/// $status = $ffi->g3fc_extract_single('/path/to/archive.g3fc', 'documents/report.docx', '/path/to/extract_to', 'secret123');
/// if ($status !== 0) { /* handle error */ }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn g3fc_extract_single(archive_path: *const c_char, file_in_archive: *const c_char, output_dir: *const c_char, password: *const c_char) -> i32 {
    let result = (|| -> Result<()> {
        let archive_p = PathBuf::from(unsafe { CStr::from_ptr(archive_path) }.to_str()?);
        let file_in_archive_str = unsafe { CStr::from_ptr(file_in_archive) }.to_str()?;
        let output_d = PathBuf::from(unsafe { CStr::from_ptr(output_dir) }.to_str()?);
        let pass = if password.is_null() { None } else { Some(unsafe { CStr::from_ptr(password) }.to_str()?) };

        fs::create_dir_all(&output_d)
            .with_context(|| format!("Failed to create output directory '{}'", output_d.display()))?;

        let (header, file_index) = reader::read_archive_metadata(&archive_p, pass)?;

        let chunks_to_extract: Vec<FileEntry> = file_index
            .into_iter()
            .filter(|entry| entry.path == file_in_archive_str)
            .collect();

        if chunks_to_extract.is_empty() {
            bail!("File '{}' not found in the archive.", file_in_archive_str);
        }
        
        let first_chunk = &chunks_to_extract[0];
        if first_chunk.entry_type == "directory" {
            let dir_path = output_d.join(&first_chunk.path);
            fs::create_dir_all(&dir_path)?;
            return Ok(());
        }

        let read_key = if header.encryption_mode > 0 {
            let p = pass.ok_or_else(|| anyhow!("Password is required for this encrypted archive."))?;
            Some(helpers::derive_key(p, &header.read_salt, header.kdf_iterations))
        } else { None };
        
        let mut data_blocks_cache: HashMap<u32, Vec<u8>> = HashMap::new();
        
        reader::extract_file_from_chunks(&archive_p, &output_d, &chunks_to_extract, &header, read_key, &mut data_blocks_cache)?;
        
        Ok(())
    })();
    
    match result {
        Ok(_) => 0,
        Err(e) => {
            update_last_error(e);
            -1
        }
    }
}
