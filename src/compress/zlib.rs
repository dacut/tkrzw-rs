use {super::Compressor, log::error, std::cmp::min};

use {
    flate2::{
        read::{DeflateDecoder, GzDecoder, ZlibDecoder},
        write::{DeflateEncoder, GzEncoder, ZlibEncoder},
        Compression,
    },
    std::io::{Read, Write},
};

/// Zlib compression metadata modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZlibMetadataMode {
    /// Without any checksum.
    None,

    /// With Adler-32 checksum, compatible with deflate.
    Adler32,

    /// With CRC-32 checksum, compatible with gzip.
    Crc32,
}

#[derive(Debug, Clone)]
pub struct ZlibCompressor {
    /// The compression level.
    level: u32,

    /// The metadata mode.
    metadata_mode: ZlibMetadataMode,
}

impl ZlibCompressor {
    pub fn new(level: u32, metadata_mode: ZlibMetadataMode) -> Self {
        let level = min(level, 9);
        Self {
            level,
            metadata_mode,
        }
    }
}

impl Default for ZlibCompressor {
    fn default() -> Self {
        Self::new(6, ZlibMetadataMode::None)
    }
}

#[cfg(feature = "zlib")]
impl Compressor for ZlibCompressor {
    fn is_supported() -> bool {
        true
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        let compression = Compression::new(self.level);
        let mut result = Vec::with_capacity(buf.len() / 2);

        match self.metadata_mode {
            ZlibMetadataMode::None => {
                let mut encoder = DeflateEncoder::new(&mut result, compression);
                if let Err(e) = encoder.write_all(buf) {
                    error!("Failed to compress data: {}", e);
                    return None;
                }

                if let Err(e) = encoder.flush() {
                    error!("Failed to finish compression: {}", e);
                    return None;
                }
            }
            ZlibMetadataMode::Adler32 => {
                let mut encoder = ZlibEncoder::new(&mut result, compression);
                if let Err(e) = encoder.write_all(buf) {
                    error!("Failed to compress data: {}", e);
                    return None;
                }

                if let Err(e) = encoder.flush() {
                    error!("Failed to finish compression: {}", e);
                    return None;
                }
            }
            ZlibMetadataMode::Crc32 => {
                let mut encoder = GzEncoder::new(&mut result, compression);
                if let Err(e) = encoder.write_all(buf) {
                    error!("Failed to compress data: {}", e);
                    return None;
                }

                if let Err(e) = encoder.flush() {
                    error!("Failed to finish compression: {}", e);
                    return None;
                }
            }
        }

        Some(result)
    }

    #[cfg(feature = "zlib")]
    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        match self.metadata_mode {
            ZlibMetadataMode::None => {
                let mut decoder = DeflateDecoder::new(buf);
                let mut result = Vec::with_capacity(buf.len() * 2);
                match decoder.read_to_end(&mut result) {
                    Ok(_) => Some(result),

                    Err(e) => {
                        error!("Failed to decompress data: {}", e);
                        None
                    }
                }
            }

            ZlibMetadataMode::Adler32 => {
                let mut decoder = ZlibDecoder::new(buf);
                let mut result = Vec::with_capacity(buf.len() * 2);
                match decoder.read_to_end(&mut result) {
                    Ok(_) => Some(result),

                    Err(e) => {
                        error!("Failed to decompress data: {}", e);
                        None
                    }
                }
            }

            ZlibMetadataMode::Crc32 => {
                let mut decoder = GzDecoder::new(buf);
                let mut result = Vec::with_capacity(buf.len() * 2);
                match decoder.read_to_end(&mut result) {
                    Ok(_) => Some(result),

                    Err(e) => {
                        error!("Failed to decompress data: {}", e);
                        None
                    }
                }
            }
        }
    }
}

#[cfg(not(feature = "zlib"))]
impl Compressor for ZlibCompressor {
    fn is_supported() -> bool {
        false
    }

    fn compress(&mut self, _buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the zlib feature enabled.");
        None
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the zlib feature enabled.");
        None
    }
}