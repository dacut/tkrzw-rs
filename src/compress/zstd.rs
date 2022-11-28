use {super::Compressor, log::error};

#[cfg(feature = "zstd")]
use {
    ::zstd::{encode_all, decode_all},
};

#[derive(Clone, Debug)]
pub struct ZstdCompressor {
    /// The compression level.
    level: i32,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Self {
        Self {
            level,
        }
    }
}

impl Default for ZstdCompressor {
    fn default() -> Self {
        Self::new(3)
    }
}

#[cfg(feature = "zstd")]
impl Compressor for ZstdCompressor {
    fn is_supported() -> bool {
        true
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        match encode_all(buf, self.level) {
            Ok(result) => Some(result),
            Err(e) => {
                error!("Failed to compress: {}", e);
                None
            }
        }
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        match decode_all(buf) {
            Ok(result) => Some(result),
            Err(e) => {
                error!("Failed to decompress: {}", e);
                None
            }
        }
    }
}

#[cfg(not(feature = "zstd"))]
impl Compressor for ZstdCompressor {
    fn is_supported() -> bool {
        false
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the zstd feature enabled.");
        None
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the zstd feature enabled.");
        None
    }
}