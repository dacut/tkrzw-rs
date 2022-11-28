use super::Compressor;

#[cfg(feature = "lzma")]
use {
    crate::common::MAX_MEMORY_SIZE,
    std::mem::{size_of, transmute},
    xz_sys::{
        lzma_auto_decoder, lzma_check, lzma_code, lzma_easy_encoder, lzma_end, lzma_stream, LZMA_CHECK_CRC32,
        LZMA_CHECK_NONE, LZMA_CHECK_SHA256, LZMA_FINISH, LZMA_OK, LZMA_STREAM_END,
    },
};

/// LZMA compression metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LzmaMetadataMode {
    /// Without any checksum.
    None,

    /// With CRC-32 checksum.
    Crc32,

    /// With SHA-256 checksum.
    Sha256,
}

impl LzmaMetadataMode {
    /// Get the check flag for LZMA.
    #[cfg(feature = "lzma")]
    fn check_flag(&self) -> lzma_check {
        match self {
            Self::None => LZMA_CHECK_NONE,
            Self::Crc32 => LZMA_CHECK_CRC32,
            Self::Sha256 => LZMA_CHECK_SHA256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LzmaCompressor {
    level: u32,
    metadata_mode: LzmaMetadataMode,
}

impl LzmaCompressor {
    pub fn new(level: u32, metadata_mode: LzmaMetadataMode) -> Self {
        Self {
            level,
            metadata_mode,
        }
    }
}

impl Default for LzmaCompressor {
    fn default() -> Self {
        Self::new(6, LzmaMetadataMode::None)
    }
}

#[cfg(feature = "lzma")]
impl Compressor for LzmaCompressor {
    fn is_supported() -> bool {
        true
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        assert!(buf.len() < MAX_MEMORY_SIZE as usize);
        let mut zs = LZMA_STREAM_INIT;
        zs.next_in = buf.as_ptr() as *const u8;
        zs.avail_in = buf.len();

        let mut compressed = Vec::with_capacity(buf.len() + 1024);
        let target = compressed.spare_capacity_mut();
        zs.next_out = target.as_mut_ptr() as *mut u8;
        zs.avail_out = target.len();

        let result = unsafe { lzma_easy_encoder(&mut zs, self.level, self.metadata_mode.check_flag()) };

        if result != LZMA_OK {
            return None;
        }

        let result = unsafe { lzma_code(&mut zs, LZMA_FINISH) };

        unsafe {
            lzma_end(&mut zs);
        }

        if result != LZMA_STREAM_END {
            return None;
        }

        let target_len = target.len();
        unsafe {
            compressed.set_len(target_len - zs.avail_out);
        }

        Some(compressed)
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        assert!(buf.len() < MAX_MEMORY_SIZE as usize);
        let mut decompressed = Vec::with_capacity(buf.len() * 12 + 32);

        loop {
            let target = decompressed.spare_capacity_mut();
            let mut zs = LZMA_STREAM_INIT;
            zs.next_in = buf.as_ptr() as *const u8;
            zs.avail_in = buf.len();
            zs.next_out = target.as_mut_ptr() as *mut u8;
            zs.avail_out = target.len();

            let result = unsafe { lzma_auto_decoder(&mut zs, 1 << 30, 0) };

            if result != LZMA_OK {
                return None;
            }

            let rv = unsafe { lzma_code(&mut zs, LZMA_FINISH) };
            unsafe { lzma_end(&mut zs) };

            let target_len = target.len();
            if rv == LZMA_STREAM_END {
                unsafe { decompressed.set_len(target_len - zs.avail_out) };
                return Some(decompressed);
            }

            if rv != LZMA_OK {
                return None;
            }

            if decompressed.capacity() >= u32::MAX as usize / 2 {
                return None;
            }

            decompressed.reserve(decompressed.capacity() * 2);
        }
    }
}

#[cfg(feature = "lzma")]
const LZMA_STREAM_SIZE: usize = size_of::<lzma_stream>();

#[cfg(feature = "lzma")]
const LZMA_STREAM_INIT: lzma_stream = unsafe { transmute([0u8; LZMA_STREAM_SIZE]) };

#[cfg(not(feature = "lzma"))]
impl Compressor for LzmaCompressor {
    fn is_supported() -> bool {
        false
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the lzma feature enabled.");
        None
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the lzma feature enabled.");
        None
    }
}
