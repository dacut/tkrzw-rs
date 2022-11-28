use {super::Compressor, log::{error, trace}};

#[cfg(feature = "lz4")]
use ::lz4::liblz4::{LZ4_compressBound, LZ4_compress_fast, LZ4_decompress_safe};

#[derive(Clone, Debug)]
pub struct Lz4Compressor {
    /// The acceleration level.
    acceleration: i32,
}

impl Lz4Compressor {
    pub fn new(acceleration: i32) -> Self {
        Self {
            acceleration,
        }
    }
}

impl Default for Lz4Compressor {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(feature = "lz4")]
impl Compressor for Lz4Compressor {
    fn is_supported() -> bool {
        true
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let compress_size = LZ4_compressBound(buf.len() as i32) as usize;
            let mut result = Vec::<u8>::with_capacity(compress_size);
            let target = result.spare_capacity_mut();
            trace!("Entering LZ4_compress_fast");
            let compress_size = LZ4_compress_fast(
                buf.as_ptr() as *const i8,
                target.as_mut_ptr() as *mut i8,
                buf.len() as i32,
                target.len() as i32,
                self.acceleration,
            );
            trace!("Leaving LZ4_compress_fast; compress_size = {}", compress_size);
            if compress_size <= 0 {
                error!("LZ4 compression failed");
                None
            } else {
                result.set_len(compress_size as usize);
                Some(result)
            }
        }
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        let mut result = Vec::<u8>::with_capacity(4 * buf.len() + 32);
        loop {
            unsafe {
                let target = result.spare_capacity_mut();
                let decompressed_size = LZ4_decompress_safe(
                    buf.as_ptr() as *const i8,
                    target.as_mut_ptr() as *mut i8,
                    buf.len() as i32,
                    target.len() as i32,
                );

                if decompressed_size >= 0 {
                    result.set_len(decompressed_size as usize);
                    return Some(result);
                }

                result.reserve(2 * result.capacity());
            }
        }
    }
}

#[cfg(not(feature = "lz4"))]
impl Compressor for Lz4Compressor {
    fn is_supported() -> bool {
        false
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the lz4 feature enabled.");
        None
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        error!("tkrzw-rs was not built with the lz4 feature enabled.");
        None
    }
}
