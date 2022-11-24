use {super::Compressor, crate::hash_util::hash_crc32, std::mem::size_of, log::error};

/// Dummy compressor implementation
#[derive(Clone, Debug)]
pub struct DummyCompressor {
    /// Whether to add a checksum.
    checksum: bool,
}

impl DummyCompressor {
    pub fn new(checksum: bool) -> Self {
        Self {
            checksum,
        }
    }
}

impl Compressor for DummyCompressor {
    fn is_supported() -> bool {
        true
    }

    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if self.checksum {
            let mut result = Vec::with_capacity(buf.len() + size_of::<u32>());
            let crc = hash_crc32(buf);
            result.extend(crc.to_be_bytes());
            result.extend(buf);
            Some(result)
        } else {
            Some(buf.to_vec())
        }
    }

    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if self.checksum {
            if buf.len() < size_of::<u32>() {
                error!("Input buffer is too short.");
                return None;
            }

            let crc = u32::from_be_bytes(buf[0..size_of::<u32>()].try_into().unwrap());

            let data = &buf[size_of::<u32>()..];
            let actual = hash_crc32(data);
            if crc != actual {
                error!("Checksum mismatch: expected {:x}, got {:x}", crc, actual);
                return None;
            }

            Some(data.to_vec())
        } else {
            Some(buf.to_vec())
        }
    }
}
