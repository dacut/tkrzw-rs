//! Data compression functions
mod dummy;
mod lz4;
mod lzma;
mod zlib;
mod zstd;

pub use {
    self::{lz4::Lz4Compressor, zstd::ZstdCompressor},
    dummy::DummyCompressor,
    lzma::{LzmaCompressor, LzmaMetadataMode},
    zlib::{ZlibCompressor, ZlibMetadataMode},
};

// tkrzw_compress.h
// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
// except in compliance with the License.  You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.  See the License for the specific language governing permissions
// and limitations under the License.

/// Interfrace of data compression and decompression.
pub trait Compressor: Clone {
    /// Checks whether the implementation is actually supported.
    ///
    /// # Return
    /// Returns True if the implementation is actually supported.
    fn is_supported() -> bool;

    /// Compresses serial data.
    ///
    /// # Arguments
    /// * `buf`: the input buffer.
    ///
    /// # Return
    /// The result data, or `None` on failure.
    fn compress(&mut self, buf: &[u8]) -> Option<Vec<u8>>;

    /// Decompresses serial data.
    ///
    /// # Arguments
    /// * `buf`: the input buffer.
    ///
    /// # Return
    /// The result data, or `None` on failure.
    fn decompress(&mut self, buf: &[u8]) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use {
        super::{
            Compressor, DummyCompressor, Lz4Compressor, LzmaCompressor, LzmaMetadataMode, ZlibCompressor,
            ZlibMetadataMode, ZstdCompressor,
        },
        mersenne_twister::MT19937,
        pretty_assertions::assert_eq,
        rand::{Rng, SeedableRng},
    };

    fn basic_test<C: Compressor>(compressor: &mut C) {
        if !C::is_supported() {
            assert!(compressor.compress(&[]).is_none());
            assert!(compressor.decompress(&[]).is_none());
            return;
        }

        let mut inputs: Vec<Vec<u8>> =
            vec![b"".to_vec(), b"a".to_vec(), b"abc".to_vec(), b"aaaa".to_vec(), b"a\0b\0c\xff".to_vec()];
        let mut size = 16;
        while size <= 262144 {
            let zbytes = vec![b'z'; size];
            inputs.push(zbytes);

            let mut cycle_str = Vec::with_capacity(size);
            for i in 0..size {
                cycle_str.push(b'a' + (i % 26) as u8);
            }
            inputs.push(cycle_str);

            let mut random_str = vec![0; size];
            let mut mt = MT19937::from_seed(size as u32);
            mt.fill_bytes(&mut random_str);
            inputs.push(random_str);

            size *= 2;
        }

        for input in inputs {
            let compressed = compressor.compress(&input);
            assert!(compressed.is_some());
            let compressed = compressed.unwrap();
            assert!(!compressed.is_empty() || input.is_empty());

            let decompressed = compressor.decompress(&compressed);
            assert!(decompressed.is_some());
            let decompressed = decompressed.unwrap();
            assert_eq!(decompressed, input);
        }
    }

    #[test_log::test]
    fn test_dummy_compressor_default() {
        let mut compressor = DummyCompressor::default();
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_dummy_compressor_checksum() {
        let mut compressor = DummyCompressor::new(true);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zlib_compressor_default() {
        let mut compressor = ZlibCompressor::default();
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zlib_compressor_noop() {
        let mut compressor = ZlibCompressor::new(0, ZlibMetadataMode::None);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zlib_compressor_fast() {
        let mut compressor = ZlibCompressor::new(1, ZlibMetadataMode::Adler32);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zlib_compressor_slow() {
        let mut compressor = ZlibCompressor::new(9, ZlibMetadataMode::Crc32);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zstd_compressor_default() {
        let mut compressor = ZstdCompressor::default();
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zstd_compressor_fast() {
        let mut compressor = ZstdCompressor::new(0);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_zstd_compressor_slow() {
        let mut compressor = ZstdCompressor::new(10);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_lz4_compressor_default() {
        let mut compressor = Lz4Compressor::default();
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_lz4_compressor_fast() {
        let mut compressor = Lz4Compressor::new(10);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_lzma_compressor_default() {
        let mut compressor = LzmaCompressor::default();
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_lzma_compressor_fast() {
        let mut compressor = LzmaCompressor::new(1, LzmaMetadataMode::Crc32);
        basic_test(&mut compressor);
    }

    #[test_log::test]
    fn test_lzma_compressor_slow() {
        let mut compressor = LzmaCompressor::new(9, LzmaMetadataMode::Sha256);
        basic_test(&mut compressor);
    }
}
