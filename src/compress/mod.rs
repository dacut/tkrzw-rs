//! Data compression functions
mod dummy;
mod zlib;
mod zstd;

pub use {dummy::DummyCompressor, zlib::{ZlibCompressor, ZlibMetadataMode}, self::zstd::ZstdCompressor};

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
