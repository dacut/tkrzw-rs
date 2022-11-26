//! Hash utilities

use {
    crate::common::MAX_MEMORY_SIZE,
    std::{cmp::min, mem::size_of},
};

// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
// except in compliance with the License.  You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.  See the License for the specific language governing permissions
// and limitations under the License.

/// Gets the hash value by Murmur hashing.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `seed`: The seed value.
///
/// # Returns
/// The hash value.
pub fn hash_murmur(mut buf: &[u8], seed: u64) -> u64 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MUL: u64 = 0xc6a4a7935bd1e995;
    const RTT: u32 = 47;
    let mut hash = seed ^ ((buf.len() as u64).wrapping_mul(MUL));

    while buf.len() >= size_of::<u64>() {
        let mut num = u64::from_le_bytes(buf[..size_of::<u64>()].try_into().unwrap());

        num = num.wrapping_mul(MUL);
        num ^= num.wrapping_shr(RTT);
        num = num.wrapping_mul(MUL);
        hash = hash.wrapping_mul(MUL);
        hash ^= num;

        buf = &buf[size_of::<u64>()..];
    }

    if buf.len() == 7 {
        hash ^= (buf[6] as u64) << 48;
    }

    if buf.len() >= 6 {
        hash ^= (buf[5] as u64) << 40;
    }

    if buf.len() >= 5 {
        hash ^= (buf[4] as u64) << 32;
    }

    if buf.len() >= 4 {
        hash ^= (buf[3] as u64) << 24;
    }

    if buf.len() >= 3 {
        hash ^= (buf[2] as u64) << 16;
    }

    if buf.len() >= 2 {
        hash ^= (buf[1] as u64) << 8;
    }

    #[allow(clippy::len_zero)]
    if buf.len() >= 1 {
        hash ^= buf[0] as u64;
        hash = hash.wrapping_mul(MUL);
    }

    hash ^= hash.wrapping_shr(RTT);
    hash = hash.wrapping_mul(MUL);
    hash ^= hash.wrapping_shr(RTT);
    hash
}

/// Gets the hash value by FNV hashing.
///
/// # Arguments
/// * `buf` The source buffer.
///
/// # Returns
/// The hash value.
pub fn hash_fnv(buf: &[u8]) -> u64 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    let mut hash: u64 = 14695981039346656037;

    for b in buf {
        hash = (hash ^ *b as u64).wrapping_mul(109951162811);
    }

    hash
}

/// Gets the hash value by Checksum-6, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_checksum6_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 61;
    const BATCH_CAP: usize = 1 << 23;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());
        for b in &buf[..batch_size] {
            seed += *b as u32;
        }

        seed %= MODULO;
        buf = &buf[batch_size..];
    }

    seed
}

/// Gets the hash value by Checksum-6.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_checksum6(buf: &[u8]) -> u32 {
    hash_checksum6_continuous(buf, true, 0)
}

/// Gets the hash value by Checksum-6.
#[inline]
pub fn hash_checksum6_pair(first_buf: &[u8], second_buf: &[u8], mut seed: u32) -> u32 {
    const MODULO: u32 = 61;
    const BATCH_CAP: usize = 1 << 23;

    let first_size = first_buf.len();
    let second_size = second_buf.len();

    if first_size + second_size < BATCH_CAP {
        for c in first_buf {
            seed += *c as u32;
        }

        for c in second_buf {
            seed += *c as u32;
        }

        seed % MODULO
    } else {
        hash_checksum6_continuous(second_buf, true, hash_checksum6_continuous(first_buf, false, seed))
    }
}

/// Gets the hash value by checksum-8, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_checksum8_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 251;
    const BATCH_CAP: usize = 1 << 23;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());

        for b in &buf[..batch_size] {
            seed = (seed + *b as u32) % MODULO;
        }

        seed %= MODULO;
        buf = &buf[batch_size..];
    }

    seed
}

/// Gets the hash value by checksum-8.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_checksum8(buf: &[u8]) -> u32 {
    hash_checksum8_continuous(buf, true, 0)
}

/// Gets the hash value by Checksum-8.
#[inline]
pub fn hash_checksum8_pair(first_buf: &[u8], second_buf: &[u8], mut seed: u32) -> u32 {
    const MODULO: u32 = 251;
    const BATCH_CAP: usize = 1 << 23;

    let first_size = first_buf.len();
    let second_size = second_buf.len();

    if first_size + second_size < BATCH_CAP {
        for c in first_buf {
            seed += *c as u32;
        }

        for c in second_buf {
            seed += *c as u32;
        }

        seed % MODULO
    } else {
        hash_checksum8_continuous(second_buf, true, hash_checksum8_continuous(first_buf, false, seed))
    }
}

/// Gets the hash value by Adler-6, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 1 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_adler6_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 7;
    const BATCH_CAP: usize = 4096;

    let mut sum = seed >> 3;
    seed &= 0x7;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());

        for b in &buf[..batch_size] {
            seed += *b as u32;
            sum += seed;
        }

        seed %= MODULO;
        sum %= MODULO;
        buf = &buf[batch_size..];
    }

    (sum << 3) | seed
}

/// Gets the hash value by Adler-6.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_adler6(buf: &[u8]) -> u32 {
    hash_adler6_continuous(buf, true, 1)
}

/// Gets the hash value by adler-8, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 1 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_adler8_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 13;
    const BATCH_CAP: usize = 4096;

    let mut sum = seed >> 4;
    seed &= 0xf;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());

        for b in &buf[..batch_size] {
            seed += *b as u32;
            sum += seed;
        }

        seed %= MODULO;
        sum %= MODULO;
        buf = &buf[batch_size..];
    }

    (sum << 4) | seed
}

/// Gets the hash value by adler-8.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_adler8(buf: &[u8]) -> u32 {
    hash_adler8_continuous(buf, true, 1)
}

/// Gets the hash value by Adler-16, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 1 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_adler16_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 251;
    const BATCH_CAP: usize = 4096;

    let mut sum = seed >> 8;
    seed &= 0xFF;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());

        for b in &buf[..batch_size] {
            seed += *b as u32;
            sum += seed;
        }

        seed %= MODULO;
        sum %= MODULO;
        buf = &buf[batch_size..];
    }

    (sum << 8) | seed
}

/// Gets the hash value by Adler-16.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_adler16(buf: &[u8]) -> u32 {
    hash_adler16_continuous(buf, true, 1)
}

/// Gets the hash value by Adler-32, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 1 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_adler32_continuous(mut buf: &[u8], _finish: bool, mut seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    const MODULO: u32 = 65521;
    const BATCH_CAP: usize = 4096;

    let mut sum = seed >> 16;
    seed &= 0xFFFF;

    while !buf.is_empty() {
        let batch_size = min(BATCH_CAP, buf.len());

        for b in &buf[..batch_size] {
            seed += *b as u32;
            sum += seed;
        }

        seed %= MODULO;
        sum %= MODULO;
        buf = &buf[batch_size..];
    }

    (sum << 16) | seed
}

/// Gets the hash value by Adler-32.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_adler32(buf: &[u8]) -> u32 {
    hash_adler32_continuous(buf, true, 1)
}

include!(concat!(env!("OUT_DIR"), "/crc4_table.rs"));

/// Gets the hash value by CRC-4, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_crc4_continuous(mut buf: &[u8], _finish: bool, seed: u32) -> u32 {
    assert!(buf.len() <= MAX_MEMORY_SIZE as usize);
    let mut crc = seed;

    while buf.len() >= 4 {
        crc ^= u32::from_le_bytes(buf[..4].try_into().unwrap());
        crc = CRC4_TABLE3[(crc & 0xFF) as usize]
            ^ CRC4_TABLE2[((crc >> 8) & 0xFF) as usize]
            ^ CRC4_TABLE1[((crc >> 16) & 0xFF) as usize]
            ^ CRC4_TABLE0[(crc >> 24) as usize];
        buf = &buf[4..];
    }

    for b in buf {
        crc = (crc >> 8) ^ CRC4_TABLE0[((crc & 0xFF) as u8 ^ *b) as usize];
    }

    crc
}

/// Gets the hash value by CRC-4.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
pub fn hash_crc4(buf: &[u8]) -> u32 {
    hash_crc4_continuous(buf, true, 0)
}

include!(concat!(env!("OUT_DIR"), "/crc8_table.rs"));

/// Gets the hash value by CRC-8, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_crc8_continuous(mut buf: &[u8], _finish: bool, seed: u32) -> u32 {
    let mut crc = seed;
    while buf.len() >= 4 {
        crc ^= u32::from_le_bytes(buf[..4].try_into().unwrap());
        crc = CRC8_TABLE3[(crc & 0xFF) as usize]
            ^ CRC8_TABLE2[((crc >> 8) & 0xFF) as usize]
            ^ CRC8_TABLE1[((crc >> 16) & 0xFF) as usize]
            ^ CRC8_TABLE0[(crc >> 24) as usize];
        buf = &buf[4..];
    }

    for b in buf {
        crc = (crc >> 8) ^ CRC8_TABLE0[((crc & 0xff) as u8 ^ *b) as usize];
    }

    crc
}

/// Gets the hash value by CRC-8.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_crc8(buf: &[u8]) -> u32 {
    hash_crc8_continuous(buf, true, 0)
}

include!(concat!(env!("OUT_DIR"), "/crc16_table.rs"));

/// Gets the hash value by CRC-16, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0 for the frist call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_crc16_continuous(buf: &[u8], _finish: bool, seed: u32) -> u32 {
    let mut crc = seed;
    for b in buf {
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ *b) as usize] ^ (crc << 8);
    }

    crc & 0xffff
}

/// Gets the hash value by CRC-16.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_crc16(buf: &[u8]) -> u32 {
    hash_crc16_continuous(buf, true, 0)
}

include!(concat!(env!("OUT_DIR"), "/crc32_table.rs"));

/// Gets the hash value by CRC-32, in a continuous way.
///
/// # Arguments
/// * `buf`: The source buffer.
/// * `finish`: True if the cycle is to be finished.
/// * `seed`: A seed value.  This should be 0xffffffff for the first call of the cycle.
///
/// # Returns
/// The hash value.
pub fn hash_crc32_continuous(mut buf: &[u8], finish: bool, seed: u32) -> u32 {
    let mut crc = seed;
    while buf.len() >= 4 {
        crc ^= u32::from_le_bytes(buf[..4].try_into().unwrap());
        crc = CRC32_TABLE3[(crc & 0xFF) as usize]
            ^ CRC32_TABLE2[((crc >> 8) & 0xFF) as usize]
            ^ CRC32_TABLE1[((crc >> 16) & 0xFF) as usize]
            ^ CRC32_TABLE0[(crc >> 24) as usize];
        buf = &buf[4..];
    }

    for b in buf {
        crc = (crc >> 8) ^ CRC32_TABLE0[((crc & 0xFF) as u8 ^ *b) as usize];
    }

    if finish {
        crc ^= 0xFFFFFFFF;
    }

    crc
}

/// Gets the hash value by CRC-32.
///
/// # Arguments
/// * `buf`: The source buffer.
///
/// # Returns
/// The hash value.
#[inline]
pub fn hash_crc32(buf: &[u8]) -> u32 {
    hash_crc32_continuous(buf, true, 0xffffffff)
}

#[cfg(test)]
mod tests {
    use {
        super::{
            hash_adler16, hash_adler16_continuous, hash_adler32, hash_adler32_continuous, hash_adler6,
            hash_adler6_continuous, hash_adler8, hash_adler8_continuous, hash_checksum6, hash_checksum6_continuous,
            hash_checksum6_pair, hash_checksum8, hash_checksum8_continuous, hash_checksum8_pair, hash_crc16,
            hash_crc16_continuous, hash_crc32, hash_crc32_continuous, hash_crc4, hash_crc4_continuous, hash_crc8,
            hash_crc8_continuous, hash_fnv, hash_murmur,
        },
        pretty_assertions::assert_eq,
    };

    fn make_cyclic_string(size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(size);
        for i in 0..size {
            result.push(i as u8);
        }

        result
    }

    #[test]
    fn test_hash_murmur() {
        assert_eq!(hash_murmur(b"Hello World", 19780211), 0x15941D6097FA1378);
        assert_eq!(hash_murmur("こんにちは世界".as_bytes(), 19780211), 0x4C6A0FFD2F090C3A);
        assert_eq!(hash_murmur(&make_cyclic_string(256), 19780211), 0xD247B93561BD1053);
        assert_eq!(hash_murmur(&make_cyclic_string(100000), 19780211), 0x7D20AA9F76F60EC0);
    }

    #[test]
    fn test_hash_fnv() {
        assert_eq!(0x9AA143013F1E405F, hash_fnv(b"Hello World"));
        assert_eq!(0x8609C402DAD8A1EF, hash_fnv("こんにちは世界".as_bytes()));
        assert_eq!(0x2F8C4ED90D46DE25, hash_fnv(&make_cyclic_string(256)));
        assert_eq!(0xB117046EFB9CE805, hash_fnv(&make_cyclic_string(100000)));
    }

    #[test]
    fn test_hash_checksum6() {
        assert_eq!(0x2C, hash_checksum6(b"hello"));
        assert_eq!(0x0F, hash_checksum6(b"Hello World"));
        assert_eq!(0x04, hash_checksum6("こんにちは世界".as_bytes()));
        assert_eq!(0x05, hash_checksum6(&make_cyclic_string(256)));
        assert_eq!(0x1E, hash_checksum6(&make_cyclic_string(100000)));
        let crc = hash_checksum6_continuous(b"Hello", false, 0);
        let crc = hash_checksum6_continuous(b" ", false, crc);
        let crc = hash_checksum6_continuous(b"World", true, crc);
        assert_eq!(0x0F, crc);
        let crc = hash_checksum6_continuous("こんにちは".as_bytes(), false, 0);
        let crc = hash_checksum6_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x04, crc);
        assert_eq!(0x0F, hash_checksum6_pair(b"Hello", b" World", 0));
        assert_eq!(0x04, hash_checksum6_pair("こんにちは".as_bytes(), "世界".as_bytes(), 0));
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_checksum6(key) < 61);
        }
    }

    #[test]
    fn test_hash_checksum8() {
        assert_eq!(0x1E, hash_checksum8(b"hello"));
        assert_eq!(0x30, hash_checksum8(b"Hello World"));
        assert_eq!(0x96, hash_checksum8("こんにちは世界".as_bytes()));
        assert_eq!(0x0A, hash_checksum8(&make_cyclic_string(256)));
        assert_eq!(0x36, hash_checksum8(&make_cyclic_string(100000)));
        let crc = hash_checksum8_continuous(b"Hello", false, 0);
        let crc = hash_checksum8_continuous(b" ", false, crc);
        let crc = hash_checksum8_continuous(b"World", true, crc);
        assert_eq!(0x30, crc);
        let crc = hash_checksum8_continuous("こんにちは".as_bytes(), false, 0);
        let crc = hash_checksum8_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x96, crc);
        assert_eq!(0x30, hash_checksum8_pair(b"Hello", b" World", 0));
        assert_eq!(0x96, hash_checksum8_pair("こんにちは".as_bytes(), "世界".as_bytes(), 0));
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_checksum8(key) < 251);
        }
    }

    #[test]
    fn test_hash_adler6() {
        assert_eq!(0x29, hash_adler6(b"hello"));
        assert_eq!(0x13, hash_adler6(b"Hello World"));
        assert_eq!(0x14, hash_adler6("こんにちは世界".as_bytes()));
        assert_eq!(0x00, hash_adler6(&make_cyclic_string(256)));
        assert_eq!(0x34, hash_adler6(&make_cyclic_string(100000)));
        let crc = hash_adler6_continuous(b"Hello", false, 1);
        let crc = hash_adler6_continuous(b" ", false, crc);
        let crc = hash_adler6_continuous(b"World", true, crc);
        assert_eq!(0x13, crc);
        let crc = hash_adler6_continuous("こんにちは".as_bytes(), false, 1);
        let crc = hash_adler6_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x14, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_adler6(key) < 64);
        }
    }

    #[test]
    fn test_hash_adler8() {
        assert_eq!(0x70, hash_adler8(b"hello"));
        assert_eq!(0x60, hash_adler8(b"Hello World"));
        assert_eq!(0x2C, hash_adler8("こんにちは世界".as_bytes()));
        assert_eq!(0xCB, hash_adler8(&make_cyclic_string(256)));
        assert_eq!(0x17, hash_adler8(&make_cyclic_string(100000)));
        let crc = hash_adler8_continuous(b"Hello", false, 1);
        let crc = hash_adler8_continuous(b" ", false, crc);
        let crc = hash_adler8_continuous(b"World", true, crc);
        assert_eq!(0x60, crc);
        let crc = hash_adler8_continuous("こんにちは".as_bytes(), false, 1);
        let crc = hash_adler8_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x2C, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_adler8(key) < 256);
        }
    }

    #[test]
    fn test_hash_adler16() {
        assert_eq!(0x4A1F, hash_adler16(b"hello"));
        assert_eq!(0x8331, hash_adler16(b"Hello World"));
        assert_eq!(0x9B97, hash_adler16("こんにちは世界".as_bytes()));
        assert_eq!(0x190B, hash_adler16(&make_cyclic_string(256)));
        assert_eq!(0xC337, hash_adler16(&make_cyclic_string(100000)));
        let crc = hash_adler16_continuous(b"Hello", false, 1);
        let crc = hash_adler16_continuous(b" ", false, crc);
        let crc = hash_adler16_continuous(b"World", true, crc);
        assert_eq!(0x8331, crc);
        let crc = hash_adler16_continuous("こんにちは".as_bytes(), false, 1);
        let crc = hash_adler16_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x9B97, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_adler16(key) < 65536);
        }
    }

    #[test]
    fn test_hash_adler32() {
        assert_eq!(0x062C0215, hash_adler32(b"hello"));
        assert_eq!(0x180B041D, hash_adler32(b"Hello World"));
        assert_eq!(0x9D7B0E51, hash_adler32("こんにちは世界".as_bytes()));
        assert_eq!(0xADF67F81, hash_adler32(&make_cyclic_string(256)));
        assert_eq!(0x61657A0F, hash_adler32(&make_cyclic_string(100000)));
        let crc = hash_adler32_continuous(b"Hello", false, 1);
        let crc = hash_adler32_continuous(b" ", false, crc);
        let crc = hash_adler32_continuous(b"World", true, crc);
        assert_eq!(0x180B041D, crc);
        let crc = hash_adler32_continuous("こんにちは".as_bytes(), false, 1);
        let crc = hash_adler32_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x9D7B0E51, crc);
    }

    #[test]
    fn test_hash_crc4() {
        assert_eq!(0xD, hash_crc4(b"hello"));
        assert_eq!(0x9, hash_crc4(b"Hello World"));
        assert_eq!(0xE, hash_crc4("こんにちは世界".as_bytes()));
        assert_eq!(0x5, hash_crc4(&make_cyclic_string(256)));
        assert_eq!(0x3, hash_crc4(&make_cyclic_string(100000)));
        let crc = hash_crc4_continuous(b"Hello", false, 0);
        let crc = hash_crc4_continuous(b" ", false, crc);
        let crc = hash_crc4_continuous(b"World", true, crc);
        assert_eq!(0x9, crc);
        let crc = hash_crc4_continuous("こんにちは".as_bytes(), false, 0);
        let crc = hash_crc4_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0xE, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_crc4(key) < 16);
        }
    }

    #[test]
    fn test_hash_crc8() {
        assert_eq!(0x92, hash_crc8(b"hello"));
        assert_eq!(0x25, hash_crc8(b"Hello World"));
        assert_eq!(0xB7, hash_crc8("こんにちは世界".as_bytes()));
        assert_eq!(0x14, hash_crc8(&make_cyclic_string(256)));
        assert_eq!(0xB8, hash_crc8(&make_cyclic_string(100000)));
        let crc = hash_crc8_continuous(b"Hello", false, 0);
        let crc = hash_crc8_continuous(b" ", false, crc);
        let crc = hash_crc8_continuous(b"World", true, crc);
        assert_eq!(0x25, crc);
        let crc = hash_crc8_continuous("こんにちは".as_bytes(), false, 0);
        let crc = hash_crc8_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0xB7, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_crc8(key) < 256);
        }
    }

    #[test]
    fn test_hash_crc16() {
        assert_eq!(0xC362, hash_crc16(b"hello"));
        assert_eq!(0x992A, hash_crc16(b"Hello World"));
        assert_eq!(0xF802, hash_crc16("こんにちは世界".as_bytes()));
        assert_eq!(0x7E55, hash_crc16(&make_cyclic_string(256)));
        assert_eq!(0x96E2, hash_crc16(&make_cyclic_string(100000)));
        let crc = hash_crc16_continuous(b"Hello", false, 0);
        let crc = hash_crc16_continuous(b" ", false, crc);
        let crc = hash_crc16_continuous(b"World", true, crc);
        assert_eq!(0x992A, crc);
        let crc = hash_crc16_continuous("こんにちは".as_bytes(), false, 0);
        let crc = hash_crc16_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0xF802, crc);
        for i in 0..256 {
            let key = &make_cyclic_string(i);
            assert!(hash_crc16(key) < 65536);
        }
    }

    #[test_log::test]
    fn test_hash_crc32() {
        assert_eq!(0x3610A686, hash_crc32(b"hello"));
        assert_eq!(0x4A17B156, hash_crc32(b"Hello World"));
        assert_eq!(0x75197186, hash_crc32("こんにちは世界".as_bytes()));
        assert_eq!(0x29058C73, hash_crc32(&make_cyclic_string(256)));
        assert_eq!(0xAACF4FC9, hash_crc32(&make_cyclic_string(100000)));
        let crc = hash_crc32_continuous(b"Hello", false, 0xffffffff);
        assert_eq!(0x082e767d, crc);
        let crc = hash_crc32_continuous(b" ", false, crc);
        assert_eq!(0x15d2033f, crc);
        let crc = hash_crc32_continuous(b"World", true, crc);
        assert_eq!(0x4A17B156, crc);
        let crc = hash_crc32_continuous("こんにちは".as_bytes(), false, 0xffffffff);
        let crc = hash_crc32_continuous("世界".as_bytes(), true, crc);
        assert_eq!(0x75197186, crc);
    }
}
