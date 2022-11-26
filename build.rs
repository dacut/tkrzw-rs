use std::{
    env::var_os,
    fs::File,
    io::{Result as IoResult, Write},
    path::{Path, PathBuf},
};

fn main() {
    let out_dir = PathBuf::from(var_os("OUT_DIR").unwrap());
    create_crc4_table(&out_dir).unwrap();
    create_crc8_table(&out_dir).unwrap();
    create_crc16_table(&out_dir).unwrap();
    create_crc32_table(&out_dir).unwrap();
}

fn create_crc4_table(out_dir: &Path) -> IoResult<()> {
    let filename = out_dir.join("crc4_table.rs");
    let mut fd = File::create(filename)?;

    // From https://github.com/estraier/tkrzw/blob/master/tkrzw_hash_util.cc#L207-L219
    let mut table0: [u32; 256] = [0; 256];
    let mut table1: [u32; 256] = [0; 256];
    let mut table2: [u32; 256] = [0; 256];
    let mut table3: [u32; 256] = [0; 256];

    for (i, el) in table0.iter_mut().enumerate() {
        let mut c: u8 = i as u8;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x0C } else { c >> 1 };
        }

        *el = c as u32;
    }

    for i in 0..256usize {
        table1[i] = table0[table0[i] as usize];
        table2[i] = table0[table1[i] as usize];
        table3[i] = table0[table2[i] as usize];
    }

    write_table32(&mut fd, "CRC4_TABLE0", &table0)?;
    write_table32(&mut fd, "CRC4_TABLE1", &table1)?;
    write_table32(&mut fd, "CRC4_TABLE2", &table2)?;
    write_table32(&mut fd, "CRC4_TABLE3", &table3)
}

fn create_crc8_table(out_dir: &Path) -> IoResult<()> {
    let filename = out_dir.join("crc8_table.rs");
    let mut fd = File::create(filename)?;

    // From https://github.com/estraier/tkrzw/blob/master/tkrzw_hash_util.cc#L281-L293
    let mut table0: [u32; 256] = [0; 256];
    let mut table1: [u32; 256] = [0; 256];
    let mut table2: [u32; 256] = [0; 256];
    let mut table3: [u32; 256] = [0; 256];

    for (i, el) in table0.iter_mut().enumerate() {
        let mut c: u8 = i as u8;
        for _ in 0..8 {
            c = (c << 1) ^ if c & 0x80 != 0 {  0x07 } else { 0 };
        }

        *el = c as u32;
    }

    for i in 0..256usize {
        table1[i] = table0[table0[i] as usize];
        table2[i] = table0[table1[i] as usize];
        table3[i] = table0[table2[i] as usize];
    }

    write_table32(&mut fd, "CRC8_TABLE0", &table0)?;
    write_table32(&mut fd, "CRC8_TABLE1", &table1)?;
    write_table32(&mut fd, "CRC8_TABLE2", &table2)?;
    write_table32(&mut fd, "CRC8_TABLE3", &table3)
}

fn create_crc16_table(out_dir: &Path) -> IoResult<()> {
    let filename = out_dir.join("crc16_table.rs");
    let mut fd = File::create(filename)?;

    // From https://github.com/estraier/tkrzw/blob/master/tkrzw_hash_util.cc#L345-L352
    let mut table: [u32; 256] = [0; 256];

    for (i, el) in table.iter_mut().enumerate() {
        let mut c: u16 = (i << 8) as u16;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 {
                0x1021 ^ (c << 1)
            } else {
                c << 1
            };
        }
        *el = c as u32;
    }

    write_table32(&mut fd, "CRC16_TABLE", &table)
}

fn create_crc32_table(out_dir: &Path) -> IoResult<()> {
    let filename = out_dir.join("crc32_table.rs");
    let mut fd = File::create(filename)?;

    // From https://github.com/estraier/tkrzw/blob/master/tkrzw_hash_util.cc#L386-L397
    let mut table0: [u32; 256] = [0; 256];
    let mut table1: [u32; 256] = [0; 256];
    let mut table2: [u32; 256] = [0; 256];
    let mut table3: [u32; 256] = [0; 256];

    for (i, el) in table0.iter_mut().enumerate() {
        let mut c: u32 = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }

        *el = c;
    }

    for i in 0..256usize {
        table1[i] = (table0[i] >> 8) ^ table0[(table0[i] & 0xff) as usize];
        table2[i] = (table1[i] >> 8) ^ table0[(table1[i] & 0xff) as usize];
        table3[i] = (table2[i] >> 8) ^ table0[(table2[i] & 0xff) as usize];
    }

    write_table32(&mut fd, "CRC32_TABLE0", &table0)?;
    write_table32(&mut fd, "CRC32_TABLE1", &table1)?;
    write_table32(&mut fd, "CRC32_TABLE2", &table2)?;
    write_table32(&mut fd, "CRC32_TABLE3", &table3)
}

#[allow(dead_code)]
fn write_table8<W: Write>(fd: &mut W, table_name: &str, table: &[u8]) -> IoResult<()> {
    let len = table.len();
    write!(fd, "const {table_name}: [u32; {len}] = [")?;
    for (i, el) in table.iter().enumerate() {
        if i % 16 == 0 {
            write!(fd, "\n    ")?;
        } else {
            write!(fd, " ")?;
        }

        write!(fd, "0x{:08x},", el)?;
    }
    write!(fd, "\n];\n\n")
}


fn write_table32<W: Write>(fd: &mut W, table_name: &str, table: &[u32]) -> IoResult<()> {
    let len = table.len();
    write!(fd, "const {table_name}: [u32; {len}] = [")?;
    for (i, el) in table.iter().enumerate() {
        if i % 16 == 0 {
            write!(fd, "\n    ")?;
        } else {
            write!(fd, " ")?;
        }

        write!(fd, "0x{:08x},", el)?;
    }
    write!(fd, "\n];\n\n")
}
