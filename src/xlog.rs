use std::fs::File;

pub struct XLogReader {
    file: File,
    record_limit: Option<u64>,
    records_read: u64,
}

#[derive(Debug)]
pub struct XLogRecPtr(pub u64);

#[derive(Debug)]
pub struct XLogFilePos {
    pub tli: u32,
    pub log: u32,
    pub seg: u32,
}

pub fn parse_filename(fname: &str) -> Result<XLogFilePos, std::num::ParseIntError> {
    let tli = u32::from_str_radix(&fname[0..8], 16)?;
    let log = u32::from_str_radix(&fname[8..16], 16)?;
    let seg =  u32::from_str_radix(&fname[16..24], 16)?;
    Ok(XLogFilePos{tli, log, seg})
}

// impl XLogReader {
//     pub fn new<P: AsRef<Path>>(path: P, record_limit: Option<u64>) -> Result<Self, XLogError> {
//         let file = File::open(path)?;
//         Ok(Self {
//             file,
//             records_read: 0,
//             record_limit,
//         })
//     }
// }
