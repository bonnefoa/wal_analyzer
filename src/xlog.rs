use std::fs::File;
use wal_analyzer::parser::RmgrId;

const XLOG_BLCKSZ: u64 = 8192;
const XLOG_PAGE_HEADER_SIZE: usize = 20;
const XLOG_RECORD_HEADER_SIZE: usize = 24;

#[derive(Clone, Debug)]
pub struct XLogRecord {
    // Total length of the record
    pub xl_tot_len: u32,
    pub xl_xid: u32,      // Transaction ID
    pub xl_prev: u64,     // Pointer to previous record (LSN)
    pub xl_info: u8,      // Flag bits
    pub xl_rmid: RmgrId,  // Resource manager for this record
    pub xl_crc: u32,      // CRC for this record
    pub xl_data: Vec<u8>, // Record data
}

pub struct XLogReader {
    file: File,
    record_limit: Option<u64>,
    records_read: u64,
}

impl XLogRecord {
    pub fn new(
        xl_tot_len: u32,
        xl_xid: u32,
        xl_prev: u64,
        xl_info: u8,
        xl_rmid: u8,
        xl_crc: u32,
        xl_data: Vec<u8>,
    ) -> Self {
        Self {
            xl_tot_len,
            xl_xid,
            xl_prev,
            xl_info,
            xl_rmid: RmgrId::from(xl_rmid),
            xl_crc,
            xl_data,
        }
    }
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
