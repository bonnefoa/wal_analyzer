use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;
use nom::IResult;

const XLOG_BLCKSZ: u64 = 8192;
const XLOG_PAGE_MAGIC: u16 = 0xD10D;
const XLOG_PAGE_HEADER_SIZE: usize = 20;
const XLOG_RECORD_HEADER_SIZE: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub struct XLogPageHeader {
    pub xlp_magic: u16,
    pub xlp_info: u16,
    pub xlp_tli: u16,
    pub xlp_pageaddr: u64,
    pub xlp_rem_len: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct XLogRecord {
    pub xl_tot_len: u32,     // Total length of the record
    pub xl_xid: u32,         // Transaction ID
    pub xl_prev: u64,        // Pointer to previous record (LSN)
    pub xl_info: u8,         // Flag bits
    pub xl_rmid: RmgrId,     // Resource manager for this record
    pub xl_crc: u32,         // CRC for this record
    pub xl_data: Vec<u8>,    // Record data
}

pub struct XLogReader {
    file: File,
    record_limit: Option<u64>,
    records_read: u64,
}

#[derive(Error, Debug)]
pub enum XLogError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid XLOG record: {0}")]
    InvalidRecord(String),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RmgrId {
    XLOG,
    Transaction,
    Storage,
    CLOG,
    Database,
    Tablespace,
    MultiXact,
    RelMap,
    Standby,
    Heap,
    Heap2,
    Index,
    Btree,
    Hash,
    Gin,
    Gist,
    Sequence,
    Spgist,
    Brin,
    CommitTs,
    ReplicationOrigin,
    Generic,
    LogicalMsg,
    Unused(u8),
}

impl From<u8> for RmgrId {
    fn from(byte: u8) -> RmgrId {
        match byte {
            0x00 => RmgrId::XLOG,
            0x01 => RmgrId::Transaction,
            0x02 => RmgrId::Storage,
            0x03 => RmgrId::CLOG,
            0x04 => RmgrId::Database,
            0x05 => RmgrId::Tablespace,
            0x06 => RmgrId::MultiXact,
            0x07 => RmgrId::RelMap,
            0x08 => RmgrId::Standby,
            0x09 => RmgrId::Heap,
            0x0a => RmgrId::Heap2,
            0x0b => RmgrId::Index,
            0x0c => RmgrId::Btree,
            0x0d => RmgrId::Hash,
            0x0e => RmgrId::Gin,
            0x0f => RmgrId::Gist,
            0x10 => RmgrId::Sequence,
            0x11 => RmgrId::Spgist,
            0x12 => RmgrId::Brin,
            0x13 => RmgrId::CommitTs,
            0x14 => RmgrId::ReplicationOrigin,
            0x15 => RmgrId::Generic,
            0x16 => RmgrId::LogicalMsg,
            otherwise => RmgrId::Unused(otherwise),
        }
    }
}

impl XLogPageHeader {
    fn new(xlp_magic: u16, xlp_info: u16, xlp_tli: u16, xlp_pageaddr: u64, xlp_rem_len: u32) -> Self {
        Self {
            xlp_magic,
            xlp_info,
            xlp_tli,
            xlp_pageaddr,
            xlp_rem_len,
        }
    }
}

impl XLogRecord {
    pub fn new(xl_tot_len: u32, xl_xid: u32, xl_prev: u64, xl_info: u8, xl_rmid: u8, xl_crc: u32, xl_data: Vec<u8>) -> Self {
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

impl XLogReader {
    pub fn new<P: AsRef<Path>>(path: P, record_limit: Option<u64>) -> Result<Self, XLogError> {
        let file = File::open(path)?;
        Ok(Self {
            file,
            records_read: 0,
            record_limit,
        })
    }

    fn parse_page_header(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let (i, byte) = take(2)(input)?;
    }

//    pub fn read_page_header(&mut self) -> Result<Option<XLogPageHeader>, XLogError> {
//        let mut header_bytes = [0u8; XLOG_PAGE_HEADER_SIZE];
//        match self.file.read_exact(&mut header_bytes) {
//            Ok(_) => {
//                let mut cursor = io::Cursor::new(header_bytes);
//                let magic = cursor.read_u16::<LittleEndian>()?;
//                let info = cursor.read_u16::<LittleEndian>()?;
//                let timeline = cursor.read_u16::<LittleEndian>()?;
//                let pageaddr = cursor.read_u64::<LittleEndian>()?;
//                let rem_len = cursor.read_u32::<LittleEndian>()?;
//                cursor.seek(SeekFrom::Current(2))?;
//
//                if magic == 0 {
//                    return Ok(None);
//                }
//
//                if magic != XLOG_PAGE_MAGIC {
//                    return Err(XLogError::InvalidRecord(format!("Invalid page magic number: {:X}", magic)));
//                }
//
//                // Move to the next page boundary
//                // let bytes_to_skip = XLOG_BLCKSZ - XLOG_PAGE_HEADER_SIZE as u64;
//                // if bytes_to_skip > 0 {
//                //     self.file.seek(SeekFrom::Current(bytes_to_skip as i64))?;
//                // }
//
//                Ok(Some(XLogPageHeader::new(magic, info, timeline, pageaddr, rem_len)))
//            }
//            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
//                Ok(None)
//            }
//            Err(e) => Err(XLogError::Io(e)),
//        }
//    }
//
//    fn read_record_header(&mut self) -> Result<Option<XLogRecord>, XLogError> {
//        let mut header_bytes = [0u8; XLOG_RECORD_HEADER_SIZE];
//        match self.file.read_exact(&mut header_bytes) {
//            Ok(_) => {
//                let mut cursor = io::Cursor::new(header_bytes);
//                let xl_tot_len = cursor.read_u32::<LittleEndian>()?;
//                if xl_tot_len == 0 {
//                    return Ok(None);
//                }
//                let xl_xid = cursor.read_u32::<LittleEndian>()?;
//                let xl_prev = cursor.read_u64::<LittleEndian>()?;
//                let xl_info = cursor.read_u8()?;
//                let xl_rmid = cursor.read_u8()?;
//                // Skip 2 bytes of padding
//                cursor.seek(SeekFrom::Current(2))?;
//                let xl_crc = cursor.read_u32::<LittleEndian>()?;
//
//                // Read the record data
//                let data_len = xl_tot_len as usize - XLOG_RECORD_HEADER_SIZE;
//                let mut xl_data = vec![0u8; data_len];
//                match self.file.read_exact(&mut xl_data) {
//                    Ok(_) => Ok(Some(XLogRecord::new(
//                        xl_tot_len,
//                        xl_xid,
//                        xl_prev,
//                        xl_info,
//                        xl_rmid,
//                        xl_crc,
//                        xl_data,
//                    ))),
//                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
//                    Err(e) => Err(XLogError::Io(e)),
//                }
//            }
//            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
//            Err(e) => Err(XLogError::Io(e)),
//        }
//    }

}

// impl Iterator for XLogReader {
//     type Item = Result<XLogRecord, XLogError>;
//     fn next(&mut self) -> Option<Self::Item> {
//         match self.read_page_header() {
//             Ok(Some(record)) => return None,
//             Ok(None) => return None,
//             Err(e) => return Some(Err(e)),
//         }
//     }
// }

#[cfg(test)]
mod tests {
//    use super::*;
//    use std::io::{Write, Seek, SeekFrom};
//    use tempfile::NamedTempFile;
//    use byteorder::{WriteBytesExt, LittleEndian};
//
//    fn create_test_xlog_file() -> NamedTempFile {
//        let mut file = NamedTempFile::new().unwrap();
//
//        // Write a page header
//        let mut header = vec![0u8; XLOG_PAGE_HEADER_SIZE];
//        let mut cursor = io::Cursor::new(&mut header);
//        cursor.write_u16::<LittleEndian>(XLOG_PAGE_MAGIC).unwrap(); // magic
//        cursor.write_u16::<LittleEndian>(0x5).unwrap(); // info
//        cursor.write_u16::<LittleEndian>(1).unwrap(); // timeline
//        cursor.write_u64::<LittleEndian>(0x100000000).unwrap(); // pageaddr
//        cursor.write_u32::<LittleEndian>(100).unwrap(); // rem_len
//        file.write_all(&header).unwrap();
//
//        // Write two test records
//        // Record 1
//        let mut record1_header = vec![0u8; XLOG_RECORD_HEADER_SIZE];
//        let mut cursor = io::Cursor::new(&mut record1_header);
//        cursor.write_u32::<LittleEndian>(50).unwrap(); // xl_tot_len
//        cursor.write_u32::<LittleEndian>(1).unwrap(); // xl_xid
//        cursor.write_u64::<LittleEndian>(0x100000000).unwrap(); // xl_prev
//        cursor.write_u8(0x4D).unwrap(); // xl_info
//        cursor.write_u8(1).unwrap(); // xl_rmid (Transaction)
//        cursor.seek(SeekFrom::Current(2)).unwrap(); // padding
//        cursor.write_u32::<LittleEndian>(0).unwrap(); // xl_crc
//        file.write_all(&record1_header).unwrap();
//
//        // Record 1 data
//        let record1_data = vec![0u8; 26]; // 50 - 24 (header size)
//        file.write_all(&record1_data).unwrap();
//
//        // Record 2
//        let mut record2_header = vec![0u8; XLOG_RECORD_HEADER_SIZE];
//        let mut cursor = io::Cursor::new(&mut record2_header);
//        cursor.write_u32::<LittleEndian>(50).unwrap(); // xl_tot_len
//        cursor.write_u32::<LittleEndian>(2).unwrap(); // xl_xid
//        cursor.write_u64::<LittleEndian>(0x100000050).unwrap(); // xl_prev
//        cursor.write_u8(0x8D).unwrap(); // xl_info
//        cursor.write_u8(2).unwrap(); // xl_rmid (Storage)
//        cursor.seek(SeekFrom::Current(2)).unwrap(); // padding
//        cursor.write_u32::<LittleEndian>(0).unwrap(); // xl_crc
//        file.write_all(&record2_header).unwrap();
//
//        // Record 2 data
//        let record2_data = vec![0u8; 26]; // 50 - 24 (header size)
//        file.write_all(&record2_data).unwrap();
//
//        // Fill the rest of the page with zeros
//        let remaining = XLOG_BLCKSZ - (XLOG_PAGE_HEADER_SIZE + 100) as u64;
//        let zeros = vec![0u8; remaining as usize];
//        file.write_all(&zeros).unwrap();
//
//        // Seek back to the beginning of the file
//        file.seek(SeekFrom::Start(0)).unwrap();
//
//        file
//    }
//
//    #[test]
//    fn test_read_page_header() {
//        let test_file = create_test_xlog_file();
//        let mut reader = XLogReader::new(test_file.path(), None).unwrap();
//
//        // Read the page header
//        let header = reader.read_page_header().unwrap().unwrap();
//
//        // Verify all header fields
//        assert_eq!(header.xlp_magic, XLOG_PAGE_MAGIC);
//        assert_eq!(header.xlp_info, 0x5);
//        assert_eq!(header.xlp_tli, 1);
//        assert_eq!(header.xlp_pageaddr, 0x100000000);
//        assert_eq!(header.xlp_rem_len, 100);
//    }
//
//    #[test]
//    fn test_read_xlog_records() {
//        let test_file = create_test_xlog_file();
//        let mut reader = XLogReader::new(test_file.path(), None).unwrap();
//
//        // Read records from the first page
//        let records = reader.read_page_records().unwrap();
//
//        // Verify we read exactly 2 records
//        assert_eq!(records.len(), 2);
//
//        // Verify first record
//        let record1 = &records[0];
//        assert_eq!(record1.xl_tot_len, 50);
//        assert_eq!(record1.xl_xid, 1);
//        assert_eq!(record1.xl_prev, 0x100000000);
//        assert_eq!(record1.xl_info, 0x4D);
//        assert_eq!(record1.xl_rmid, RmgrId::Transaction);
//        assert_eq!(record1.xl_crc, 0);
//        assert_eq!(record1.xl_data.len(), 26);
//
//        // Verify second record
//        let record2 = &records[1];
//        assert_eq!(record2.xl_tot_len, 50);
//        assert_eq!(record2.xl_xid, 2);
//        assert_eq!(record2.xl_prev, 0x100000050);
//        assert_eq!(record2.xl_info, 0x8D);
//        assert_eq!(record2.xl_rmid, RmgrId::Storage);
//        assert_eq!(record2.xl_crc, 0);
//        assert_eq!(record2.xl_data.len(), 26);
//    }
}
