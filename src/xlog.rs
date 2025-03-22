use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum XLogError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid XLOG record: {0}")]
    InvalidRecord(String),
}

// Resource manager types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RmgrId {
    XLOG = 0,
    Transaction = 1,
    Storage = 2,
    CLOG = 3,
    Database = 4,
    Tablespace = 5,
    MultiXact = 6,
    RelMap = 7,
    Standby = 8,
    Heap = 10,
    Heap2 = 12,
    Index = 13,
    Btree = 14,
    Hash = 15,
    Gin = 16,
    Gist = 17,
    Sequence = 18,
    Spgist = 19,
    Brin = 20,
    CommitTs = 21,
    ReplicationOrigin = 22,
    Generic = 23,
    LogicalMsg = 24,
    Unused = 25, // Values after RM_MAX_ID are unused
}

impl RmgrId {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => RmgrId::XLOG,
            1 => RmgrId::Transaction,
            2 => RmgrId::Storage,
            3 => RmgrId::CLOG,
            4 => RmgrId::Database,
            5 => RmgrId::Tablespace,
            6 => RmgrId::MultiXact,
            7 => RmgrId::RelMap,
            8 => RmgrId::Standby,
            10 => RmgrId::Heap,
            12 => RmgrId::Heap2,
            13 => RmgrId::Index,
            14 => RmgrId::Btree,
            15 => RmgrId::Hash,
            16 => RmgrId::Gin,
            17 => RmgrId::Gist,
            18 => RmgrId::Sequence,
            19 => RmgrId::Spgist,
            20 => RmgrId::Brin,
            21 => RmgrId::CommitTs,
            22 => RmgrId::ReplicationOrigin,
            23 => RmgrId::Generic,
            24 => RmgrId::LogicalMsg,
            _ => RmgrId::Unused,
        }
    }
}

pub const XLOG_BLCKSZ: u64 = 8192;
const XLOG_PAGE_MAGIC: u16 = 0xD10D; // PostgreSQL XLOG_PAGE_MAGIC
const XLOG_PAGE_HEADER_SIZE: usize = 20; // 2 bytes magic + 2 bytes info + 2 bytes tli + 8 bytes LSN + 4 bytes rem_len + 2 bytes hole
const XLOG_RECORD_HEADER_SIZE: usize = 24; // Size of XLogRecord header

#[derive(Debug, Clone)]
pub struct XLogPageHeader {
    pub magic: u16,      // uint16 xlp_magic
    pub info: u16,       // uint16 xlp_info
    pub timeline: u16,   // uint16 xlp_tli (timeline)
    pub pageaddr: u64,   // uint64 xlp_pageaddr (LSN)
    pub rem_len: u32,    // uint32 xlp_rem_len (remaining length)
}

impl XLogPageHeader {
    fn new(magic: u16, info: u16, timeline: u16, pageaddr: u64, rem_len: u32) -> Self {
        Self {
            magic,
            info,
            timeline,
            pageaddr,
            rem_len,
        }
    }
}

#[derive(Debug, Clone)]
pub struct XLogRecord {
    pub xl_tot_len: u32,     // Total length of the record
    pub xl_xid: u32,         // Transaction ID
    pub xl_prev: u64,        // Pointer to previous record (LSN)
    pub xl_info: u8,         // Flag bits
    pub xl_rmid: RmgrId,     // Resource manager for this record
    pub xl_crc: u32,         // CRC for this record
    pub xl_data: Vec<u8>,    // Record data
}

impl XLogRecord {
    pub fn new(xl_tot_len: u32, xl_xid: u32, xl_prev: u64, xl_info: u8, xl_rmid: u8, xl_crc: u32, xl_data: Vec<u8>) -> Self {
        Self {
            xl_tot_len,
            xl_xid,
            xl_prev,
            xl_info,
            xl_rmid: RmgrId::from_u8(xl_rmid),
            xl_crc,
            xl_data,
        }
    }
}

pub struct XLogReader {
    file: File,
    current_pos: u64,
    eof: bool,
    page_limit: Option<u64>,
    pages_read: u64,
    pub file_size: u64,
}

impl XLogReader {
    pub fn new<P: AsRef<Path>>(path: P, limit: Option<u64>) -> Result<Self, XLogError> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        Ok(Self {
            file,
            current_pos: 0,
            eof: false,
            page_limit: limit,
            pages_read: 0,
            file_size,
        })
    }

    pub fn read_page_header(&mut self) -> Result<Option<XLogPageHeader>, XLogError> {
        // Check if we've hit the page limit
        if let Some(limit) = self.page_limit {
            if self.pages_read >= limit {
                return Ok(None);
            }
        }

        // Check if we've reached the end of the file
        if self.current_pos >= self.file_size {
            self.eof = true;
            return Ok(None);
        }

        // Read the page header
        let mut header_bytes = [0u8; XLOG_PAGE_HEADER_SIZE];
        match self.file.read_exact(&mut header_bytes) {
            Ok(_) => {
                let mut cursor = io::Cursor::new(header_bytes);
                let magic = cursor.read_u16::<LittleEndian>()?;
                let info = cursor.read_u16::<LittleEndian>()?;
                let timeline = cursor.read_u16::<LittleEndian>()?;
                let pageaddr = cursor.read_u64::<LittleEndian>()?;
                let rem_len = cursor.read_u32::<LittleEndian>()?;
                // Skip the 2-byte hole at the end
                cursor.seek(SeekFrom::Current(2))?;

                // Check for zero header (empty page)
                if magic == 0 && info == 0 && timeline == 0 {
                    println!("Found zero header at position {} (page {})", self.current_pos, self.pages_read + 1);
                    self.eof = true;
                    return Ok(None);
                }

                // Validate magic number
                if magic != XLOG_PAGE_MAGIC {
                    self.pages_read += 1;
                    return Err(XLogError::InvalidRecord(format!("Invalid page magic number: {:X}", magic)));
                }

                // Move to the next page boundary
                let bytes_to_skip = XLOG_BLCKSZ - XLOG_PAGE_HEADER_SIZE as u64;
                if bytes_to_skip > 0 {
                    self.file.seek(SeekFrom::Current(bytes_to_skip as i64))?;
                }

                self.current_pos += XLOG_BLCKSZ;
                self.pages_read += 1;

                Ok(Some(XLogPageHeader::new(magic, info, timeline, pageaddr, rem_len)))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.eof = true;
                Ok(None)
            }
            Err(e) => Err(XLogError::Io(e)),
        }
    }

    fn read_record_header(&mut self) -> Result<Option<XLogRecord>, XLogError> {
        let mut header_bytes = [0u8; XLOG_RECORD_HEADER_SIZE];
        match self.file.read_exact(&mut header_bytes) {
            Ok(_) => {
                let mut cursor = io::Cursor::new(header_bytes);
                let xl_tot_len = cursor.read_u32::<LittleEndian>()?;
                if xl_tot_len == 0 {
                    return Ok(None);
                }
                let xl_xid = cursor.read_u32::<LittleEndian>()?;
                let xl_prev = cursor.read_u64::<LittleEndian>()?;
                let xl_info = cursor.read_u8()?;
                let xl_rmid = cursor.read_u8()?;
                // Skip 2 bytes of padding
                cursor.seek(SeekFrom::Current(2))?;
                let xl_crc = cursor.read_u32::<LittleEndian>()?;

                // Read the record data
                let data_len = xl_tot_len as usize - XLOG_RECORD_HEADER_SIZE;
                let mut xl_data = vec![0u8; data_len];
                match self.file.read_exact(&mut xl_data) {
                    Ok(_) => Ok(Some(XLogRecord::new(
                        xl_tot_len,
                        xl_xid,
                        xl_prev,
                        xl_info,
                        xl_rmid,
                        xl_crc,
                        xl_data,
                    ))),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
                    Err(e) => Err(XLogError::Io(e)),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(XLogError::Io(e)),
        }
    }

    pub fn read_page_records(&mut self) -> Result<Vec<XLogRecord>, XLogError> {
        let mut records = Vec::new();
        
        // Read the page header first
        if let Some(header) = self.read_page_header()? {
            // Calculate remaining bytes in the page
            let page_start = (self.current_pos / XLOG_BLCKSZ) * XLOG_BLCKSZ;
            let page_end = page_start + XLOG_BLCKSZ;
            let mut remaining = page_end - self.current_pos;

            // Read records until we hit the end of the page or run out of data
            while remaining >= XLOG_RECORD_HEADER_SIZE as u64 {
                match self.read_record_header()? {
                    Some(record) => {
                        remaining = remaining.saturating_sub(record.xl_tot_len as u64);
                        records.push(record);
                    }
                    None => break,
                }
            }

            // Seek to the next page boundary
            self.file.seek(SeekFrom::Start(page_end))?;
            self.current_pos = page_end;
        }

        Ok(records)
    }
}

impl Iterator for XLogReader {
    type Item = Result<Vec<XLogRecord>, XLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_page_records() {
            Ok(records) if !records.is_empty() => Some(Ok(records)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_xlog_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        
        // Write a page header
        let mut header = [0u8; XLOG_PAGE_HEADER_SIZE];
        let mut cursor = io::Cursor::new(&mut header);
        cursor.write_u16::<LittleEndian>(XLOG_PAGE_MAGIC).unwrap(); // magic
        cursor.write_u16::<LittleEndian>(0x5).unwrap(); // info
        cursor.write_u16::<LittleEndian>(1).unwrap(); // timeline
        cursor.write_u64::<LittleEndian>(0x100000000).unwrap(); // pageaddr
        cursor.write_u32::<LittleEndian>(100).unwrap(); // rem_len
        file.write_all(&header).unwrap();

        // Write two test records
        // Record 1
        let mut record1_header = [0u8; XLOG_RECORD_HEADER_SIZE];
        let mut cursor = io::Cursor::new(&mut record1_header);
        cursor.write_u32::<LittleEndian>(50).unwrap(); // xl_tot_len
        cursor.write_u32::<LittleEndian>(1).unwrap(); // xl_xid
        cursor.write_u64::<LittleEndian>(0x100000000).unwrap(); // xl_prev
        cursor.write_u8(0x4D).unwrap(); // xl_info
        cursor.write_u8(1).unwrap(); // xl_rmid (Transaction)
        cursor.seek(SeekFrom::Current(2)).unwrap(); // padding
        cursor.write_u32::<LittleEndian>(0).unwrap(); // xl_crc
        file.write_all(&record1_header).unwrap();

        // Record 1 data
        let record1_data = vec![0u8; 26]; // 50 - 24 (header size)
        file.write_all(&record1_data).unwrap();

        // Record 2
        let mut record2_header = [0u8; XLOG_RECORD_HEADER_SIZE];
        let mut cursor = io::Cursor::new(&mut record2_header);
        cursor.write_u32::<LittleEndian>(50).unwrap(); // xl_tot_len
        cursor.write_u32::<LittleEndian>(2).unwrap(); // xl_xid
        cursor.write_u64::<LittleEndian>(0x100000050).unwrap(); // xl_prev
        cursor.write_u8(0x8D).unwrap(); // xl_info
        cursor.write_u8(2).unwrap(); // xl_rmid (Storage)
        cursor.seek(SeekFrom::Current(2)).unwrap(); // padding
        cursor.write_u32::<LittleEndian>(0).unwrap(); // xl_crc
        file.write_all(&record2_header).unwrap();

        // Record 2 data
        let record2_data = vec![0u8; 26]; // 50 - 24 (header size)
        file.write_all(&record2_data).unwrap();

        // Fill the rest of the page with zeros
        let remaining = XLOG_BLCKSZ - (XLOG_PAGE_HEADER_SIZE + 100) as u64;
        let zeros = vec![0u8; remaining as usize];
        file.write_all(&zeros).unwrap();

        file
    }

    #[test]
    fn test_read_xlog_records() {
        let test_file = create_test_xlog_file();
        let mut reader = XLogReader::new(test_file.path(), None).unwrap();
        
        // Read records from the first page
        let records = reader.read_page_records().unwrap();
        
        // Verify we read exactly 2 records
        assert_eq!(records.len(), 2);
        
        // Verify first record
        let record1 = &records[0];
        assert_eq!(record1.xl_tot_len, 50);
        assert_eq!(record1.xl_xid, 1);
        assert_eq!(record1.xl_prev, 0x100000000);
        assert_eq!(record1.xl_info, 0x4D);
        assert_eq!(record1.xl_rmid, RmgrId::Transaction);
        assert_eq!(record1.xl_crc, 0);
        assert_eq!(record1.xl_data.len(), 26);
        
        // Verify second record
        let record2 = &records[1];
        assert_eq!(record2.xl_tot_len, 50);
        assert_eq!(record2.xl_xid, 2);
        assert_eq!(record2.xl_prev, 0x100000050);
        assert_eq!(record2.xl_info, 0x8D);
        assert_eq!(record2.xl_rmid, RmgrId::Storage);
        assert_eq!(record2.xl_crc, 0);
        assert_eq!(record2.xl_data.len(), 26);
    }
} 