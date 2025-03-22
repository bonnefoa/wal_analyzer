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

const XLOG_BLCKSZ: usize = 8192;
const XLOG_PAGE_MAGIC: u16 = 0xD10D; // PostgreSQL XLOG_PAGE_MAGIC
const XLOG_PAGE_HEADER_SIZE: usize = 20; // 2 bytes magic + 2 bytes info + 2 bytes tli + 8 bytes LSN + 4 bytes rem_len + 2 bytes hole

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

        // Align to XLOG page boundary
        let page_offset = self.current_pos % XLOG_BLCKSZ as u64;
        if page_offset != 0 {
            let skip = XLOG_BLCKSZ as u64 - page_offset;
            self.file.seek(SeekFrom::Current(skip as i64))?;
            self.current_pos += skip;
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
                let bytes_to_skip = XLOG_BLCKSZ - XLOG_PAGE_HEADER_SIZE;
                if bytes_to_skip > 0 {
                    self.file.seek(SeekFrom::Current(bytes_to_skip as i64))?;
                }

                self.current_pos += XLOG_BLCKSZ as u64;
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
}

impl Iterator for XLogReader {
    type Item = Result<XLogPageHeader, XLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_page_header() {
            Ok(Some(header)) => Some(Ok(header)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
} 