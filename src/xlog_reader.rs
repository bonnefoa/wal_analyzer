use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use nom::Finish;

use crate::error::XLogError;
use crate::xlog_page::{parse_xlog_page, XLogPageContent};
use crate::xlog_record::XLogRecord;

pub type XLogRecPtr = u64;
pub type TimelineID = u32;

#[derive(Debug)]
pub enum ReaderError<I: Sized> {
    IoError(io::Error),
    ParseError(XLogError<I>),
}

impl<I> From<io::Error> for ReaderError<I> {
    fn from(item: io::Error) -> Self {
        ReaderError::<I>::IoError(item)
    }
}

impl<I> From<XLogError<I>> for ReaderError<I> {
    fn from(item: XLogError<I>) -> Self {
        ReaderError::ParseError(item)
    }
}

pub struct XLogReader {
    current_rec_ptr: XLogRecPtr,
    current_tli: TimelineID,

    data_dir: String,
    wal_seg_size: u64,
    f: File,
    buffer: [u8; 8192],
    page: Option<XLogPageContent>,
}

#[derive(Debug)]
pub struct XLogFilePos {
    pub tli: u32,
    pub log: u32,
    pub seg: u32,
}

impl XLogFilePos {
    pub fn get_xlog_rec_ptr(&self, wal_seg_size: u64) -> XLogRecPtr {
        u64::from(self.log) * wal_seg_size + u64::from(self.seg)
    }
}

pub fn parse_filename(fname: &str) -> Result<XLogFilePos, std::num::ParseIntError> {
    let tli = u32::from_str_radix(&fname[0..8], 16)?;
    let log = u32::from_str_radix(&fname[8..16], 16)?;
    let seg = u32::from_str_radix(&fname[16..24], 16)?;
    Ok(XLogFilePos { tli, log, seg })
}

impl XLogReader {
    pub fn new_from_filename(walsegment: PathBuf) -> Result<Self, Box<dyn Error>> {
        let data_dir = String::from(walsegment.parent().unwrap().to_str().unwrap());
        let file_pos = parse_filename(walsegment.file_name().unwrap().to_str().unwrap())?;
        let f = File::open(walsegment)?;
        let metadata = f.metadata()?;
        let wal_seg_size = metadata.size();
        let current_rec_ptr = file_pos.get_xlog_rec_ptr(wal_seg_size);
        let buffer = [0; 8192];
        let page = None;

        Ok(Self {
            current_rec_ptr,
            current_tli: file_pos.tli,
            data_dir,
            wal_seg_size,
            f,
            buffer,
            page,
        })
    }

    fn xlog_ptr_to_walfile(&self, xlrp: XLogRecPtr) -> String {
        let log = xlrp / self.wal_seg_size;
        let seg = xlrp % self.wal_seg_size;
        let wal_filename = format!("{}{}{}", self.current_tli, log, seg);
        format!("{}/pg_wal/{}", self.data_dir, wal_filename)
    }

    pub fn read_next_page(&mut self) -> Result<XLogPageContent, ReaderError<&[u8]>> {
        self.f.read_exact(&mut self.buffer)?;
        let (_i, r) = parse_xlog_page(&self.buffer).finish()?;
        Ok(r)
    }

    pub fn pop_record(&mut self) -> Option<XLogRecord> {
        self.page.as_mut().and_then(|p| p.records.pop())
    }
}

impl Iterator for XLogReader {
    type Item = XLogRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.page.as_ref().map_or(0, |p| p.records.len()) == 0 {
            match self.read_next_page() {
                Ok(page) => self.page = Some(page),
                Err(_) => return None,
            };
        }
        self.pop_record()
    }
}
