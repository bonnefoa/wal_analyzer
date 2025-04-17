use crate::error::XLogError;
use crate::xlog_block::{parse_blocks, XLBData};
use log::debug;
use nom::bytes::complete::take;
use nom::multi;
use nom::number::complete::{le_u32, le_u64, le_u8};
use nom::IResult;
use nom::Parser;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RmgrId {
    Xlog,
    Transaction,
    Storage,
    Clog,
    Database,
    Tablespace,
    MultiXact,
    RelMap,
    Standby,
    Heap,
    Heap2,
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
            0x00 => RmgrId::Xlog,
            0x01 => RmgrId::Transaction,
            0x02 => RmgrId::Storage,
            0x03 => RmgrId::Clog,
            0x04 => RmgrId::Database,
            0x05 => RmgrId::Tablespace,
            0x06 => RmgrId::MultiXact,
            0x07 => RmgrId::RelMap,
            0x08 => RmgrId::Standby,
            0x09 => RmgrId::Heap2,
            0x0a => RmgrId::Heap,
            0x0b => RmgrId::Btree,
            0x0c => RmgrId::Hash,
            0x0d => RmgrId::Gin,
            0x0e => RmgrId::Gist,
            0x0f => RmgrId::Sequence,
            0x10 => RmgrId::Spgist,
            0x11 => RmgrId::Brin,
            0x12 => RmgrId::CommitTs,
            0x13 => RmgrId::ReplicationOrigin,
            0x14 => RmgrId::Generic,
            0x15 => RmgrId::LogicalMsg,
            unused => RmgrId::Unused(unused),
        }
    }
}

impl std::fmt::Display for RmgrId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            RmgrId::Xlog => "Xlog",
            RmgrId::Transaction => "Transaction",
            RmgrId::Storage => "Storage",
            RmgrId::Clog => "Clog",
            RmgrId::Database => "Database",
            RmgrId::Tablespace => "Tablespace",
            RmgrId::MultiXact => "MultiXact",
            RmgrId::RelMap => "RelMap",
            RmgrId::Standby => "Standby",
            RmgrId::Heap => "Heap",
            RmgrId::Heap2 => "Heap2",
            RmgrId::Btree => "Btree",
            RmgrId::Hash => "Hash",
            RmgrId::Gin => "Gin",
            RmgrId::Gist => "Gist",
            RmgrId::Sequence => "Sequence",
            RmgrId::Spgist => "Spgist",
            RmgrId::Brin => "Brin",
            RmgrId::CommitTs => "CommitTs",
            RmgrId::ReplicationOrigin => "ReplicationOrigin",
            RmgrId::Generic => "Generic",
            RmgrId::LogicalMsg => "LogicalMsg",
            RmgrId::Unused(_) => "Unused",
        };
        write!(f, "{}", s)
    }
}

pub const XLOG_RECORD_HEADER_SIZE: u32 = 24;

#[derive(Clone, Debug)]
pub struct XLogRecord {
    pub header: XLogRecordHeader,
    pub blocks: Vec<XLBData>,
}

#[derive(Clone, Debug)]
pub struct XLogRecordHeader {
    // Total length of the record
    pub xl_tot_len: u32,
    // Transaction ID
    pub xl_xid: u32,
    // Pointer to previous record (LSN)
    pub xl_prev: u64,
    // Flag bits
    pub xl_info: u8,
    // Resource manager for this record
    pub xl_rmid: RmgrId,
    // CRC for this record
    pub xl_crc: u32,
}

impl std::fmt::Display for XLogRecordHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "rmgr: {}, len: {}, tx: {}, prev: 0x{:08X}",
            self.xl_rmid, self.xl_tot_len, self.xl_xid, self.xl_prev
        )
    }
}

impl std::fmt::Display for XLogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.header)
    }
}

pub fn consume_padding(i: &[u8], size: usize) -> IResult<&[u8], (), XLogError<&[u8]>> {
    if size == 0 {
        return Ok((i, ()));
    }
    let (i, padding) = take(size)(i)?;
    debug!("Consumed padding {} from input of size {}", size, i.len());
    if size > 8 {
        return Err(nom::Err::Error(XLogError::IncorrectPaddingLength(size)));
    }
    if padding.iter().all(|x| *x != 0) {
        return Err(nom::Err::Error(XLogError::IncorrectPaddingValue(
            padding.to_owned(),
        )));
    }
    Ok((i, ()))
}

pub fn parse_xlog_record_header(i: &[u8]) -> IResult<&[u8], XLogRecordHeader, XLogError<&[u8]>> {
    let header_size = XLOG_RECORD_HEADER_SIZE as usize;
    if i.len() < header_size {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            header_size - i.len(),
        )));
    }

    let (i, xl_tot_len) = le_u32(i)?;
    if xl_tot_len == 0 {
        // Last record of the page
        return Err(nom::Err::Error(XLogError::EmptyRecord));
    }
    let (i, xl_xid) = le_u32(i)?;
    let (i, xl_prev) = le_u64(i)?;
    let (i, xl_info) = le_u8(i)?;
    let (i, xl_rmid) = le_u8(i).map(|(i, x)| (i, RmgrId::from(x)))?;
    let (i, _) = consume_padding(i, 2)?;
    let (i, xl_crc) = le_u32(i)?;
    let data_len = (xl_tot_len - XLOG_RECORD_HEADER_SIZE) as usize;
    if i.len() < data_len {
        return Err(nom::Err::Incomplete(nom::Needed::new(data_len)));
    }

    let record = XLogRecordHeader {
        xl_tot_len,
        xl_xid,
        xl_prev,
        xl_info,
        xl_rmid,
        xl_crc,
    };
    debug!("Parsed record header {}", record);
    Ok((i, record))
}

/// Parse record header, block headers and block contents
pub fn parse_xlog_record(i: &[u8]) -> IResult<&[u8], XLogRecord, XLogError<&[u8]>> {
    let (i, header) = parse_xlog_record_header(i)?;

    // Create a subslice with block headers and data
    let record_length = (header.xl_tot_len - XLOG_RECORD_HEADER_SIZE) as usize;
    let block_bytes = &i[..record_length];

    let (block_bytes, blocks) = parse_blocks(block_bytes)?;
    if !block_bytes.is_empty() {
        return Err(nom::Err::Error(XLogError::LeftoverBytes(
            block_bytes.to_owned(),
        )));
    }

    // Padding needs to be consumed
    let i = &i[record_length..];
    let (i, _) = consume_padding(i, i.len() % 8)?;
    Ok((i, XLogRecord { header, blocks }))
}

pub fn parse_xlog_records(i: &[u8]) -> IResult<&[u8], Vec<XLogRecord>, XLogError<&[u8]>> {
    multi::many1(parse_xlog_record).parse(i)
}
