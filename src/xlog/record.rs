use std::mem;

use crate::error::XLogError;
use crate::xlog::block::{parse_blocks, XLBData};
use log::debug;
use nom::bytes::complete::take;
use nom::multi;
use nom::number::complete::{le_u32, le_u64, le_u8};
use nom::IResult;
use nom::Parser;

use super::operation::heap::{parse_heap_operation, HeapOperation};

const XLOG_RECORD_HEADER_SIZE: usize = mem::size_of::<XLogRecordHeader>();

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
}

impl TryFrom<u8> for RmgrId {
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(RmgrId::Xlog),
            0x01 => Ok(RmgrId::Transaction),
            0x02 => Ok(RmgrId::Storage),
            0x03 => Ok(RmgrId::Clog),
            0x04 => Ok(RmgrId::Database),
            0x05 => Ok(RmgrId::Tablespace),
            0x06 => Ok(RmgrId::MultiXact),
            0x07 => Ok(RmgrId::RelMap),
            0x08 => Ok(RmgrId::Standby),
            0x09 => Ok(RmgrId::Heap2),
            0x0a => Ok(RmgrId::Heap),
            0x0b => Ok(RmgrId::Btree),
            0x0c => Ok(RmgrId::Hash),
            0x0d => Ok(RmgrId::Gin),
            0x0e => Ok(RmgrId::Gist),
            0x0f => Ok(RmgrId::Sequence),
            0x10 => Ok(RmgrId::Spgist),
            0x11 => Ok(RmgrId::Brin),
            0x12 => Ok(RmgrId::CommitTs),
            0x13 => Ok(RmgrId::ReplicationOrigin),
            0x14 => Ok(RmgrId::Generic),
            0x15 => Ok(RmgrId::LogicalMsg),
            f => Err(f),
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
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug)]
pub enum Operation {
    Xlog,
    Transaction,
    Storage,
    Clog,
    Database,
    Tablespace,
    MultiXact,
    RelMap,
    Standby,
    Heap2,
    Heap(HeapOperation),
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
}

#[derive(Clone, Debug)]
pub struct XLogRecord {
    pub header: XLogRecordHeader,
    pub blocks: Vec<XLBData>,
    pub operation: Operation,
}

#[derive(Clone, Debug)]
pub struct XLogRecordHeader {
    /// Total length of the record
    pub xl_tot_len: u32,
    /// Transaction ID
    pub xl_xid: u32,
    /// Pointer to previous record (LSN)
    pub xl_prev: u64,

    // Info Mask
    pub special_rel_update: bool,
    pub check_consistency: bool,
    pub rmgr_info: u8,

    /// Resource manager for this record
    pub xl_rmid: RmgrId,
    /// CRC for this record
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
        writeln!(f, "{}", self.header)?;
        for block in &self.blocks {
            writeln!(f, " {}", block)?;
        }
        Ok(())
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
    let header_size = XLOG_RECORD_HEADER_SIZE;
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
    // First 4 bits of xl_info is used by rmgr
    let rmgr_info = xl_info & 0xf0;
    // Last 4 bits of xl_info
    let special_rel_update = xl_info & 0x01 != 0;
    let check_consistency = xl_info & 0x02 != 0;

    let (i, rmid) = le_u8(i)?;
    let xl_rmid = match RmgrId::try_from(rmid) {
        Ok(xl_rmid) => xl_rmid,
        Err(f) => return Err(nom::Err::Error(XLogError::InvalidResourceManager(f))),
    };

    let (i, _) = consume_padding(i, 2)?;
    let (i, xl_crc) = le_u32(i)?;
    let data_len = xl_tot_len as usize - XLOG_RECORD_HEADER_SIZE;
    if i.len() < data_len {
        return Err(nom::Err::Incomplete(nom::Needed::new(data_len)));
    }

    let record = XLogRecordHeader {
        xl_tot_len,
        xl_xid,
        xl_prev,
        special_rel_update,
        check_consistency,
        rmgr_info,
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
    let record_length = header.xl_tot_len as usize - XLOG_RECORD_HEADER_SIZE;
    let block_bytes = &i[..record_length];
    let (_, (main_block_start, blocks)) = parse_blocks(block_bytes)?;

    let (_, operation) = match header.xl_rmid {
        RmgrId::Xlog => (main_block_start, Operation::Xlog),
        RmgrId::Transaction => (main_block_start, Operation::Transaction),
        RmgrId::Storage => (main_block_start, Operation::Storage),
        RmgrId::Clog => (main_block_start, Operation::Clog),
        RmgrId::Database => (main_block_start, Operation::Database),
        RmgrId::Tablespace => (main_block_start, Operation::Tablespace),
        RmgrId::MultiXact => (main_block_start, Operation::MultiXact),
        RmgrId::RelMap => (main_block_start, Operation::RelMap),
        RmgrId::Standby => (main_block_start, Operation::Standby),
        RmgrId::Heap => parse_heap_operation(main_block_start)?,
        RmgrId::Heap2 => (main_block_start, Operation::Heap2),
        RmgrId::Btree => (main_block_start, Operation::Btree),
        RmgrId::Hash => (main_block_start, Operation::Hash),
        RmgrId::Gin => (main_block_start, Operation::Gin),
        RmgrId::Gist => (main_block_start, Operation::Gist),
        RmgrId::Sequence => (main_block_start, Operation::Sequence),
        RmgrId::Spgist => (main_block_start, Operation::Spgist),
        RmgrId::Brin => (main_block_start, Operation::Brin),
        RmgrId::CommitTs => (main_block_start, Operation::CommitTs),
        RmgrId::ReplicationOrigin => (main_block_start, Operation::ReplicationOrigin),
        RmgrId::Generic => (main_block_start, Operation::Generic),
        RmgrId::LogicalMsg => (main_block_start, Operation::LogicalMsg),
    };

    // Padding needs to be consumed
    let i = &i[record_length..];
    let (i, _) = consume_padding(i, i.len() % 8)?;
    Ok((
        i,
        XLogRecord {
            header,
            blocks,
            operation,
        },
    ))
}

pub fn parse_xlog_records(i: &[u8]) -> IResult<&[u8], Vec<XLogRecord>, XLogError<&[u8]>> {
    multi::many1(parse_xlog_record).parse(i)
}
