use crate::error::XLogError;
use log::debug;
use nom::bytes::complete::take;
use nom::multi;
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};
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

const XLOG_RECORD_HEADER_SIZE: u32 = 24;

#[derive(Clone, Debug)]
pub struct XLogRecord {
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

impl std::fmt::Display for XLogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "rmgr: {}, len: {}, tx: {}, prev: {:08X}",
            self.xl_rmid, self.xl_tot_len, self.xl_xid, self.xl_prev
        )
    }
}

pub fn parse_xlog_record(i: &[u8]) -> IResult<&[u8], XLogRecord, XLogError<&[u8]>> {
    let header_size = XLOG_RECORD_HEADER_SIZE as usize;
    if i.len() < header_size {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            header_size - i.len(),
        )));
    }

    let (i, xl_tot_len) = le_u32(i)?;
    let (i, xl_xid) = le_u32(i)?;
    let (i, xl_prev) = le_u64(i)?;
    let (i, xl_info) = le_u8(i)?;
    let (i, rmid) = le_u8(i)?;
    let (i, padding) = le_u16(i)?;
    if padding != 0 {
        return Err(nom::Err::Error(XLogError::IncorrectPaddingValue(
            u32::from(padding),
        )));
    }
    let (i, xl_crc) = le_u32(i)?;

    let xl_rmid = RmgrId::from(rmid);
    let record = XLogRecord {
        xl_tot_len,
        xl_xid,
        xl_prev,
        xl_info,
        xl_rmid,
        xl_crc,
    };

    debug!("Parsed a record of {}", xl_tot_len);

    // TODO: Process record blocks
    let data_len = (xl_tot_len - XLOG_RECORD_HEADER_SIZE) as usize;
    if i.len() < data_len {
        return Err(nom::Err::Incomplete(nom::Needed::new(data_len)));
    }
    let (i, _data) = take(data_len)(i)?;
    let (i, _padding) = take(i.len() % 8)(i)?;
    // Check padding value

    Ok((i, record))
}

pub fn parse_xlog_records(i: &[u8]) -> IResult<&[u8], Vec<XLogRecord>, XLogError<&[u8]>> {
    multi::many1(parse_xlog_record).parse(i)
}
