use crate::error::XLogError;
use nom::{
    bytes::complete::take,
    number::complete::{le_u32, le_u64, le_u8},
    IResult,
};

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
            0x00 => RmgrId::Xlog,
            0x01 => RmgrId::Transaction,
            0x02 => RmgrId::Storage,
            0x03 => RmgrId::Clog,
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
            unused => RmgrId::Unused(unused),
        }
    }
}

const XLOG_RECORD_HEADER_SIZE: usize = 22;

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

pub fn parse_xlog_record(i: &[u8]) -> IResult<&[u8], XLogRecord, XLogError<&[u8]>> {
    if i.len() < XLOG_RECORD_HEADER_SIZE {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            XLOG_RECORD_HEADER_SIZE - i.len(),
        )));
    }

    let (i, xl_tot_len) = le_u32(i)?;
    let (i, xl_xid) = le_u32(i)?;
    let (i, xl_prev) = le_u64(i)?;
    let (i, xl_info) = le_u8(i)?;
    let (i, rmid) = le_u8(i)?;
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
    // TODO: Process record blocks
    let (i, _data) = take(xl_tot_len - 22)(i)?;

    Ok((i, record))
}
