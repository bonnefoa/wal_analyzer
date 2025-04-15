use crate::error::XLogError;
use log::debug;
use nom::bytes::complete::take;
use nom::error::dbg_dmp;
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

pub const XLOG_RECORD_HEADER_SIZE: u32 = 24;
pub const BKPBLOCK_FORK_MASK: u8 = 0x0F;
pub const BKPBLOCK_FLAG_MASK: u8 = 0xF0;
pub const BKPBLOCK_HAS_IMAGE: u8 = 0x10; /* block data is an XLogRecordBlockImage */
pub const BKPBLOCK_HAS_DATA: u8 = 0x20;
pub const BKPBLOCK_WILL_INIT: u8 = 0x40; /* redo will re-init the page */
pub const BKPBLOCK_SAME_REL: u8 = 0x80; /* RelFileNode omitted, same as previous */

pub const XLR_BLOCK_ID_TOPLEVEL_XID: u8 = 0xfc;
pub const XLR_BLOCK_ID_ORIGIN: u8 = 0xfd;
pub const XLR_BLOCK_ID_DATA_LONG: u8 = 0xfe;
pub const XLR_BLOCK_ID_DATA_SHORT: u8 = 0xff;

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

#[derive(Clone, Debug)]
pub struct XLBData {
    pub blk_id: u8,
    pub fork_num: u8,
    pub has_image: bool,
    pub has_data: bool,
    pub flags: u8,
    pub data_len: u32,
    pub data: Vec<u8>,
}

impl std::fmt::Display for XLogRecordHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "rmgr: {}, len: {}, tx: {}, prev: {:08X}",
            self.xl_rmid, self.xl_tot_len, self.xl_xid, self.xl_prev
        )
    }
}

impl std::fmt::Display for XLogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}", self.header
        )
    }
}

pub fn consume_padding(i: &[u8], size: usize) -> IResult<&[u8], (), XLogError<&[u8]>> {
    let (i, padding) = take(size)(i)?;
    if padding.iter().all(|x| *x != 0) {
        return Err(nom::Err::Error(XLogError::IncorrectPaddingValue(padding.to_owned())));
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
    let (i, rmid) = le_u8(i)?;
    let (i, _) = consume_padding(i, 2)?;
    let (i, xl_crc) = le_u32(i)?;
    let data_len = (xl_tot_len - XLOG_RECORD_HEADER_SIZE) as usize;
    if i.len() < data_len {
        return Err(nom::Err::Incomplete(nom::Needed::new(data_len)));
    }

    let xl_rmid = RmgrId::from(rmid);

    let record = XLogRecordHeader {
        xl_tot_len,
        xl_xid,
        xl_prev,
        xl_info,
        xl_rmid,
        xl_crc,
    };
    debug!("Parsed record {}", record);
    Ok((i, record))
}

pub fn parse_xlog_record(i: &[u8]) -> IResult<&[u8], XLogRecord, XLogError<&[u8]>> {
    let (i, header) = parse_xlog_record_header(i)?;
    let (i, mut blocks) = parse_block_headers(i)?;

    let mut input = i;
    for data_block in &mut blocks {
        let (i, data) = take(data_block.data_len)(input)?;
        input = i;
        data_block.data.clone_from_slice(data);
    }

    let (i, _) = consume_padding(input, input.len() % 8)?;

    Ok((i, XLogRecord { header, blocks }))
}

pub fn parse_main_data_block_header(i: &[u8]) -> IResult<&[u8], XLBData, XLogError<&[u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id != XLR_BLOCK_ID_DATA_SHORT && blk_id != XLR_BLOCK_ID_DATA_LONG {
        return Err(nom::Err::Error(XLogError::IncorrectId(blk_id)));
    }

    let (i, data_len) = if blk_id == XLR_BLOCK_ID_DATA_SHORT {
        le_u8(i).map(|(i, x)| (i, u32::from(x)))?
    } else {
        le_u16(i).map(|(i, x)| (i, u32::from(x)))?
    };

    let data = vec![0; data_len as usize];
    let block_header = XLBData {
        blk_id,
        fork_num: 0,
        flags: 0,
        has_image: false,
        has_data: true,
        data_len,
        data,
    };
    Ok((i, block_header))
}

pub fn parse_data_block_header(i: &[u8]) -> IResult<&[u8], XLBData, XLogError<&[u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id == 0xff {
        return Err(nom::Err::Error(XLogError::EndBlock));
    }

    let (i, fork_flags) = le_u8(i)?;
    let fork_num = fork_flags & BKPBLOCK_FORK_MASK;
    let flags = fork_flags & BKPBLOCK_FLAG_MASK;
    let has_image = fork_flags & BKPBLOCK_HAS_IMAGE > 0;
    let has_data = fork_flags & BKPBLOCK_HAS_DATA > 0;
    let (i, data_len) = le_u16(i)?;
    let data = vec![0; data_len as usize];
    let block = XLBData {
        blk_id,
        fork_num,
        flags,
        has_image,
        has_data,
        data_len: data_len as u32,
        data,
    };
    Ok((i, block))
}

pub fn parse_block_headers(i: &[u8]) -> IResult<&[u8], Vec<XLBData>, XLogError<&[u8]>> {
    let (i, mut data_blocks) = multi::many0(parse_data_block_header).parse(i)?;
    let (i, main_data) = parse_main_data_block_header(i)?;
    data_blocks.push(main_data);
    Ok((i, data_blocks))
}

pub fn parse_xlog_records(i: &[u8]) -> IResult<&[u8], Vec<XLogRecord>, XLogError<&[u8]>> {
    multi::many1(parse_xlog_record).parse(i)
}
