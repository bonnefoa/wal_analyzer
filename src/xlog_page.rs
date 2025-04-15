use std::mem;

use crate::error::XLogError;
use crate::xlog_record::{consume_padding, parse_xlog_records, XLogRecord};
use log::debug;
use nom::branch;
use nom::combinator::map;
use nom::multi::many1;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::IResult;
use nom::Parser;

// When record crosses page boundary, set this flag in new page's header
pub const XLP_FIRST_IS_CONTRECORD: u16 = 0x0001;
// This flag indicates a "long" page header
pub const XLP_LONG_HEADER: u16 = 0x0002;
// This flag indicates backup blocks starting in this page are optional
pub const XLP_BKP_REMOVABLE: u16 = 0x0004;
// Replaces a missing contrecord; see CreateOverwriteContrecordRecord
pub const XLP_FIRST_IS_OVERWRITE_CONTRECORD: u16 = 0x0008;
// All defined flag bits in xlp_info (used for validity checking of header)
pub const XLP_ALL_FLAGS: u16 = 0x000F;

const XLP_MAGIC: u16 = 0xd10d;

#[derive(Clone, Debug)]
pub struct XLogShortPageHeader {
    pub xlp_magic: u16,
    pub xlp_info: u16,
    pub xlp_tli: u32,
    pub xlp_pageaddr: u64,
    pub xlp_rem_len: u32,
}

#[derive(Clone, Debug)]
pub struct XLogLongPageHeader {
    // standard header fiels
    pub std: XLogShortPageHeader,
    // system identifier from pg_control
    pub xlp_sysid: u64,
    // just as a cross-check
    pub xlp_seg_size: u32,
    // just as a cross-check
    pub xlp_xlog_blcksz: u32,
}

#[derive(Clone, Debug)]
pub enum XLogPageHeader {
    Short(XLogShortPageHeader),
    Long(XLogLongPageHeader),
}

#[derive(Debug)]
pub struct XLogPageContent {
    pub page_header: XLogPageHeader,
    pub records: Vec<XLogRecord>,
}

impl From<XLogShortPageHeader> for XLogPageHeader {
    fn from(value: XLogShortPageHeader) -> Self {
        XLogPageHeader::Short(value)
    }
}

impl From<XLogLongPageHeader> for XLogPageHeader {
    fn from(value: XLogLongPageHeader) -> Self {
        XLogPageHeader::Long(value)
    }
}

pub fn parse_xlog_short_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    let header_size = mem::size_of::<XLogShortPageHeader>();

    if i.len() < mem::size_of::<XLogShortPageHeader>() {
        return Err(nom::Err::Incomplete(nom::Needed::new(header_size - i.len())));
    }

    let (i, xlp_magic) = le_u16(i)?;
    if xlp_magic != XLP_MAGIC {
        return Err(nom::Err::Failure(XLogError::InvalidPageHeader));
    }

    let (i, xlp_info) = le_u16(i)?;
    if xlp_info & XLP_LONG_HEADER > 0 {
        return Err(nom::Err::Error(XLogError::IncorrectPageType));
    }

    let (i, xlp_tli) = le_u32(i)?;
    let (i, xlp_pageaddr) = le_u64(i)?;
    let (i, xlp_rem_len) = le_u32(i)?;

    debug!(
        "Parsed a short page at {}, remaning length {}",
        xlp_pageaddr, xlp_rem_len
    );
    let page_header = XLogShortPageHeader {
        xlp_magic,
        xlp_info,
        xlp_tli,
        xlp_pageaddr,
        xlp_rem_len,
    };

    Ok((i, XLogPageHeader::from(page_header)))
}

pub fn parse_xlog_long_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    let header_size = mem::size_of::<XLogLongPageHeader>();
    if i.len() < mem::size_of::<XLogLongPageHeader>() {
        return Err(nom::Err::Incomplete(nom::Needed::new(header_size - i.len())));
    }

    let (i, xlp_magic) = le_u16(i)?;
    if xlp_magic != XLP_MAGIC {
        return Err(nom::Err::Failure(XLogError::InvalidPageHeader));
    }

    let (i, xlp_info) = le_u16(i)?;
    if xlp_info & XLP_LONG_HEADER == 0 {
        return Err(nom::Err::Error(XLogError::IncorrectPageType));
    }

    let (i, xlp_tli) = le_u32(i)?;
    let (i, xlp_pageaddr) = le_u64(i)?;
    let (i, xlp_rem_len) = le_u32(i)?;

    debug!(
        "Parsed a long page at {:#02x}, remaning length {}",
        xlp_pageaddr, xlp_rem_len
    );
    let std = XLogShortPageHeader {
        xlp_magic,
        xlp_info,
        xlp_tli,
        xlp_pageaddr,
        xlp_rem_len,
    };

    // 4 bytes of memory padding
    let (i, _) = consume_padding(i, 4)?;
    let (i, xlp_sysid) = le_u64(i)?;
    let (i, xlp_seg_size) = le_u32(i)?;
    let (i, xlp_xlog_blcksz) = le_u32(i)?;

    let page_header = XLogLongPageHeader {
        std,
        xlp_sysid,
        xlp_seg_size,
        xlp_xlog_blcksz,
    };

    Ok((i, XLogPageHeader::from(page_header)))
}

pub fn parse_xlog_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    branch::alt((parse_xlog_short_page_header, parse_xlog_long_page_header)).parse(i)
}

pub fn parse_xlog_page(i: &[u8]) -> IResult<&[u8], XLogPageContent, XLogError<&[u8]>> {
    map((parse_xlog_page_header, parse_xlog_records), |t| {
        XLogPageContent {
            page_header: t.0,
            records: t.1,
        }
    })
    .parse(i)
}

pub fn parse_xlog_pages(i: &[u8]) -> IResult<&[u8], Vec<XLogPageContent>, XLogError<&[u8]>> {
    many1(parse_xlog_page).parse(i)
}
