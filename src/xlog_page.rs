use crate::error::XLogError;
use nom::branch::alt;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::IResult;
use nom::Parser;

// When record crosses page boundary, set this flag in new page's header
const XLP_FIRST_IS_CONTRECORD: u16 = 0x0001;
// This flag indicates a "long" page header
const XLP_LONG_HEADER: u16 = 0x0002;
// This flag indicates backup blocks starting in this page are optional
const XLP_BKP_REMOVABLE: u16 = 0x0004;
// Replaces a missing contrecord; see CreateOverwriteContrecordRecord
const XLP_FIRST_IS_OVERWRITE_CONTRECORD: u16 = 0x0008;
// All defined flag bits in xlp_info (used for validity checking of header)
const XLP_ALL_FLAGS: u16 = 0x000F;

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
    if i.len() < 20 {
        return Err(nom::Err::Incomplete(nom::Needed::new(20 - i.len())));
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

    let page_header = XLogShortPageHeader {
        xlp_magic,
        xlp_info,
        xlp_tli,
        xlp_pageaddr,
        xlp_rem_len,
    };

    Ok((i, XLogPageHeader::from(page_header)))
}

// XLogSegNoOffsetToRecPtr
pub fn parse_xlog_long_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    if i.len() < 36 {
        return Err(nom::Err::Incomplete(nom::Needed::new(36 - i.len())));
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

    let std = XLogShortPageHeader {
        xlp_magic,
        xlp_info,
        xlp_tli,
        xlp_pageaddr,
        xlp_rem_len,
    };

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
    alt((parse_xlog_short_page_header, parse_xlog_long_page_header)).parse(i)
}
