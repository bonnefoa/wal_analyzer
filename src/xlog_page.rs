use std::mem;

use crate::error::XLogError;
use crate::xlog_record::{consume_padding, parse_xlog_records, XLogRecord};
use log::debug;
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

impl std::fmt::Display for XLogShortPageHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "xlp_magic: 0x{:02X}, xlp_info: 0x{:02X}, xlp_tli: {}, xlp_pageaddr: 0x{:08X}, xlp_rem_len: {}",
            self.xlp_magic, self.xlp_info, self.xlp_tli, self.xlp_pageaddr, self.xlp_rem_len
        )
    }
}

impl std::fmt::Display for XLogLongPageHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "std: {}, xlp_sysid: 0x{:08X}, xlp_seg_size: 0x{:04X}, xlp_xlog_blcksz: 0x{:04X}",
            self.std, self.xlp_sysid, self.xlp_seg_size, self.xlp_xlog_blcksz
        )
    }
}

impl std::fmt::Display for XLogPageHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            XLogPageHeader::Short(xlog_short_page_header) => {
                write!(f, "Short page header: {}", xlog_short_page_header)
            }
            XLogPageHeader::Long(long_page_header) => {
                write!(f, "Long page header: {}", long_page_header)
            }
        }
    }
}

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

pub fn parse_xlog_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    let start_size = i.len();
    let short_header_size = mem::size_of::<XLogShortPageHeader>();
    if start_size < short_header_size {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            short_header_size - start_size,
        )));
    }
    let (i, xlp_magic) = le_u16(i)?;
    if xlp_magic != XLP_MAGIC {
        return Err(nom::Err::Failure(XLogError::InvalidPageHeader));
    }
    let (i, xlp_info) = le_u16(i)?;
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
    if xlp_info & XLP_LONG_HEADER == 0 {
        debug!("Parsed a short page header at {}, {}", xlp_pageaddr, std);
        return Ok((i, XLogPageHeader::from(std)));
    }

    // We have a long page header
    let long_header_size = mem::size_of::<XLogLongPageHeader>();
    if start_size < long_header_size {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            long_header_size - start_size,
        )));
    }

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
    debug!(
        "Parsed a long page header at {:#02x}, {}",
        xlp_pageaddr, page_header
    );
    Ok((i, XLogPageHeader::from(page_header)))
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
