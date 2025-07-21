use std::mem;

use log::debug;
use nom::IResult;
use nom::number::complete::{le_u16, le_u32};
use nom::error::{ErrorKind, ParseError};
use nom::Parser;

use crate::xlog::common::TransactionId;

#[derive(Debug)]
pub enum InspectError<I: Sized> {
    /// An error encountered during parsing
    NomParseError(I, ErrorKind),
}

impl<I> ParseError<I> for InspectError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        InspectError::NomParseError(input, kind)
    }
    fn append(input: I, kind: ErrorKind, _other: Self) -> Self {
        InspectError::NomParseError(input, kind)
    }
}

impl<I> ParseError<(I, usize)> for InspectError<I> {
    fn from_error_kind((input, _s): (I, usize), kind: ErrorKind) -> Self {
        InspectError::NomParseError(input, kind)
    }
    fn append((input, _s): (I, usize), kind: ErrorKind, _other: Self) -> Self {
        InspectError::NomParseError(input, kind)
    }
}

impl<I> From<InspectError<I>> for nom::Err<InspectError<I>> {
    fn from(item: InspectError<I>) -> Self {
        nom::Err::Error(item)
    }
}

type LocationIndex = u16;

#[derive(Debug, PartialEq)]
pub struct PageXLogRecPtr {
    /// high bits
    pub xlogid: u32,
    /// low bits
    pub xrecoff: u32,
}

#[derive(Debug, PartialEq)]
pub struct ItemIdData {
    /// offset to tuple (from start of page)
    pub lp_off: u16,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u16,
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct PageHeaderData {
    pub pd_lsn: PageXLogRecPtr,
    /// checksum
    pub pd_checksum: u16,
    /// flag bits, see below
    pub pd_flags: u16,
    /// offset to start of free space
    pub pd_lower: LocationIndex,
    /// offset to end of free space
    pub pd_upper: LocationIndex,
    /// offset to start of special space
    pub pd_special: LocationIndex,
    pub pd_pagesize_version: u16,
    /// oldest prunable XID, or zero if none
    pub pd_prune_xid: TransactionId,
    pub pd_linp: Vec<ItemIdData>,
}

/// are there any unused line pointers?
pub const PD_HAS_FREE_LINES: u8 = 0x0001;
/// not enough free space for new tuple?
pub const PD_PAGE_FULL: u8 = 0x0002;
/// all tuples on page are visible to everyone
pub const PD_ALL_VISIBLE: u8 = 0x0004;
/// OR of all valid pd_flags bits
pub const PD_VALID_FLAG_BITS: u8 = 0x0007;

pub fn parse_rec_ptr(i: &[u8]) -> IResult<&[u8], PageXLogRecPtr, InspectError<&[u8]>> {
    let (i, xlogid) = le_u32(i)?;
    let (i, xrecoff) = le_u32(i)?;
    Ok((i, PageXLogRecPtr { xlogid, xrecoff }))
}

pub fn parse_item_id_data(i: &[u8]) -> IResult<&[u8], ItemIdData, InspectError<&[u8]>> {
    debug!("Got {:?}", i);
    let ((i, s), lp_off) = nom::bits::complete::take(15usize)((i, 0))?;
    let ((i, s), lp_flags) = nom::bits::complete::take(2usize)((i, s))?;
    let ((i, _s), lp_len) = nom::bits::complete::take(15usize)((i, s))?;
    Ok((i, ItemIdData { lp_off, lp_flags, lp_len }))
}

pub fn page_get_max_offset_number(pd_lower_u16: LocationIndex)-> usize{
    let pd_lower= usize::from(pd_lower_u16);
    // Should be 24
    let size_page_header_data = mem::offset_of!(PageHeaderData, pd_linp);
    if pd_lower <= size_page_header_data {
        return 0;
    }
    // ItemIdData is 4 bytes
    (pd_lower - size_page_header_data) / 4
}

pub fn parse_page_header(i: &[u8]) -> IResult<&[u8], PageHeaderData, InspectError<&[u8]>> {
    let (i, pd_lsn) = parse_rec_ptr(i)?;
    let (i, pd_checksum) = le_u16(i)?;
    let (i, pd_flags) = le_u16(i)?;
    let (i, pd_lower) = le_u16(i)?;
    let (i, pd_upper) = le_u16(i)?;
    let (i, pd_special) = le_u16(i)?;
    let (i, pd_pagesize_version) = le_u16(i)?;
    let (i, pd_prune_xid) = le_u32(i)?;

    let num_line_pointers = page_get_max_offset_number(pd_lower);
    debug!("Got {:?}, count {}, pd_lower {}", i, num_line_pointers, pd_lower);
    let (i, pd_linp) = nom::multi::count(parse_item_id_data, num_line_pointers).parse(i)?;
    debug!("Got {:?}", i);

    Ok((
        i,
        PageHeaderData {
            pd_lsn,
            pd_checksum,
            pd_flags,
            pd_lower,
            pd_upper,
            pd_special,
            pd_pagesize_version,
            pd_prune_xid,
            pd_linp,
        },
    ))
}
