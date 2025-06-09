use nom::{
    error::{ErrorKind, ParseError},
    number::complete::{le_u16, le_u32},
    IResult,
};

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
    pub lp_off: u8,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u8,
}

#[derive(Debug, PartialEq)]
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

pub fn parse_page_header(i: &[u8]) -> IResult<&[u8], PageHeaderData, InspectError<&[u8]>> {
    let (i, pd_lsn) = parse_rec_ptr(i)?;
    let (i, pd_checksum) = le_u16(i)?;
    let (i, pd_flags) = le_u16(i)?;
    let (i, pd_lower) = le_u16(i)?;
    let (i, pd_upper) = le_u16(i)?;
    let (i, pd_special) = le_u16(i)?;
    let (i, pd_pagesize_version) = le_u16(i)?;
    let (i, pd_prune_xid) = le_u32(i)?;
    // TODO: Parse line pointers
    let pd_linp = Vec::new();

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
