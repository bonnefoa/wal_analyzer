use std::mem;

use nom::combinator::map;
use nom::error::{context, ContextError, ParseError};
use nom::number::complete::{le_u16, le_u32};
use nom::IResult;
use nom::Parser;

use crate::xlog::common::TransactionId;

type BitInput<'a> = (&'a [u8], usize);

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

fn parse_rec_ptr<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageXLogRecPtr, E> {
    context(
        "Xlog Rec",
        map((le_u32, le_u32), |(xlogid, xrecoff)| PageXLogRecPtr {
            xlogid,
            xrecoff,
        }),
    )
    .parse(i)
}

pub fn parse_item_id_data<'a, E: ParseError<BitInput<'a>> + ContextError<BitInput<'a>>>(
    i: &'a [u8],
) -> IResult<&'a [u8], ItemIdData, E> {
    let ((i, s), lp_off) = nom::bits::complete::take(15usize)((i, 0))?;
    let ((i, s), lp_flags) = nom::bits::complete::take(2usize)((i, s))?;
    let ((i, _s), lp_len) = nom::bits::complete::take(15usize)((i, s))?;
    Ok((
        i,
        ItemIdData {
            lp_off,
            lp_flags,
            lp_len,
        },
    ))
}

fn page_get_max_offset_number(pd_lower_u16: LocationIndex) -> usize {
    let pd_lower = usize::from(pd_lower_u16);
    // Should be 24
    let size_page_header_data = mem::offset_of!(PageHeaderData, pd_linp);
    if pd_lower <= size_page_header_data {
        return 0;
    }
    // ItemIdData is 4 bytes
    (pd_lower - size_page_header_data) / 4
}

pub fn parse_page_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageHeaderData, E> {
    let (i, pd_lsn) = parse_rec_ptr(i)?;
    let (i, pd_checksum) = le_u16(i)?;
    let (i, pd_flags) = le_u16(i)?;
    let (i, pd_lower) = le_u16(i)?;
    let (i, pd_upper) = le_u16(i)?;
    let (i, pd_special) = le_u16(i)?;
    let (i, pd_pagesize_version) = le_u16(i)?;
    let (i, pd_prune_xid) = le_u32(i)?;

    let num_line_pointers = page_get_max_offset_number(pd_lower);
    let (i, pd_linp) = (i, Vec::new());
    // let (i, pd_linp) = nom::multi::count(parse_item_id_data, num_line_pointers).parse(i)?;

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
