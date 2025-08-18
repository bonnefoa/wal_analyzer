use std::mem;

use struple::Struple;
use nom::error::{context, ContextError, ParseError};
use nom::number::complete::{le_u64, le_u16, le_u32};
use nom::IResult;
use nom::Parser;

type BitInput<'a> = (&'a [u8], usize);

type LocationIndex = u16;
type TransactionId = u32;

#[derive(Debug, PartialEq)]
pub struct ItemIdData {
    /// offset to tuple (from start of page)
    pub lp_off: u16,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u16,
}

#[derive(Debug, PartialEq, Struple)]
pub struct PageHeaderData {
    /// lSN
    pub pd_lsn: u64,
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
}

#[derive(Debug, PartialEq)]
pub struct PageHeaderDataWithLP {
    pub page_header_data: PageHeaderData,
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
    let size_page_header_data = mem::size_of::<PageHeaderData>();
    if pd_lower <= size_page_header_data {
        return 0;
    }
    // ItemIdData is 4 bytes
    (pd_lower - size_page_header_data) / 4
}

pub fn parse_line_pointer_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8], num_lp: u16
) -> IResult<&'a [u8], PageHeaderData, E> {
    todo!()
}

pub fn parse_page_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageHeaderData, E> {
    context(
        "PageHeader",
        (le_u64, le_u16, le_u16, le_u16, le_u16, le_u16, le_u16, le_u32)
        .map(PageHeaderData::from_tuple)
    ).parse(i)
}


#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

#[cfg(test)]
use pretty_assertions::{assert_eq};

#[test]
fn test_parse_page_header() {
    let input = b"\x0e\x00\x00\x00\x68\x7f\xd3\x8a\xf4\x9f\x00\x00\x28\x00\x80\x1f\x00\x20\x04\x20\x00\x00\x00\x00";
    let res = parse_page_header::<nom_language::error::VerboseError<&[u8]>>(input);
    assert!(res.is_ok(), "{:?}", res);
    let (i, page_header) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);

    let pd_lsn = 0x892c80;

    let expected_page_header = PageHeaderData {
        pd_lsn,
        pd_checksum: 0x9f4f,
        pd_flags: 0,
        pd_lower: 0x28,
        pd_upper: 0x1f80,
        pd_special: 0x2000,
        pd_pagesize_version: 0x2004,
        pd_prune_xid: 0,
    };
    assert_eq!(expected_page_header, page_header);
}
