use std::mem;

use bitter::{BitReader, LittleEndianReader};
use log::debug;
use nom::IResult;
use nom::Parser;
use nom::bytes::complete::take;
use nom::error::{ContextError, ParseError, context};
use nom::multi::count;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom_language::error::VerboseError;
use nom_language::error::convert_error;
use struple::Struple;

type LocationIndex = u16;
type TransactionId = u32;
type CommandId = u32;
type Oid = u32;

#[derive(Debug, PartialEq)]
pub struct ItemIdData {
    /// offset to tuple (from start of page)
    pub lp_off: u16,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u16,
}

type HeaderTypes = (u64, u16, u16, u16, u16, u16, u16, u32);

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
    pub pd_linp: Vec<ItemIdData>,
}

#[derive(Debug, PartialEq, Struple)]
pub struct HeapTupleFields {
    /// Inserting xact ID
    pub xmin: TransactionId,
    /// Deleting or locking xact ID
    pub xmax: TransactionId,
    /// Inserting or deleting command ID, or both
    pub t_cid: CommandId,
}

#[derive(Debug, PartialEq, Struple)]
pub struct DatumTupleFields {
    pub datum_len: i32,
    pub datum_typmod: i32,
    pub datum_typeid: Oid,
}

#[derive(Debug, PartialEq, Struple)]
pub struct PageData {
    pub page_header_data: PageHeaderData,
}

/// are there any unused line pointers?
pub const PD_HAS_FREE_LINES: u8 = 0x0001;
/// not enough free space for new tuple?
pub const PD_PAGE_FULL: u8 = 0x0002;
/// all tuples on page are visible to everyone
pub const PD_ALL_VISIBLE: u8 = 0x0004;
/// OR of all valid pd_flags bits
pub const PD_VALID_FLAG_BITS: u8 = 0x0007;

/// used (should always have lp_len>0)
pub const LP_NORMAL: u8 = 1;
/// HOT redirect (should have lp_len=0)
pub const LP_REDIRECT: u8 = 2;
/// dead, may or may not have storage
pub const LP_DEAD: u8 = 3;

/// Parse bits into ItemIdData
fn parse_item_id_data_bits(bytes: &[u8]) -> Option<ItemIdData> {
    let mut bits = LittleEndianReader::new(bytes);
    let lp_off = bits.read_bits(15)? as u16;
    let lp_flags = bits.read_bits(2)? as u8;
    let lp_len = bits.read_bits(15)? as u16;
    debug!("Found itemiddata");
    Some(ItemIdData {
        lp_off,
        lp_flags,
        lp_len,
    })
}

/// Parse a single line pointer
fn parse_line_pointer<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], ItemIdData, E> {
    context("ItemIdData", take(4usize).map_opt(parse_item_id_data_bits)).parse(i)
}

/// Compute number of items from page header's pd_lower
fn max_offset_number(pd_lower_u16: LocationIndex) -> usize {
    let pd_lower = usize::from(pd_lower_u16);
    // Should be 24
    let size_page_header_data = mem::size_of::<PageHeaderData>();
    if pd_lower <= size_page_header_data {
        return 0;
    }
    // ItemIdData is 4 bytes
    (pd_lower - size_page_header_data) / 4
}

///// Parse multiple line pointers
//fn parse_line_pointers<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
//    i: &'a [u8],
//    num_lp: usize,
//) -> IResult<&'a [u8], Vec<ItemIdData>, E> {
//    context("LinePointers", count(parse_line_pointer, num_lp))
//}

pub fn parse_line_pointers<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    t: (&'a [u8], HeaderTypes),
) -> IResult<&'a [u8], PageHeaderData, E> {
    let (
        i,
        (
            pd_lsn,
            pd_checksum,
            pd_flags,
            pd_lower,
            pd_upper,
            pd_special,
            pd_pagesize_version,
            pd_prune_xid,
        ),
    ) = t;
    let num_lp = max_offset_number(pd_lower);
    count(parse_line_pointer, num_lp)
        .map(|pd_linp| PageHeaderData {
            pd_lsn,
            pd_checksum,
            pd_flags,
            pd_lower,
            pd_upper,
            pd_special,
            pd_pagesize_version,
            pd_prune_xid,
            pd_linp,
        })
        .parse(i)
}

/// Parse page header without line pointers
pub fn parse_page_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageHeaderData, E> {
    context(
        "PageHeader",
        (
            le_u64, le_u16, le_u16, le_u16, le_u16, le_u16, le_u16, le_u32,
        ),
    )
    .parse(i)
    .and_then(parse_line_pointers)
}

/// Parse page with header and data
pub fn parse_page<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageData, E> {
    context("PageData", parse_page_header.map(PageData)).parse(i)
}

#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_parse_page_header() {
    let input = b"\x0e\x00\x00\x00\x68\x7f\xd3\x8a\xf4\x9f\x00\x00\x28\x00\x80\x1f\x00\x20\x04\x20\x00\x00\x00\x00";
    let res = parse_page_header::<VerboseError<&[u8]>>(input);
    assert!(res.is_ok(), "{:?}", res);
    let (i, page_header) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);

    let expected_page_header = PageHeaderData {
        pd_lsn: 0x8ad37f680000000e,
        pd_checksum: 0x9ff4,
        pd_flags: 0,
        pd_lower: 0x28,
        pd_upper: 0x1f80,
        pd_special: 0x2000,
        pd_pagesize_version: 0x2004,
        pd_prune_xid: 0,
        pd_linp: Vec::new(),
    };
    assert_eq!(expected_page_header, page_header);
}

#[test]
fn test_parse_line_pointer() {
    let input = b"\x80\x9f\x38\x00";
    let res = parse_line_pointer::<VerboseError<&[u8]>>(input);
    assert!(res.is_ok(), "{:?}", res.unwrap_err());
    let (i, item_id_data) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);

    let expected_item_id_data = ItemIdData {
        lp_off: 8064,
        lp_flags: LP_NORMAL,
        lp_len: 28,
    };
    assert_eq!(expected_item_id_data, item_id_data);
}

#[test]
fn test_parse_page() {
    let input = include_bytes!("../assets/test_page");
    let res = parse_line_pointer::<VerboseError<&[u8]>>(input);
    assert!(res.is_ok(), "{:?}", res.unwrap_err());
    let (i, item_id_data) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);

    let expected_item_id_data = ItemIdData {
        lp_off: 8064,
        lp_flags: LP_NORMAL,
        lp_len: 28,
    };
    assert_eq!(expected_item_id_data, item_id_data);
}
