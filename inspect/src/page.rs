use bitter::{BitReader, LittleEndianReader};
use itertools::Itertools;
use nom::IResult;
use nom::Input;
use nom::Parser;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::multi::count;
use nom::number::complete::{le_u8, le_u16, le_u32};
use struple::Struple;

use crate::pg_lsn::PageXLogRecPtr;
use crate::tuple::HeapTuple;
use crate::tuple::HeapTupleHeader;
use crate::tuple::parse_heap_tuple;

pub type LocationIndex = u16;
pub type TransactionId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Struple)]
pub struct PageHeader {
    /// lSN
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
    pub pd_version: u8,
    pub pd_pagesize: u16,
    /// oldest prunable XID, or zero if none
    pub pd_prune_xid: TransactionId,
}

#[derive(Debug, PartialEq, Struple)]
pub struct Page {
    pub header: PageHeader,
    pub pd_linp: Vec<ItemId>,
    // Other approach: Store page bytes and access tuples on demand
    pub tuples: Vec<HeapTuple>,
}

#[derive(Debug, PartialEq, Struple)]
pub struct ItemId {
    /// offset to tuple (from start of page)
    pub lp_off: u16,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u16,
}

impl Page {

}

/// are there any unused line pointers?
const PD_HAS_FREE_LINES: u8 = 0x0001;
/// not enough free space for new tuple?
const PD_PAGE_FULL: u8 = 0x0002;
/// all tuples on page are visible to everyone
const PD_ALL_VISIBLE: u8 = 0x0004;
/// OR of all valid pd_flags bits
const PD_VALID_FLAG_BITS: u8 = 0x0007;

/// used (should always have lp_len>0)
const LP_NORMAL: u8 = 1;
/// HOT redirect (should have lp_len=0)
const LP_REDIRECT: u8 = 2;
/// dead, may or may not have storage
const LP_DEAD: u8 = 3;

const PAGE_HEADER_MEM_SIZE: usize = 24;
const ITEM_ID_DATA_MEM_SIZE: usize = 4;
pub const PAGE_SIZE: usize = 4;

fn parse_lsn<I, E: ParseError<I>>(input: I) -> IResult<I, PageXLogRecPtr, E>
where
    I: Input<Item = u8>,
{
    (le_u32, le_u32).map(PageXLogRecPtr::new).parse(input)
}

fn parse_pagesize<I, E: ParseError<I>>(input: I) -> IResult<I, u16, E>
where
    I: Input<Item = u8>,
{
    le_u8(input).map(|(input, a)| (input, u16::from(a) << 8))
}

/// Parse page header, then pass it to parse_line_pointer
fn parse_page<I, E: ParseError<I>>(input: I) -> IResult<I, Page, E>
where
    I: Input<Item = u8>,
{
    let (page_bytes, rest) = input.take_split(PAGE_SIZE);

    let (header_bytes, header) = parse_header.parse(page_bytes.clone())?;
    let (_, pd_linp) = parse_line_pointers(header).parse(header_bytes)?;

    let tuples: Vec<HeapTuple> = pd_linp
        .iter()
        .map(|lp| page_bytes.take_from(lp.lp_off as usize))
        .map(parse_heap_tuple::<I, E>)
        .map_ok(|a| a.1)
        .try_collect()?;

    Ok((
        rest,
        Page {
            header,
            pd_linp,
            tuples,
        },
    ))
}

fn parse_header<I, E: ParseError<I>>(input: I) -> IResult<I, PageHeader, E>
where
    I: Input<Item = u8>,
{
    (
        parse_lsn,      // lsn
        le_u16,         // Checksum
        le_u16,         // flags
        le_u16,         // lower
        le_u16,         // upper
        le_u16,         // special
        le_u8,          // version
        parse_pagesize, // pagesize
        le_u32,         // prune_xid
    )
        .map(PageHeader::from_tuple)
        .parse(input)
}

/// Compute number of items from page header's pd_lower
fn max_offset_number(pd_lower_u16: LocationIndex) -> usize {
    let pd_lower = usize::from(pd_lower_u16);
    if pd_lower <= PAGE_HEADER_MEM_SIZE {
        return 0;
    }
    (pd_lower - PAGE_HEADER_MEM_SIZE) / ITEM_ID_DATA_MEM_SIZE
}

/// Parse multiple line pointers
fn parse_line_pointers<I, E: ParseError<I>>(
    header: PageHeader,
) -> impl Parser<I, Output = Vec<ItemId>, Error = E>
where
    I: Input<Item = u8>,
{
    let num_lp = max_offset_number(header.pd_lower);
    count(parse_line_pointer, num_lp)
}

/// Parse a single line pointer
fn parse_line_pointer<I, E: ParseError<I>>(input: I) -> IResult<I, ItemId, E>
where
    I: Input<Item = u8>,
{
    take(4usize).map_opt(parse_item_id_data_bits).parse(input)
}

/// Parse bits into ItemId
fn parse_item_id_data_bits<I>(input: I) -> Option<ItemId>
where
    I: Input<Item = u8>,
{
    let bytes = input
        .take(4)
        .iter_indices()
        .map(|t| t.1)
        .collect::<Vec<u8>>();
    let mut bits = LittleEndianReader::new(&bytes);
    let lp_off = bits.read_bits(15)? as u16;
    let lp_flags = bits.read_bits(2)? as u8;
    let lp_len = bits.read_bits(15)? as u16;
    Some(ItemId {
        lp_off,
        lp_flags,
        lp_len,
    })
}

#[cfg(test)]
mod tests {
    use nom_language::error::VerboseError;
    use pretty_assertions::assert_eq;

    use crate::page::{
        ItemId, LP_NORMAL, Page, PageHeader, max_offset_number, parse_line_pointer, parse_page,
    };

    #[ctor::ctor]
    fn init() {
        env_logger::init();
    }

    #[test]
    fn test_parse_line_pointer() {
        let input = b"\x80\x9f\x38\x00";
        let res = parse_line_pointer::<&[u8], VerboseError<&[u8]>>(input);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        let (i, item_id_data) = res.unwrap();
        assert!(i.is_empty(), "{:?}", i);

        let expected_item_id_data = ItemId {
            lp_off: 8064,
            lp_flags: LP_NORMAL,
            lp_len: 28,
        };
        assert_eq!(expected_item_id_data, item_id_data);
    }

    #[test]
    fn test_parse_page() {
        let input = include_bytes!("../assets/page_two_tuples").as_slice();
        let res = parse_page::<&[u8], VerboseError<&[u8]>>(input);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        let (i, page) = res.unwrap();

        let expected_linp = vec![
            ItemId {
                lp_off: 8160,
                lp_flags: 1,
                lp_len: 28,
            },
            ItemId {
                lp_off: 8128,
                lp_flags: 1,
                lp_len: 28,
            },
        ];
        let expected_heap_tuples = vec![];

        let expected_page = Page {
            header: PageHeader {
                pd_lsn: "0/1592EA8".try_into().unwrap(),
                pd_checksum: 24867,
                pd_flags: 0,
                pd_lower: 32,
                pd_upper: 8128,
                pd_special: 8192,
                pd_version: 4,
                pd_pagesize: 8192,
                pd_prune_xid: 0,
            },
            pd_linp: expected_linp,
            tuples: expected_heap_tuples,
        };
        assert_eq!(expected_page, page);

        assert_eq!(
            max_offset_number(page.header.pd_lower),
            2,
            "Should have 2 line pointer in the header"
        );
        assert_eq!(page.pd_linp.len(), 2);

        //        assert!(
        //            i.is_empty(),
        //            "Everything should have been consumed, still got {:x?}",
        //            i
        //        );
    }
}
