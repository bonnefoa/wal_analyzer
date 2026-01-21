use std::fmt::Display;
use std::fmt::Formatter;

use bitter::{BitReader, LittleEndianReader};
use log::debug;
use log::info;
use nom::IResult;
use nom::Input;
use nom::Parser;
use nom::bytes::complete::take;
use nom::error::{ContextError, ParseError, context};
use nom::multi::count;
use nom::number::complete::{le_u8, le_u16, le_u32};
use struple::Struple;

pub type LocationIndex = u16;
pub type TransactionId = u32;

#[derive(Debug, PartialEq)]
pub struct ItemIdData {
    /// offset to tuple (from start of page)
    pub lp_off: u16,
    /// state of line pointer, see below
    pub lp_flags: u8,
    /// byte length of tuple
    pub lp_len: u16,
}

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct PageXLogRecPtr {
    xlogid: u32,
    xrecoff: u32,
}

impl Display for PageXLogRecPtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // format ourselves as a `ffffffff/ffffffff` string
        write!(f, "{0:X}/{1:08X}", self.xlogid, self.xrecoff)
    }
}

#[derive(Clone, Debug, Hash, Ord, PartialOrd, PartialEq, Eq, thiserror::Error)]
pub enum InvalidLSN {
    #[error("Invalid LSN Format '{0}'")]
    Format(String),
    #[error("Invalid hex value in '{0}': `{1}`")]
    HexValue(String, String),
}

impl TryFrom<&str> for PageXLogRecPtr {
    type Error = InvalidLSN;

    fn try_from(lsn: &str) -> Result<Self, Self::Error> {
        let mut iter = lsn.split('/');
        let Some(xlogid_str) = iter.next() else {
            return Err(InvalidLSN::Format(lsn.to_string()));
        };
        let xlogid = match u32::from_str_radix(xlogid_str, 16) {
            Ok(xlogid) => xlogid,
            Err(e) => return Err(InvalidLSN::HexValue(lsn.to_string(), e.to_string())),
        };

        let xrecoff_str = iter.next().unwrap();
        let xrecoff = match u32::from_str_radix(xrecoff_str, 16) {
            Ok(xrecoff) => xrecoff,
            Err(e) => return Err(InvalidLSN::HexValue(lsn.to_string(), e.to_string())),
        };
        Ok(PageXLogRecPtr { xlogid, xrecoff })
    }
}

#[derive(Debug, PartialEq, Struple)]
pub struct PageHeaderData {
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
    pub pd_linp: Vec<ItemIdData>,
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

type HeaderTypes = (PageXLogRecPtr, u16, u16, u16, u16, u16, u8, u16, u32);

fn parse_lsn<I, E: ParseError<I>>(i: I) -> IResult<I, PageXLogRecPtr, E>
where
    I: Input<Item = u8>,
{
    (le_u32, le_u32)
        .map(|(xlogid, xrecoff)| PageXLogRecPtr { xlogid, xrecoff })
        .parse(i)
}

fn le_pagesize<I, E: ParseError<I>>(i: I) -> IResult<I, u16, E>
where
    I: Input<Item = u8>,
{
    le_u8(i).map(|(i, a)| (i, u16::from(a) << 8))
}

/// Parse page header, then pass it to parse_line_pointer
fn parse_page<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], PageHeaderData, E> {
    context(
        "PageHeader",
        (
            parse_lsn,
            le_u16,      // Checksum
            le_u16,      // flags
            le_u16,      // lower
            le_u16,      // upper
            le_u16,      // special
            le_u8,       // version
            le_pagesize, // pagesize
            le_u32,      // prune_xid
        ),
    )
    .parse(i)
    .and_then(parse_line_pointers)
}

/// Parse multiple line pointers
fn parse_line_pointers<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
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
            pd_version,
            pd_pagesize,
            pd_prune_xid,
        ),
    ) = t;
    let num_lp = max_offset_number(pd_lower);
    info!("Found {num_lp} line pointers");
    count(parse_line_pointer, num_lp)
        .map(|pd_linp| PageHeaderData {
            pd_lsn,
            pd_checksum,
            pd_flags,
            pd_lower,
            pd_upper,
            pd_special,
            pd_version,
            pd_pagesize,
            pd_prune_xid,
            pd_linp,
        })
        .parse(i)
}

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
    if pd_lower <= PAGE_HEADER_MEM_SIZE {
        return 0;
    }
    (pd_lower - PAGE_HEADER_MEM_SIZE) / ITEM_ID_DATA_MEM_SIZE
}

#[cfg(test)]
mod tests {
    use nom_language::error::VerboseError;
    use pretty_assertions::assert_eq;

    use crate::page::{
        ItemIdData, LP_NORMAL, PageHeaderData, max_offset_number, parse_line_pointer, parse_page,
    };

    #[ctor::ctor]
    fn init() {
        env_logger::init();
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
        let input = include_bytes!("../assets/page_two_tuples");
        let res = parse_page::<VerboseError<&[u8]>>(input);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        let (i, page) = res.unwrap();

        let expected_linp = vec![
            ItemIdData {
                lp_off: 8160,
                lp_flags: 1,
                lp_len: 28,
            },
            ItemIdData {
                lp_off: 8128,
                lp_flags: 1,
                lp_len: 28,
            },
        ];

        let expected_page_header = PageHeaderData {
            pd_lsn: "0/1592EA8".try_into().unwrap(),
            pd_checksum: 24867,
            pd_flags: 0,
            pd_lower: 32,
            pd_upper: 8128,
            pd_special: 8192,
            pd_version: 4,
            pd_pagesize: 8192,
            pd_prune_xid: 0,
            pd_linp: expected_linp,
        };
        assert_eq!(expected_page_header, page);

        assert_eq!(
            max_offset_number(page.pd_lower),
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
