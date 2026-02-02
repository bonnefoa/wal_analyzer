use bitter::{BitReader, LittleEndianReader};
use nom::Err;
use nom::IResult;
use nom::Input;
use nom::Parser;
use nom::bytes::complete::take;
use nom::error::ParseError;
use nom::number::complete::{le_u8, le_u16, le_u32};
use nom_language::error::VerboseError;
use struple::Struple;

use crate::pg_lsn::PageXLogRecPtr;
use crate::tuple::HeapTupleHeader;
use crate::tuple::parse_heap_tuple_header;
use crate::tuple_desc::TupleDescriptor;

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

#[derive(Debug, PartialEq)]
pub struct Page {
    header: PageHeader,
    /// Page content, without page header
    data: [u8; PAGE_SIZE],
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

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PageError {
    #[error("Invalid line pointer offset '{0}', max is '{1}'")]
    InvalidOffset(usize, usize),
    #[error("Error parsing line pointer: '{0}'")]
    LinePointerParseError(String),
}

impl From<Err<VerboseError<&[u8]>>> for PageError {
    fn from(val: Err<VerboseError<&[u8]>>) -> Self {
        PageError::LinePointerParseError(val.to_string())
    }
}

impl Page {
    /// Compute number of items from page header's pd_lower
    pub fn num_lp(&self) -> usize {
        let pd_lower = usize::from(self.header.pd_lower);
        if pd_lower <= PAGE_HEADER_MEM_SIZE {
            return 0;
        }
        (pd_lower - PAGE_HEADER_MEM_SIZE) / ITEM_ID_DATA_MEM_SIZE
    }

    pub fn get_line_pointer(&self, offset: usize) -> Result<ItemId, PageError> {
        let max_offset = self.num_lp();
        if offset > max_offset {
            return Err(PageError::InvalidOffset(offset, max_offset));
        }
        // Line pointer are 4 bytes and located after page header
        let start_lp = PAGE_HEADER_MEM_SIZE + offset * 4;
        let end_lp = start_lp + 4;
        let lp_bytes = &self.data[start_lp..end_lp];

        let (_, lp) = parse_line_pointer::<&[u8], VerboseError<&[u8]>>(lp_bytes)?;
        Ok(lp)
    }

    pub fn get_tuple(&self, offset: usize) -> Result<HeapTupleHeader, PageError> {
        let lp = self.get_line_pointer(offset)?;
        let offset = lp.lp_off as usize;
        let heap_tuple_bytes = &self.data[offset..];
        let (_, heap_tuple) =
            parse_heap_tuple_header::<&[u8], VerboseError<&[u8]>>(heap_tuple_bytes)?;
        Ok(heap_tuple)
    }
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
pub const PAGE_SIZE: usize = 8192;

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

fn parse_page<I, E: ParseError<I>>(input: I) -> IResult<I, Page, E>
where
    I: Input<Item = u8>,
{
    let (input, page_bytes) = input.take_split(PAGE_SIZE);
    let (_, header) = parse_page_header.parse(page_bytes.clone())?;
    let data = page_bytes.iter_elements().collect::<Vec<u8>>().try_into();
    Ok((
        input,
        Page {
            header,
            data: data.unwrap(),
        },
    ))
}

fn parse_page_header<I, E: ParseError<I>>(input: I) -> IResult<I, PageHeader, E>
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
    use bitvec::vec::BitVec;
    use nom_language::error::VerboseError;
    use pretty_assertions::assert_eq;

    use crate::{
        page::{ItemId, LP_NORMAL, Page, PageHeader, parse_line_pointer, parse_page},
        tuple::{HeapTupleHeader, ItemPointerData, TupleValue, deform_tuple},
        tuple_desc::TupleDescriptorMap,
    };

    #[ctor::ctor]
    fn init() {
        env_logger::init();
    }

    #[test]
    fn test_parse_page() {
        let input = include_bytes!("../assets/page_two_tuples").as_slice();
        let res = parse_page::<&[u8], VerboseError<&[u8]>>(input);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());

        let (i, page) = res.unwrap();
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
            data: input.try_into().unwrap(),
        };
        assert_eq!(expected_page, page);

        let expected_lp_1 = ItemId {
            lp_off: 8160,
            lp_flags: 1,
            lp_len: 28,
        };
        let expected_lp_2 = ItemId {
            lp_off: 8128,
            lp_flags: 1,
            lp_len: 28,
        };
        let first_lp = page.get_line_pointer(0);
        let second_lp = page.get_line_pointer(1);
        assert_eq!(Ok(expected_lp_1), first_lp, "First lp");
        assert_eq!(Ok(expected_lp_2), second_lp, "Second lp");

        let expected_tuple_1 = HeapTupleHeader {
            xmin: 767,
            xmax: 0,
            t_cid: 0,
            t_ctid: ItemPointerData {
                ip_blkid: 0,
                ip_posid: 1,
            },
            t_infomask2: 2,
            t_infomask: 2305,
            t_hoff: 24,
            t_bits: BitVec::from_slice(&[0b1]),
        };

        let expected_tuple_2 = HeapTupleHeader {
            xmin: 767,
            xmax: 0,
            t_cid: 1,
            t_ctid: ItemPointerData {
                ip_blkid: 0,
                ip_posid: 2,
            },
            t_infomask2: 2,
            t_infomask: 2305,
            t_hoff: 24,
            t_bits: BitVec::from_slice(&[0b1]),
        };

        let first_tuple = page.get_tuple(0);
        let second_tuple = page.get_tuple(1);
        assert_eq!(Ok(expected_tuple_1), first_tuple, "First tuple");
        assert_eq!(Ok(expected_tuple_2), second_tuple, "Second tuple");

        // Nothing should be left to parse
        assert_eq!(i.len(), 0);
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
    fn test_deform() {
        let tuple_descs: TupleDescriptorMap =
            serde_json::from_str(include_str!("../assets/tuple_descriptor_test.json")).unwrap();
        let tuple_desc = &tuple_descs["16462"];

        let input = include_bytes!("../assets/page_two_tuples").as_slice();
        let (_, page) = parse_page::<&[u8], VerboseError<&[u8]>>(input).unwrap();
        let t_data = &input[8160 + 24..8160 + 28];

        let heap_tuple = page.get_tuple(0).unwrap();
        assert_eq!(heap_tuple.t_bits[0], true);
        assert_eq!(heap_tuple.t_bits[1], false);
        let (_, r) = deform_tuple::<&[u8], VerboseError<&[u8]>>(t_data, &heap_tuple, tuple_desc).unwrap();
        let expected_deform_values = vec![Some(TupleValue::Int4(1)), None];
        assert_eq!(r, expected_deform_values);
    }
}
