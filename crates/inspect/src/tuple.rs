use log::debug;
use nom::Parser;
use nom::bytes::take;
use nom::number::complete::{le_i32, le_u8, le_u16};
use nom::{
    IResult,
    error::{ContextError, ParseError, context},
    number::complete::le_u32,
};
use struple::Struple;

use crate::page::TransactionId;

pub type CommandId = u32;
pub type Oid = u32;
pub type BlockIdData = u32;
pub type OffsetNumber = u16;

#[derive(Debug, PartialEq, Struple, Clone)]
pub struct HeapTupleFields {
    /// Inserting xact ID
    pub xmin: TransactionId,
    /// Deleting or locking xact ID
    pub xmax: TransactionId,

    /// Inserting or deleting command ID, or both
    pub t_cid: CommandId,
}

#[derive(Debug, PartialEq, Struple, Clone)]
pub struct ItemPointerData {
    pub ip_blkid: BlockIdData,
    pub ip_posid: BlockIdData,
}

#[derive(Debug, PartialEq)]
pub struct HeapTupleHeaderData {
    pub t_heap: HeapTupleFields,

    /// Current TID of this or newer tuple (or a speculative insertion token)
    pub t_ctid: ItemPointerData,
    /// Number of attributes + various flags
    pub t_infomask2: u16,
    /// various flags bits
    pub t_infomask: u16,
    /// sizeof header incl. bitmap, padding
    pub t_hoff: u8,
    /// bitmaps of NULLs
    pub t_bits: Vec<u8>,
}

impl HeapTupleHeaderData {
    fn new(
        t_heap: HeapTupleFields,
        t_ctid: ItemPointerData,
        t_infomask2: u16,
        t_infomask: u16,
        t_hoff: u8,
        t_bits: Vec<u8>,
    ) -> Self {
        Self {
            t_heap,
            t_ctid,
            t_infomask2,
            t_infomask,
            t_hoff,
            t_bits,
        }
    }
}

// t_infomask2 flags
/// 11 bits for number of attributes
const HEAP_NATTS_MASK: u16 = 0x07FF;
/// tuple was updated and key cols modified, or tuple deleted
const HEAP_KEYS_UPDATED: u16 = 0x2000;
/// tuple was HOT-updated
const HEAP_HOT_UPDATED: u16 = 0x4000;
/// this is heap-only tuple
const HEAP_ONLY_TUPLE: u16 = 0x8000;
/// visibility-related bits
const HEAP2_XACT_MASK: u16 = 0xE000;

fn parse_item_pointer_data<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], ItemPointerData, E> {
    context(
        "ItemPointerData",
        (le_u32, le_u32).map(ItemPointerData::from_tuple),
    )
    .parse(i)
}

fn parse_heap_tuple_fields<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], HeapTupleFields, E> {
    context(
        "HeapTupleFields",
        (le_u32, le_u32, le_u32).map(HeapTupleFields::from_tuple),
    )
    .parse(i)
}

type HeapHeaderTypes = (HeapTupleFields, ItemPointerData, u16, u16, u8);
type HeapHeaderTypesWithBitmaps = (HeapTupleFields, ItemPointerData, u16, u16, u8, Vec<u8>);
fn parse_bitmaps<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    t: (&'a [u8], HeapHeaderTypes),
) -> IResult<&'a [u8], HeapTupleHeaderData, E> {
    let (i, (t_heap, t_ctid, t_infomask2, t_infomask, t_hoff)) = t;
    let natts = t_infomask2 & HEAP_NATTS_MASK;
    let bitmap_len = ((natts + 7) / 8) * 8;
    context(
        "Bitmaps",
        take(bitmap_len).map(|bitmaps: &'a [u8]| {
            HeapTupleHeaderData::new(
                t_heap,
                t_ctid,
                t_infomask2,
                t_infomask,
                t_hoff,
                bitmaps.to_vec(),
            )
        }),
    )
    .parse(i)
}

fn parse_heap_header_data<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], HeapTupleHeaderData, E> {
    context(
        "HeapHeaderData",
        (
            parse_heap_tuple_fields,
            parse_item_pointer_data,
            le_u16,
            le_u16,
            le_u8,
        )
            .and_then(parse_bitmaps),
    )
    .parse(i)
}

#[cfg(test)]
mod tests {
    use nom_language::error::VerboseError;
    use pretty_assertions::assert_eq;
}
