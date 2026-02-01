use bit_set::BitSet;
use nom::bytes::take;
use nom::number::complete::{le_i32, le_u8, le_u16};
use nom::{IResult, error::ParseError, number::complete::le_u32};
use nom::{Input, Parser};
use struple::Struple;

use crate::page::TransactionId;
use crate::tuple_desc::{TupleDescriptor, TypeOutput};

pub type CommandId = u32;
pub type Oid = u32;
pub type BlockIdData = u32;
pub type OffsetNumber = u16;

#[derive(Debug, PartialEq, Struple, Clone)]
pub struct ItemPointerData {
    pub ip_blkid: BlockIdData,
    pub ip_posid: OffsetNumber,
}

#[derive(Debug, PartialEq, Struple)]
pub struct HeapTupleHeader {
    /// Inserting xact ID
    pub xmin: TransactionId,
    /// Deleting or locking xact ID
    pub xmax: TransactionId,
    /// Inserting or deleting command ID, or both
    pub t_cid: CommandId,
    /// Current TID of this or newer tuple (or a speculative insertion token)
    pub t_ctid: ItemPointerData,
    /// Number of attributes + various flags
    pub t_infomask2: u16,
    /// various flags bits
    pub t_infomask: u16,
    /// sizeof header incl. bitmap, padding
    pub t_hoff: u8,
    /// bitmaps of NULLs
    pub t_bits: BitSet<u32>,
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

// t_infomask
/// has null attribute(s)
const HEAP_HASNULL: u8 = 0x0001;
/// has variable-width attribute(s)
const HEAP_HASVARWIDTH: u8 = 0x0002;
/// has external stored attribute(s)
const HEAP_HASEXTERNAL: u8 = 0x0004;
/// has an object-id field
const HEAP_HASOID_OLD: u8 = 0x0008;
/// xmax is a key-shared locker
const HEAP_XMAX_KEYSHR_LOCK: u8 = 0x0010;
/// t_cid is a combo CID
const HEAP_COMBOCID: u8 = 0x0020;
/// xmax is exclusive locker
const HEAP_XMAX_EXCL_LOCK: u8 = 0x0040;
/// xmax, if valid, is only a locker
const HEAP_XMAX_LOCK_ONLY: u8 = 0x0080;

pub fn parse_heap_tuple_header<I, E: ParseError<I>>(input: I) -> IResult<I, HeapTupleHeader, E>
where
    I: Input<Item = u8>,
{
    let (input, (xmin, xmax, t_cid, t_ctid, t_infomask2, t_infomask, t_hoff)) = (
        le_u32,     // xmin
        le_u32,     // xmax
        le_u32,     // t_cid
        parse_ctid, // t_ctid
        le_u16,     // t_infomask2
        le_u16,     // t_infomask
        le_u8,      // t_hoff
    )
        .parse(input)?;

    let natts = t_infomask2 & HEAP_NATTS_MASK;
    // We store bitmaps as Vec<u8>
    let bitmap_len = natts.div_ceil(8);
    let (input, t_bits) = take(bitmap_len)
        .map(|a: I| BitSet::from_bytes(&a.iter_elements().collect::<Vec<u8>>()))
        .parse(input)?;

    Ok((
        input,
        HeapTupleHeader {
            xmin,
            xmax,
            t_cid,
            t_ctid,
            t_infomask2,
            t_infomask,
            t_hoff,
            t_bits,
        },
    ))
}

fn parse_ctid<I, E: ParseError<I>>(input: I) -> IResult<I, ItemPointerData, E>
where
    I: Input<Item = u8>,
{
    (le_u32, le_u16)
        .map(ItemPointerData::from_tuple)
        .parse(input)
}

#[derive(Debug)]
enum TupleValue {
    Int2(i16),
    Int4(i32),
    Int8(i64),
    Text(String),
}

fn parse_tuple_value<I, E: ParseError<I>>(
    input: I,
    type_output: TypeOutput,
) -> IResult<I, TupleValue, E>
where
    I: Input<Item = u8>,
{
    match type_output {
        TypeOutput::Int4 => le_i32.map(TupleValue::Int4).parse(input),
        default => todo!("Type not handled: {:?}", type_output),
    }
}

pub fn deform_tuple<I, E: ParseError<I>>(
    heap_tuple: &HeapTupleHeader,
    desc: &TupleDescriptor,
    t_data: I,
) -> IResult<I, Vec<Option<TupleValue>>, E>
where
    I: Input<Item = u8>,
{
    desc.attributes.iter().enumerate().map(|(idx, attr)| {
        if heap_tuple.t_bits.contains(idx) {
            None
        } else {
            None
        }
    });

    // let mut res: Vec<Option<TupleValue>> = vec![];
    //    for (idx, attr) in desc.attributes.iter().enumerate() {
    //        if heap_tuple.t_bits.contains(idx) {
    //            res.push(None);
    //        } else {
    //            let (t_data, v) = match &attr.type_output {
    //                TypeOutput::Int4 => le_i32.map(TupleValue::Int4).map(Some).parse(t_data)?,
    //                default => todo!("Type not handled: {:?}", attr.type_output),
    //            };
    //            res.push(v);
    //        }
    //    }

    todo!();
}
