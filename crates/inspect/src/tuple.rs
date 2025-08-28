use log::debug;
use nom::Parser;
use nom::{
    IResult,
    error::{ContextError, ParseError, context},
    number::complete::le_u32,
};

use crate::page::TransactionId;

pub type CommandId = u32;
pub type Oid = u32;
pub type BlockIdData = u32;
pub type OffsetNumber = u16;

#[derive(Debug, PartialEq)]
pub struct HeapTupleFields {
    /// Inserting xact ID
    pub xmin: TransactionId,
    /// Deleting or locking xact ID
    pub xmax: TransactionId,

    /// Inserting or deleting command ID, or both
    pub t_cid: Option<CommandId>,
    /// old-style VACUUM FULL xact ID
    pub t_xvac: Option<TransactionId>,
}

impl HeapTupleFields {
    fn new(is_cid: bool, t: (TransactionId, TransactionId, u32)) -> HeapTupleFields {
        let (xmin, xmax, val) = t;
        let t_cid = if is_cid { Some(val) } else { None };
        let t_xvac = if !is_cid { Some(val) } else { None };
        HeapTupleFields {
            xmin,
            xmax,
            t_cid,
            t_xvac,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DatumTupleFields {
    /// varlena header
    pub datum_len: i32,
    /// -1, or identifier of a record type
    pub datum_typmod: i32,
    /// Composite type OID, or RECORDOID
    pub datum_typeid: Oid,
}

#[derive(Debug, PartialEq)]
pub struct ItemPointerData {
    pub ip_blkid: BlockIdData,
    pub ip_posid: BlockIdData,
}

#[derive(Debug, PartialEq)]
pub struct HeapTupleHeaderData {
    pub t_heap: Option<HeapTupleFields>,
    pub t_datum: Option<DatumTupleFields>,

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

fn parse_heap_tuple_fields<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    t: (&'a [u8], bool),
) -> IResult<&'a [u8], HeapTupleFields, E> {
    let (i, is_cid) = t;
    context(
        "HeapTupleFields",
        (le_u32, le_u32, le_u32).map(|t| HeapTupleFields::new(is_cid, t)),
    )
    .parse(i)
}

#[cfg(test)]
mod tests {
    use nom_language::error::VerboseError;
    use pretty_assertions::assert_eq;

    #[ctor::ctor]
    fn init() {
        env_logger::init();
    }
}
