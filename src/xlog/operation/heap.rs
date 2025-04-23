use log::debug;
use nom::{
    number::complete::{le_u16, le_u32, le_u8},
    IResult,
};

use crate::{
    error::XLogError,
    xlog::{
        common::{OffsetNumber, TransactionId},
        record::Operation,
    },
};

#[derive(Clone, Debug)]
pub struct Infobits {
    pub xmax_is_multi: bool,
    pub xmax_lock_only: bool,
    pub xmax_excl_lock: bool,
    pub xmax_keyshare_lock: bool,
    pub keys_updated: bool,
}

#[derive(Clone, Debug)]
pub struct Delete {
    pub xmax: TransactionId,
    pub offnum: OffsetNumber,
    pub infobits: Infobits,

    /// Delete flags
    pub all_visible_cleared: bool,
    pub contains_old_tuple: bool,
    pub contains_old_key: bool,
    pub is_super: bool,
    pub is_partition_move: bool,
}

#[derive(Clone, Debug)]
pub struct Insert {
    pub offnum: OffsetNumber,

    /// Insert flags
    pub all_visible_cleared: bool,
    pub last_in_multi: bool,
    pub is_speculative: bool,
    pub contains_new_tuple: bool,
    pub on_toast_relation: bool,
    pub all_frozen_set: bool,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub old_xmax: TransactionId,
    pub old_offnum: OffsetNumber,
    pub old_infobits: Infobits,

    /// Update flags
    pub old_all_visible_cleared: bool,
    pub new_all_visible_cleared: bool,
    pub contains_old_tuple: bool,
    pub contains_new_tuple: bool,
    pub prefix_from_old: bool,
    pub suffix_from_old: bool,

    pub new_xmax: TransactionId,
    pub new_offnum: OffsetNumber,
}

#[derive(Clone, Debug)]
pub struct Prune {
    pub latest_remove_xid: TransactionId,
    pub nredirected: u16,
    pub ndead: u16,
}

#[derive(Clone, Debug)]
pub enum HeapOperation {
    Delete(Delete),
    Insert(Insert),
    Update(Update),
    Prune(Prune),
    Placeholder,
}

impl std::fmt::Display for HeapOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HeapOperation::Delete(o) => write!(f, "{:?}", o),
            HeapOperation::Insert(o) => write!(f, "{:?}", o),
            HeapOperation::Update(o) => write!(f, "{:?}", o),
            HeapOperation::Prune(o) => write!(f, "{:?}", o),
            HeapOperation::Placeholder => write!(f, "Placeholder"),
        }
    }
}

pub fn parse_infobits(i: &[u8]) -> IResult<&[u8], Infobits, XLogError<&[u8]>> {
    let (i, infobits_set) = le_u8(i)?;
    let infobits = Infobits {
        xmax_is_multi: infobits_set & 0x01 != 0,
        xmax_lock_only: infobits_set & 0x02 != 0,
        xmax_excl_lock: infobits_set & 0x04 != 0,
        xmax_keyshare_lock: infobits_set & 0x08 != 0,
        keys_updated: infobits_set & 0x10 != 0,
    };
    // TODO: Add check
    Ok((i, infobits))
}

pub fn parse_heap_delete(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    let (i, xmax) = le_u32(i)?;
    let (i, offnum) = le_u16(i)?;
    let (i, infobits) = parse_infobits(i)?;
    let (i, flags) = le_u8(i)?;
    let heap_delete = Delete {
        xmax,
        offnum,
        infobits,
        all_visible_cleared: flags & 0x01 != 0,
        contains_old_tuple: flags & 0x02 != 0,
        contains_old_key: flags & 0x04 != 0,
        is_super: flags & 0x08 != 0,
        is_partition_move: flags & 0x10 != 0,
    };
    Ok((i, HeapOperation::Delete(heap_delete)))
}

pub fn parse_heap_update(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    let (i, old_xmax) = le_u32(i)?;
    let (i, old_offnum) = le_u16(i)?;
    let (i, old_infobits) = parse_infobits(i)?;

    let (i, flags) = le_u8(i)?;
    let (i, new_xmax) = le_u32(i)?;
    let (i, new_offnum) = le_u16(i)?;
    let heap_update = Update {
        old_xmax,
        old_offnum,
        old_infobits,
        old_all_visible_cleared: flags & 0x01 != 0,
        new_all_visible_cleared: flags & 0x02 != 0,
        contains_old_tuple: flags & 0x04 != 0,
        contains_new_tuple: flags & 0x08 != 0,
        prefix_from_old: flags & 0x10 != 0,
        suffix_from_old: flags & 0x20 != 0,
        new_xmax,
        new_offnum,
    };

    Ok((i, HeapOperation::Update(heap_update)))
}

pub fn parse_heap_insert(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    let (i, offnum) = le_u16(i)?;
    let (i, flags) = le_u8(i)?;

    let heap_insert = Insert {
        offnum,
        all_visible_cleared: flags & 0x01 != 0,
        last_in_multi: flags & 0x02 != 0,
        is_speculative: flags & 0x04 != 0,
        contains_new_tuple: flags & 0x08 != 0,
        on_toast_relation: flags & 0x10 != 0,
        all_frozen_set: flags & 0x20 != 0,
    };

    Ok((i, HeapOperation::Insert(heap_insert)))
}

pub fn parse_heap_prune(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    let (i, latest_remove_xid) = le_u32(i)?;
    let (i, nredirected) = le_u16(i)?;
    let (i, ndead) = le_u16(i)?;

    let heap_prune = Prune {
        latest_remove_xid,
        nredirected,
        ndead,
    };

    Ok((i, HeapOperation::Prune(heap_prune)))
}

pub fn parse_heap_truncate(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    todo!("truncate");
}

pub fn parse_heap_hot_update(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    todo!("hot update");
}

pub fn parse_heap_confirm(i: &[u8]) -> IResult<&[u8], HeapOperation, XLogError<&[u8]>> {
    todo!("hot update");
}

pub fn parse_heap_operation(
    rmgr_info: u8,
    i: &[u8],
) -> IResult<&[u8], Operation, XLogError<&[u8]>> {
    const XLOG_HEAP_OPMASK: u8 = 0x70;
    let op = rmgr_info & XLOG_HEAP_OPMASK;
    let (i, heap_operation) = match op {
        0x00 => parse_heap_insert(i)?,
        0x10 => parse_heap_delete(i)?,
        0x20 => parse_heap_update(i)?,
        0x30 => parse_heap_truncate(i)?,
        0x40 => parse_heap_hot_update(i)?,
        0x50 => (i, HeapOperation::Placeholder),
        0x60 => (i, HeapOperation::Placeholder),
        0x70 => (i, HeapOperation::Placeholder),
        _ => panic!("Unreachable"),
    };
    debug!("Parsed Operation: {}", heap_operation);
    Ok((i, Operation::Heap(heap_operation)))
}
