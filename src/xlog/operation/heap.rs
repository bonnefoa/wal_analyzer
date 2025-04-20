use nom::{
    number::complete::{le_u16, le_u32, le_u8},
    IResult,
};

use crate::{
    error::XLogError,
    xlog::common::{OffsetNumber, TransactionId},
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

    /// Delete flag
    pub all_visible_cleared: bool,
    pub contains_old_tuple: bool,
    pub contains_old_key: bool,
    pub is_super: bool,
    pub is_partition_move: bool,
}

#[derive(Clone, Debug)]
pub struct Insert {
    pub offnum: OffsetNumber,
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub old_xmax: TransactionId,
    pub old_offnum: OffsetNumber,
    pub old_infobits: Infobits,

    /// Update Flags
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

pub fn parse_heap_delete(i: &[u8]) -> IResult<&[u8], Delete, XLogError<&[u8]>> {
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
    Ok((i, heap_delete))
}

pub fn parse_heap_update(i: &[u8]) -> IResult<&[u8], Update, XLogError<&[u8]>> {
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

    Ok((i, heap_update))
}
