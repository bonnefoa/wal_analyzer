use crate::error::XLogError;
use log::debug;
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::IResult;

pub const BKPBLOCK_FORK_MASK: u8 = 0x0F;
pub const BKPBLOCK_FLAG_MASK: u8 = 0xF0;
pub const BKPBLOCK_HAS_IMAGE: u8 = 0x10; /* block data is an XLogRecordBlockImage */
pub const BKPBLOCK_HAS_DATA: u8 = 0x20;
pub const BKPBLOCK_WILL_INIT: u8 = 0x40; /* redo will re-init the page */
pub const BKPBLOCK_SAME_REL: u8 = 0x80; /* RelFileNode omitted, same as previous */

pub const XLR_BLOCK_ID_TOPLEVEL_XID: u8 = 0xfc;
pub const XLR_BLOCK_ID_ORIGIN: u8 = 0xfd;
pub const XLR_BLOCK_ID_DATA_LONG: u8 = 0xfe;
pub const XLR_BLOCK_ID_DATA_SHORT: u8 = 0xff;

pub const XLR_MAX_BLOCK_ID: u8 = 32;

#[derive(Clone, Copy, Debug)]
pub struct RelFileNode {
    pub spc_node: u32,
    pub db_node: u32,
    pub rel_node: u32,
}

#[derive(Clone, Debug)]
pub struct XLBData {
    pub blk_id: u8,
    pub fork_num: u8,
    pub has_image: bool,
    pub has_data: bool,
    pub flags: u8,
    pub data_len: u32,
    pub rnode: Option<RelFileNode>,
    pub blkno: u32,
    pub data: Vec<u8>,
}

impl std::fmt::Display for RelFileNode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.spc_node, self.db_node, self.rel_node)
    }
}

impl std::fmt::Display for XLBData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let rnode_str = self
            .rnode
            .map_or(String::from(""), |x| format!("rnode: {}, ", x));
        if self.blk_id < XLR_MAX_BLOCK_ID {
            write!(f, "blk_id: 0x{:X}, fork_num: {}, has_image: {}, has_data: {}, flags: 0x{:X}, {}data_len: {}",
            self.blk_id, self.fork_num, self.has_image, self.has_data,
            self.flags, rnode_str, self.data_len)
        } else {
            write!(
                f,
                "blk_id: 0x{:X}, data_len: {}",
                self.blk_id, self.data_len
            )
        }
    }
}

pub fn parse_main_data_block_header(i: &[u8]) -> IResult<&[u8], XLBData, XLogError<&[u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id < XLR_BLOCK_ID_DATA_LONG {
        // Not a main block header, exit
        return Err(nom::Err::Error(XLogError::IncorrectId(blk_id)));
    }

    let (i, data_len) = if blk_id == XLR_BLOCK_ID_DATA_SHORT {
        le_u8(i).map(|(i, x)| (i, u32::from(x)))?
    } else {
        le_u16(i).map(|(i, x)| (i, u32::from(x)))?
    };

    let data = vec![0; data_len as usize];
    let block_header = XLBData {
        blk_id,
        fork_num: 0,
        flags: 0,
        has_image: false,
        has_data: true,
        data_len,
        rnode: None,
        blkno: 0,
        data,
    };
    debug!("Parsed main block header {}", block_header);
    Ok((i, block_header))
}

pub fn parse_data_block_header<'a>(
    previous_block: Option<&XLBData>,
    i: &'a [u8],
) -> IResult<&'a [u8], XLBData, XLogError<&'a [u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id > XLR_MAX_BLOCK_ID {
        return Err(nom::Err::Error(XLogError::EndBlock));
    }
    // We expect the block_id to be ordered, starting with 0
    if previous_block.is_some_and(|x| blk_id <= x.blk_id) {
        return Err(nom::Err::Error(XLogError::InvalidBlockId(
            previous_block.map(|x| x.blk_id),
            blk_id,
        )));
    }

    let (i, fork_flags) = le_u8(i)?;
    let fork_num = fork_flags & BKPBLOCK_FORK_MASK;
    let flags = fork_flags & BKPBLOCK_FLAG_MASK;
    let has_image = fork_flags & BKPBLOCK_HAS_IMAGE > 0;
    let has_data = fork_flags & BKPBLOCK_HAS_DATA > 0;
    let (i, data_len) = le_u16(i)?;

    if has_data && data_len == 0 {
        return Err(nom::Err::Error(XLogError::MissingBlockDataLen));
    }

    if !has_data && data_len > 0 {
        return Err(nom::Err::Error(XLogError::UnexpectedBlockDataLen(data_len)));
    }

    if has_image {
        todo!("HANDLE BLOCK IMAGE");
    }

    let (i, rnode) = if fork_flags & BKPBLOCK_SAME_REL > 0 {
        match previous_block {
            // No previous block
            None => return Err(nom::Err::Error(XLogError::OutOfOrderBlock)),
            // Return previous relnode
            Some(blk) => (i, blk.rnode),
        }
    } else {
        let (i, spc_node) = le_u32(i)?;
        let (i, db_node) = le_u32(i)?;
        let (i, rel_node) = le_u32(i)?;
        let rnode = RelFileNode {
            spc_node,
            db_node,
            rel_node,
        };
        (i, Some(rnode))
    };

    let (i, blkno) = le_u32(i)?;
    let data = vec![0; data_len as usize];
    let block = XLBData {
        blk_id,
        fork_num,
        flags,
        has_image,
        has_data,
        data_len: data_len as u32,
        rnode,
        blkno,
        data,
    };
    debug!("Parsed block header {}", block);
    Ok((i, block))
}

pub fn parse_blocks(i: &[u8]) -> IResult<&[u8], Vec<XLBData>, XLogError<&[u8]>> {
    let mut blocks = Vec::new();
    let mut input = i;
    loop {
        match parse_data_block_header(blocks.last(), input) {
            Ok((i, block)) => {
                blocks.push(block);
                input = i;
            }
            Err(nom::Err::Error(XLogError::EndBlock)) => break,
            Err(e) => return Err(e),
        }
    }
    let (i, main_block) = parse_main_data_block_header(input)?;
    input = i;
    blocks.push(main_block);

    // We've reached the block's data
    for block in &mut blocks {
        let (i, data) = take(block.data_len)(input)?;
        input = i;
        debug!("Data for block {}: {:X?}", block.blkno, data);
        block.data.copy_from_slice(data);
    }

    Ok((input, blocks))
}
