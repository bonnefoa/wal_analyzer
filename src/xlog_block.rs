use crate::error::XLogError;
use log::debug;
use nom::multi;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::IResult;
use nom::Parser;

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

#[derive(Clone, Debug)]
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
    pub data: Vec<u8>,
}

static mut RNODE: Option<RelFileNode> = None;

impl std::fmt::Display for XLBData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "blk_id: 0x{:X}, fork_num: {}, has_image: {}, has_data: {}, flags: 0x{:X}, data_len: {}, data: {:X?}",
            self.blk_id, self.fork_num, self.has_image, self.has_data,
            self.flags, self.data_len, self.data)
    }
}

pub fn parse_main_data_block_header(i: &[u8]) -> IResult<&[u8], XLBData, XLogError<&[u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id < XLR_BLOCK_ID_DATA_LONG {
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
        data,
    };
    Ok((i, block_header))
}

pub fn parse_data_block_header(i: &[u8]) -> IResult<&[u8], XLBData, XLogError<&[u8]>> {
    let (i, blk_id) = le_u8(i)?;
    if blk_id > XLR_MAX_BLOCK_ID {
        return Err(nom::Err::Error(XLogError::EndBlock));
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
        todo!("REUSE RNODE");
    } else {
        let (i, spc_node) = le_u32(i)?;
        let (i, db_node) = le_u32(i)?;
        let (i, rel_node) = le_u32(i)?;
        let rnode = RelFileNode {
            spc_node,
            db_node,
            rel_node,
        };
        (i, rnode)
    };

    let data = vec![0; data_len as usize];
    let block = XLBData {
        blk_id,
        fork_num,
        flags,
        has_image,
        has_data,
        data_len: data_len as u32,
        data,
    };
    debug!("Parsed block header {}", block);
    Ok((i, block))
}

pub fn parse_block_headers(i: &[u8]) -> IResult<&[u8], Vec<XLBData>, XLogError<&[u8]>> {
    let (i, mut data_blocks) = multi::many0(parse_data_block_header).parse(i)?;
    let (i, main_data) = parse_main_data_block_header(i)?;
    data_blocks.push(main_data);
    Ok((i, data_blocks))
}
