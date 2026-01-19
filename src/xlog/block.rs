use crate::error::XLogError;
use crate::xlog::common::TransactionId;
use crate::xlog::reader::XLogRecPtr;
use crate::xlog::record::RmgrId;
use log::debug;
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{map, peek, verify};
use nom::error::{context, ContextError, ParseError};
use nom::multi::length_data;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::sequence::preceded;
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

/// page image has "hole"
pub const BKPIMAGE_HAS_HOLE: u8 = 0x01;
///page image is compressed
pub const BKPIMAGE_IS_COMPRESSED: u8 = 0x02;
///page image should be restored during replay
pub const BKPIMAGE_APPLY: u8 = 0x04;

const XLR_MAX_BLOCK_ID: u8 = 32;

// TODO: Make this configurable
pub const BLCKSZ: u16 = 8192;
pub type BlockNumber = u32;

#[derive(Debug, Clone, PartialEq, Hash, Eq, Copy)]
pub enum ForkNumber {
    Main,
    Fsm,
    VisibilityMap,
    Init,
}

impl TryFrom<u8> for ForkNumber {
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(ForkNumber::Main),
            0x01 => Ok(ForkNumber::Fsm),
            0x02 => Ok(ForkNumber::VisibilityMap),
            0x03 => Ok(ForkNumber::Init),
            f => Err(f),
        }
    }
}

impl std::fmt::Display for ForkNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            ForkNumber::Main => "Main",
            ForkNumber::Fsm => "Fsm",
            ForkNumber::VisibilityMap => "VisibilityMap",
            ForkNumber::Init => "Init",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RelFileLocator {
    pub spc_node: u32,
    pub db_node: u32,
    pub rel_node: u32,
}

impl std::fmt::Display for RelFileLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.spc_node, self.db_node, self.rel_node)
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Copy)]
pub struct PageId {
    pub locator: RelFileLocator,
    pub blockno: BlockNumber,
    pub fork: ForkNumber,
}

impl std::fmt::Display for PageId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "locator: {}, blockno{}, fork: {}",
            self.locator, self.blockno, self.fork
        )
    }
}

#[derive(Debug, Clone)]
pub struct XLBImage {
    /// has image that should be restored
    pub apply_image: bool,
    pub hole_offset: u16,
    pub hole_length: u16,
    pub bimg_len: u16,
    pub bimg_info: u8,
    pub bkp_image: Vec<u8>,
}

impl std::fmt::Display for XLBImage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "apply_image: {}, hole_offset: {}, hole_length: {}, len: {}, info: 0x{:X}",
            self.apply_image, self.hole_offset, self.hole_length, self.bimg_len, self.bimg_info
        )
    }
}

/*
 * The overall layout of an XLOG record is:
 *      Fixed-size header (XLogRecord struct)
 *      XLogRecordBlockHeader struct
 *      XLogRecordBlockHeader struct
 *      ...
 *      XLogRecordDataHeader[Short|Long] struct
 *      block data
 *      block data
 *      ...
 *      main data
 *
 * There can be zero or more XLogRecordBlockHeaders, and 0 or more bytes of
 * rmgr-specific data not associated with a block.  XLogRecord structs
 * always start on MAXALIGN boundaries in the WAL files, but the rest of
 * the fields are not aligned.
 *
 * The XLogRecordBlockHeader, XLogRecordDataHeaderShort and
 * XLogRecordDataHeaderLong structs all begin with a single 'id' byte. It's
 * used to distinguish between block references, and the main data structs.
 */
#[derive(Debug, Clone)]
pub struct XLogRecord {
    /// total length of entier record
    xl_tot_len: u32,
    /// xact id
    xl_xid: TransactionId,
    /// ptr to previous record
    xl_prev: XLogRecPtr,
    /// flag bits
    xl_info: u8,
    /// resource manager for this record
    xl_rmid: RmgrId,
    /// CRC for this record
    xl_crc: u32,

    xl_block_headers: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct XLogRecordBlockHeader {
    /// block reference ID
    id: u8,
    /// fork within the relation, and flags
    fork_flags: u8,
    /// number of payload bytes (not including page image)
    data_length: u16,

    block_img: Option<XLogRecordBlockImageHeader>,
}

#[derive(Debug, Clone)]
pub struct XLogRecordBlockImageHeader {
    /// number of page image bytes
    length: u16,
    /// number of bytes before "hole"
    hole_offset: u16,
    /// flag bits
    bimg_info: u16,

    /// if BKPIMAGE_HAS_HOLE and BKPIMAGE_COMPRESSED, page
    /// image has "hole" and is compressed
    hole_length: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct XLBData {
    blk_id: u8,

    // Identify the block this refers to
    page_id: Option<PageId>,

    // Copy of fork_flags field from the block header
    flags: u8,

    // Information on full-page image, if any
    image: Option<XLBImage>,

    // TODO: Probably redundant
    has_data: bool,
    data_len: u16,
    data: Option<Vec<u8>>,
}

impl std::fmt::Display for XLBData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let pageid_str = self
            .page_id
            .as_ref()
            .map_or(String::from(""), |x| format!("page: {}, ", x));
        let image_str = self
            .image
            .as_ref()
            .map_or(String::from(""), |x| format!("image: {}, ", x));
        if self.blk_id < XLR_MAX_BLOCK_ID {
            write!(
                f,
                "blk_id: 0x{:X}, {}{}flags: 0x{:X}, data_len: {}",
                self.blk_id, pageid_str, image_str, self.flags, self.data_len
            )
        } else {
            write!(
                f,
                "blk_id: 0x{:X}, data_len: {}",
                self.blk_id, self.data_len
            )
        }
    }
}

// fn ws<'a, O, E: ParseError<&'a str>, F: Parser<&'a str, Output = O, Error = E>>(
//   f: F,
// ) -> impl Parser<&'a str, Output = O, Error = E> {
//   delimited(first: multispace0, second: f, third: multispace0)
// }

//fn byte<'a, E: ParseError<&'a [u8]>, F: Parser<&'a [u8], Output=u8, Error = E>>(value: u8)
//-> impl Parser<&'a [u8], Output = u8, Error = E> {
fn byte<'a, E: ParseError<&'a [u8]>>(value: u8) -> impl Parser<&'a [u8], Output = u8, Error = E> {
    verify(le_u8, move |u| *u == value)
}

// fn parse_short_data_block_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
//     i: &'a [u8],
// ) -> IResult<&'a [u8], XLBData, E> {
//     let parse_short_length = le_u8.map(u16::from);
//     let parse_long_length = le_u16;
//
//         preceded(byte(XLR_BLOCK_ID_DATA_SHORT), parse_short_length )
//
//         .map(|data_len| XLBData {
//             blk_id: XLR_BLOCK_ID_DATA_SHORT,
//             page_id: None,
//             flags: 0,
//             image: None,
//             has_data: true,
//             data_len,
//             data: Some(vec![0; data_len as usize]),
//         })
//         .parse(i)
// }

fn parse_main_data_block_header<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], XLBData, E> {
    //    let parse_short_length = le_u8.map(u16::from);
    //    let parse_long_length = le_u16;

    context(
        "Xlog_Block",
        alt((
            preceded(
                byte(XLR_BLOCK_ID_DATA_SHORT),
                map(le_u8::<&'a [u8], E>, u16::from),
            ),
            preceded(byte(XLR_BLOCK_ID_DATA_LONG), le_u16),
        )),
    )
    .parse(i);

    todo!()
    //    let (i, blk_id) = le_u8(i)?;
    //    if blk_id < XLR_BLOCK_ID_DATA_LONG {
    //        // Not a main block header, exit
    //        return Err(nom::Err::Error(XLogError::IncorrectId(blk_id)));
    //    }
    //
    //    let (i, data_len) = if blk_id == XLR_BLOCK_ID_DATA_SHORT {
    //        le_u8(i).map(|(i, x)| (i, u16::from(x)))?
    //    } else {
    //        le_u16(i)?
    //    };
    //
    //    let data = Some(vec![0; data_len as usize]);
    //    let block_header = XLBData {
    //        blk_id,
    //        page_id: None,
    //        flags: 0,
    //        image: None,
    //        has_data: true,
    //        data_len,
    //        data,
    //    };
    //    debug!("Parsed main block header {}", block_header);
    //    Ok((i, block_header))
}

fn parse_relfilenode(i: &[u8]) -> IResult<&[u8], RelFileLocator, XLogError<&[u8]>> {
    let (i, spc_node) = le_u32(i)?;
    let (i, db_node) = le_u32(i)?;
    let (i, rel_node) = le_u32(i)?;
    let rnode = RelFileLocator {
        spc_node,
        db_node,
        rel_node,
    };
    Ok((i, rnode))
}

fn parse_block_image(i: &[u8]) -> IResult<&[u8], XLBImage, XLogError<&[u8]>> {
    let (i, bimg_len) = le_u16(i)?;
    let (i, hole_offset) = le_u16(i)?;
    let (i, bimg_info) = le_u8(i)?;

    let apply_image = (bimg_info & BKPIMAGE_APPLY) != 0;
    let is_compressed = (bimg_info & BKPIMAGE_IS_COMPRESSED) != 0;
    let has_hole = (bimg_info & BKPIMAGE_HAS_HOLE) != 0;
    let (i, hole_length) = if is_compressed {
        if has_hole {
            le_u16(i)?
        } else {
            (i, 0)
        }
    } else {
        (i, BLCKSZ - bimg_len)
    };

    if has_hole && (hole_offset == 0 || hole_length == 0 || bimg_len == BLCKSZ) {
        return Err(nom::Err::Error(XLogError::InvalidBlockImageHole(
            hole_offset,
            hole_length,
            bimg_len,
        )));
    }
    let bkp_image = vec![0; bimg_len as usize];
    let xlb_image = XLBImage {
        apply_image,
        hole_offset,
        hole_length,
        bimg_len,
        bimg_info,
        bkp_image,
    };
    debug!("Parsed block image {:?}", xlb_image);
    Ok((i, xlb_image))
}

fn parse_data_block_header<'a>(
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
    let fork = match ForkNumber::try_from(fork_flags & BKPBLOCK_FORK_MASK) {
        Ok(fork) => fork,
        Err(f) => return Err(nom::Err::Error(XLogError::InvalidForkNumber(f))),
    };
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

    let (i, image) = if has_image {
        parse_block_image(i).map(|(i, img)| (i, Some(img)))?
    } else {
        (i, None)
    };

    let (i, locator) = if fork_flags & BKPBLOCK_SAME_REL != 0 {
        match previous_block {
            // No previous block
            None => return Err(nom::Err::Error(XLogError::OutOfOrderBlock)),
            // Return previous relnode
            Some(blk) => match &blk.page_id {
                Some(page_id) => (i, page_id.locator),
                None => return Err(nom::Err::Error(XLogError::OutOfOrderBlock)),
            },
        }
    } else {
        parse_relfilenode(i)?
    };

    let (i, blockno) = le_u32(i)?;
    let page_id = Some(PageId {
        locator,
        blockno,
        fork,
    });
    let data = Some(vec![0; data_len as usize]);
    let block = XLBData {
        blk_id,
        page_id,
        flags,
        image,
        has_data,
        data_len,
        data,
    };
    debug!("Parsed block header {}", block);
    Ok((i, block))
}

type BlockResult<'a> = (&'a [u8], Vec<XLBData>);

pub fn parse_blocks(i: &[u8]) -> IResult<&[u8], BlockResult, XLogError<&[u8]>> {
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

    let main_block_start = input;
    //    let (i, main_block) = parse_main_data_block_header(main_block_start)?;
    //    input = i;
    //    blocks.push(main_block);

    // We've reached the block's data
    for block in &mut blocks {
        // Fetch image data first
        input = match &mut block.image {
            Some(image) => {
                let (i, data) = take(image.bimg_len)(input)?;
                image.bkp_image.copy_from_slice(data);
                i
            }
            None => input,
        };

        let (i, data) = take(block.data_len)(input)?;
        input = i;
        debug!("Data for block {:?}: {:X?}", block.page_id, data);
        if let Some(block_data) = block.data.as_mut() {
            block_data.copy_from_slice(data);
        } else {
            return Err(nom::Err::Error(XLogError::EmptyRecord));
        }
    }

    if !input.is_empty() {
        return Err(nom::Err::Error(XLogError::LeftoverBytes(input.to_owned())));
    }
    Ok((input, (main_block_start, blocks)))
}
