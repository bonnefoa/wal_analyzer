use nom::number::streaming::{le_u16, le_u32, le_u64};
use nom::IResult;
use crate::error::XLogError;

#[derive(Clone, Debug)]
pub struct XLogPageHeader {
    pub xlp_magic: u16,
    pub xlp_info: u16,
    pub xlp_tli: u32,
    pub xlp_pageaddr: u64,
    pub xlp_rem_len: u32,
}

pub fn parse_xlog_page_header(i: &[u8]) -> IResult<&[u8], XLogPageHeader, XLogError<&[u8]>> {
    if i.len() < 20 {
        return Err(nom::Err::Incomplete(nom::Needed::new(20 - i.len())));
    }

    let (i, xlp_magic) = le_u16(i)?;
    if xlp_magic != 0xd10d {
        return Err(nom::Err::Error(XLogError::InvalidPageHeader));
    }

    let (i, xlp_info) = le_u16(i)?;
    let (i, xlp_tli) = le_u32(i)?;
    let (i, xlp_pageaddr) = le_u64(i)?;
    let (i, xlp_rem_len) = le_u32(i)?;

    let page_header = XLogPageHeader {
        xlp_magic,
        xlp_info,
        xlp_tli,
        xlp_pageaddr,
        xlp_rem_len,
    };

    Ok((i, page_header))
}
