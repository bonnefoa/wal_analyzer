use crate::xlog_block::{BlockNumber, RelFileLocator, BLCKSZ};

pub struct Page {
    pub data: [u8; BLCKSZ as usize],
}

pub struct PageId {
    pub locator: RelFileLocator,
    pub blockno: BlockNumber,
    pub fork: BlockNumber,
}

// pub update_page_map() {
// }
