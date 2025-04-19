use std::collections::HashMap;

use crate::xlog_block::{BlockNumber, PageId, RelFileLocator, XLBData, XLBImage, BLCKSZ};
use crate::xlog_record::XLogRecord;

pub struct Page {
    pub data: [u8; BLCKSZ as usize],
}

struct PageMapping {
    pub pages: HashMap<PageId, Page>,
}

impl PageMapping {
    pub fn apply_xlog_record(self, record: &XLogRecord) {
        for block in &record.blocks {
            if let Some(image) = &block.image {
                self.apply_image(block, image)
            }
        }
    }

    fn apply_image(&self, block: &XLBData, image: &XLBImage) {
        todo!()
    }
}
