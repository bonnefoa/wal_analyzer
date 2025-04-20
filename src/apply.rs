use std::collections::HashMap;
use std::iter;

use crate::xlog_block::{
    PageId, XLBData, XLBImage, BKPIMAGE_HAS_HOLE, BKPIMAGE_IS_COMPRESSED, BLCKSZ,
};
use crate::xlog_record::XLogRecord;

#[derive(Debug)]
pub struct ApplyError {
    pub message: String,
}

pub struct Page {
    pub data: [u8; BLCKSZ as usize],
}

pub struct PageMapping {
    pub pages: HashMap<PageId, Page>,
}

impl Default for PageMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl PageMapping {
    pub fn new() -> Self {
        let pages = HashMap::new();
        Self { pages }
    }

    pub fn apply_xlog_record(&mut self, record: &XLogRecord) -> Result<(), ApplyError> {
        for block in &record.blocks {
            if let Some(image) = &block.image {
                self.apply_image(block, image)?
            }
        }
        Ok(())
    }

    fn apply_image(&mut self, block: &XLBData, image: &XLBImage) -> Result<(), ApplyError> {
        let pageId = match block.pageId {
            Some(pageId) => pageId,
            None => return Ok(()),
        };

        if (image.bimg_info & BKPIMAGE_IS_COMPRESSED) != 0 {
            todo!("COMPRESSION NOT IMPLEMENTED");
        }

        let mut data_vec = Vec::new();
        let page_vec = if image.hole_length > 0 {
            // We have a hole
            // Copy data before the hole
            data_vec.extend_from_slice(&image.bkp_image[..image.hole_offset as usize]);
            // Fill the hole with 0
            data_vec.extend(std::iter::repeat_n(0, image.hole_length as usize));
            // Copy leftover data
            data_vec.extend_from_slice(&image.bkp_image[image.hole_offset as usize..]);
            &data_vec
        } else {
            // No hole, just copy the data content
            &image.bkp_image
        };

        // TODO: Better check on vec size
        let data: [u8; BLCKSZ as usize] = page_vec.as_slice().try_into().unwrap();
        self.pages.insert(pageId, Page { data });
        Ok(())
    }
}
