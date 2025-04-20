use std::collections::HashMap;

use crate::xlog::block::{PageId, XLBData, XLBImage, BKPIMAGE_IS_COMPRESSED, BLCKSZ};
use crate::xlog::record::{RmgrId, XLogRecord};

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
        if record.header.xl_rmid != RmgrId::Heap || record.header.xl_rmid != RmgrId::Heap2 {
            // Not a heap change, ignore
            // TODO: Handle btree
            return Ok(());
        }

        for block in &record.blocks {
            // First, restore eventual full page images
            if let Some(image) = &block.image {
                self.apply_image(block, image)?
            }

            // if let Some(data) = block.data {
            //     self.apply_data(block, data)?
            // }
        }
        Ok(())
    }

    fn apply_image(&mut self, block: &XLBData, image: &XLBImage) -> Result<(), ApplyError> {
        let page_id = match block.page_id {
            Some(page_id) => page_id,
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
        self.pages.insert(page_id, Page { data });
        Ok(())
    }

    fn apply_data(&self, block: &XLBData, data: Vec<u8>) -> Result<(), ApplyError> {
        todo!()
    }
}
