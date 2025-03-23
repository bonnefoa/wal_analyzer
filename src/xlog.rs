use std::fs::File;

pub struct XLogReader {
    file: File,
    record_limit: Option<u64>,
    records_read: u64,
}

// impl XLogReader {
//     pub fn new<P: AsRef<Path>>(path: P, record_limit: Option<u64>) -> Result<Self, XLogError> {
//         let file = File::open(path)?;
//         Ok(Self {
//             file,
//             records_read: 0,
//             record_limit,
//         })
//     }
// }
