use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct PageXLogRecPtr {
    xlogid: u32,
    xrecoff: u32,
}

impl Display for PageXLogRecPtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // format ourselves as a `ffffffff/ffffffff` string
        write!(f, "{0:X}/{1:08X}", self.xlogid, self.xrecoff)
    }
}

#[derive(Clone, Debug, Hash, Ord, PartialOrd, PartialEq, Eq, thiserror::Error)]
pub enum InvalidLSN {
    #[error("Invalid LSN Format '{0}'")]
    Format(String),
    #[error("Invalid hex value in '{0}': `{1}`")]
    HexValue(String, String),
}

impl TryFrom<&str> for PageXLogRecPtr {
    type Error = InvalidLSN;

    fn try_from(lsn: &str) -> Result<Self, Self::Error> {
        let mut iter = lsn.split('/');
        let Some(xlogid_str) = iter.next() else {
            return Err(InvalidLSN::Format(lsn.to_string()));
        };
        let xlogid = match u32::from_str_radix(xlogid_str, 16) {
            Ok(xlogid) => xlogid,
            Err(e) => return Err(InvalidLSN::HexValue(lsn.to_string(), e.to_string())),
        };

        let xrecoff_str = iter.next().unwrap();
        let xrecoff = match u32::from_str_radix(xrecoff_str, 16) {
            Ok(xrecoff) => xrecoff,
            Err(e) => return Err(InvalidLSN::HexValue(lsn.to_string(), e.to_string())),
        };
        Ok(PageXLogRecPtr { xlogid, xrecoff })
    }
}

impl PageXLogRecPtr {
    pub fn new((xlogid, xrecoff): (u32, u32)) -> Self {
        Self { xlogid, xrecoff }
    }
}
