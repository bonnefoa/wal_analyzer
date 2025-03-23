use std::fmt;

use nom::error::{ErrorKind, ParseError};

#[derive(Debug, PartialEq)]
pub enum XLogError<I: Sized> {
    /// No more data available
    Eof,
    InvalidPageHeader,
    InvalidRecord(String),

    /// An error encountered during parsing
    NomError(I, ErrorKind),
}

impl<I> ParseError<I> for XLogError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        XLogError::NomError(input, kind)
    }
    fn append(input: I, kind: ErrorKind, _other: Self) -> Self {
        XLogError::NomError(input, kind)
    }
}

impl<I> fmt::Display for XLogError<I>
where
    I: fmt::Debug,
 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XLogError::Eof => write!(f, "End of file"),
            XLogError::InvalidPageHeader => write!(f, "Invalid page header"),
            XLogError::InvalidRecord(e) => write!(f, "Invalid XLog Record {:?}", e),
            XLogError::NomError(i, e) => write!(f, "Internal parser error {:?}, input {:?}", e, i),
        }
    }
}
