use std::fmt;

use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub enum XLogError<I: Sized> {
    /// No more data available
    Eof,
    InvalidPageHeader,
    EmptyRecord,
    EndBlock,
    MissingBlockDataLen,
    UnexpectedBlockDataLen(u16),
    IncorrectId(u8),
    IncorrectPageType,
    LeftoverBytes(Vec<u8>),
    IncorrectPaddingValue(Vec<u8>),
    InvalidRecord(String),

    /// An error encountered during parsing
    NomParseError(I, ErrorKind),
}

impl<I> ParseError<I> for XLogError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        XLogError::NomParseError(input, kind)
    }
    fn append(input: I, kind: ErrorKind, _other: Self) -> Self {
        XLogError::NomParseError(input, kind)
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
            XLogError::EmptyRecord => write!(f, "Empty record"),
            XLogError::EndBlock => write!(f, "End block"),
            XLogError::MissingBlockDataLen => {
                write!(f, "BKPBLOCK_HAS_DATA set, but not data included")
            }
            XLogError::UnexpectedBlockDataLen(d) => {
                write!(f, "BKPBLOCK_HAS_DATA not set, but data length is {}", d)
            }
            XLogError::IncorrectPageType => write!(f, "Incorrect page type"),
            XLogError::IncorrectId(u) => {
                write!(f, "Incorrect id {:x?}", u)
            }
            XLogError::LeftoverBytes(leftover) => {
                write!(f, "Leftover bytes {:x?}", leftover)
            }
            XLogError::IncorrectPaddingValue(padding) => {
                write!(f, "Incorrect padding value {:x?}", padding)
            }
            XLogError::InvalidRecord(e) => write!(f, "Invalid XLog Record {:?}", e),
            XLogError::NomParseError(i, e) => {
                write!(f, "Internal parser error {:?}, input {:x?}", e, i)
            }
        }
    }
}
