use wal_analyzer::inspect::page_inspect::{
    parse_page_header, PageHeaderData, PageXLogRecPtr, PD_ALL_VISIBLE,
};

#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

#[test]
fn test_parse_page_header() {
    let input =  b"\x0e\x00\x00\x00\xa8\x05\x06\x8a\x77\x87\x00\x00\x20\x00\xc0\x1f\x00\x20\x04\x20\x00\x00\x00\x00\xe0\x9f\x38\x00\xc0\x9f\x38";
    //    let input = b"\x00\x00\x00\x00\x80\x2c\x89\x00\x4f\x95\x04\x00\x0c\x01\x80\x01\x00\x20\x04\x20\x00\x00\x00\x00";
    let res = parse_page_header::<nom_language::error::VerboseError<&[u8]>>(input);
    assert!(res.is_ok(), "{:?}", res);
    let (i, page_header) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);

    let pd_lsn = PageXLogRecPtr {
        xlogid: 0,
        xrecoff: 0x892c80,
    };
    let pd_linp = Vec::new();

    let expected_page_header = PageHeaderData {
        pd_lsn,
        pd_checksum: 0x954f,
        pd_flags: PD_ALL_VISIBLE as u16,
        pd_lower: 268,
        pd_upper: 384,
        pd_special: 0x2000,
        pd_pagesize_version: 0x2004,
        pd_prune_xid: 0,
        pd_linp,
    };
    assert_eq!(expected_page_header, page_header);
}

// #[test]
// fn test_parse_line_pointers() {
//     //
//     let input =  b"\x0e\x00\x00\x00\xa8\x05\x06\x8a\x77\x87\x00\x00\x20\x00\xc0\x1f\x00\x20\x04\x20\x00\x00\x00\x00\xe0\x9f\x38\x00\xc0\x9f\x38";
//
// }
