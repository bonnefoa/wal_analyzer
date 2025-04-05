use wal_analyzer::xlog_page::{parse_xlog_page_header, XLogPageHeader};

#[test]
fn test_parse_long_page_header() {
    let input = b"\x0d\xd1\x07\x00\x01\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x23\x04\x00\x00\x00\x00\x00\x00\x76\xb3\x5f\x3c\x04\xb7\xdf\x67\x00\x00\x00\x01\x00\x00\x00\x00";
    let res = parse_xlog_page_header(input);
    assert!(res.is_ok(), "{:?}", res);
    match res.unwrap() {
        (i, XLogPageHeader::Long(page)) => {
            assert!(i.is_empty(), "{:?}", i);
            assert_eq!(page.std.xlp_magic, 0xd10d)
        }
        e => {
            panic!("Unexpected output: {:?}", e)
        }
    }
}

#[test]
fn test_page_too_small() {
    let input = b"\x0d\xd1";
    let res = parse_xlog_page_header(input);
    assert!(matches!(res, Err(nom::Err::Incomplete(_))));
}
