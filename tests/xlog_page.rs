use wal_analyzer::xlog_page::parse_xlog_page_header;

#[test]
fn test_parse_page_header() {
    let input = b"\x0d\xd1\x07\x00\x01\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x23\x04\x00\x00";
    let res = parse_xlog_page_header(input);
    assert!(res.is_ok(), "{:?}", res);

    let (i, page) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);
    assert_eq!(page.xlp_magic, 0xd10d);
}

#[test]
fn test_page_too_small() {
    let input = b"\x0d\xd1";
    let res = parse_xlog_page_header(input);
    assert!(matches!(res, Err(nom::Err::Incomplete(_))));
}
