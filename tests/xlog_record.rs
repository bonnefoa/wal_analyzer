use wal_analyzer::xlog_record::parse_xlog_record;

#[test]
fn test_record_too_small() {
    let input = b"\x00\x00";
    let res = parse_xlog_record(input);
    assert!(matches!(res, Err(nom::Err::Incomplete(_))));
}

#[test]
fn test_working_record() {
    // rmgr: Standby     len (rec/tot):     50/    50, tx:          0, lsn: 0/04000028, prev 0/03004A00, desc: RUNNING_XACTS nextXid 746 latestCompletedXid 745 oldestRunningXid 746
    let input = b"\x32\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x03\x00\x00\x00\x00\x10\x08\x00\x00\xed\x8b\xfc\x2d\xff\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\xee\x0a\xea\x02\x00\x00\xea\x02\x00\x00\xe9\x02\x00\x00";
    let res = parse_xlog_record(input);
    assert!(res.is_ok(), "{:?}", res);

    let (i, record) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);
    assert_eq!(record.xl_tot_len, 50);
    assert_eq!(record.xl_xid, 0);
}
