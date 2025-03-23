use wal_analyzer::xlog_record::parse_xlog_record;

#[test]
fn test_record_too_small() {
    let input = b"\x00\x00";
    let res = parse_xlog_record(input);
    assert!(matches!(res, Err(nom::Err::Incomplete(_))));
}

#[test]
fn test_working_record() {
    // rmgr: Heap2       len (rec/tot):   6515/  6515, tx:        737, lsn: 0/02000450, prev 0/01FFEAB0, desc: MULTI_INSERT+INIT 61 tuples flags 0x08, blkref #0: rel 1663/12976/16396 blk 1506
    let input = b"\x00\x00\x00\x00\x76\xb3\x5f\x3c\x04\xb7\xdf\x67\x00\x00\x00\x01\x00\x20\x00\x00\x02\x08";
    let res = parse_xlog_record(input);
    assert!(res.is_ok(), "{:?}", res);

    let (i, record) = res.unwrap();
    assert!(i.is_empty(), "{:?}", i);
    assert_eq!(record.xl_tot_len, 6515);
    assert_eq!(record.xl_xid, 737);
}
