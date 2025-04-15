use nom::error::dbg_dmp;
use wal_analyzer::xlog_record::{parse_xlog_record, parse_xlog_record_header};

#[test]
fn test_record_too_small() {
    let input = b"\x00\x00";
    let res = parse_xlog_record_header(input);
    assert!(matches!(res, Err(nom::Err::Incomplete(_))));
}

#[test]
fn test_parse_standby() {
    // Header:
    //  xl_tot_len: \x32\x00\x00\x00
    //  xl_xid: \x00\x00\x00\x00
    //  xl_prev: \x00\x4a\x00\x03\x00\x00\x00\x00
    //  xl_info: \x10
    //  xl_rmid: \x08
    //  padding: \x00\x00
    //  xl_crc: \xed\x8b\xfc\x2d
    // block:
    //  id: \xff
    //  data_len: \x18
    //  \x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\xee\x0a\xea\x02\x00\x00\xea\x02\x00\x00\xe9\x02\x00\x00
    // rmgr: Standby     len (rec/tot):     50/    50, tx:          0, lsn: 0/04000028, prev 0/03004A00, desc: RUNNING_XACTS nextXid 746 latestCompletedXid 745 oldestRunningXid 746
    //            \x32\x00\x00\x00\x00\x00\x00\x00\xc0\x08\x40\x01\x00\x00\x00\x00\x10\x08\x00\x00\x5a\x57\x32\xef\xff\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9b\x80\xe3\xea\x02\x00\x00\xea\x02\x00\x00\xe9\x02\x00\x00
    let input = b"\x32\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x03\x00\x00\x00\x00\x10\x08\x00\x00\xed\x8b\xfc\x2d\xff\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\xee\x0a\xea\x02\x00\x00\xea\x02\x00\x00\xe9\x02\x00\x00\x00\x00\x00\x00\x00\x00";
    let res = dbg_dmp(parse_xlog_record, "record")(input);
    assert!(res.is_ok(), "{:x?}", res);

    let (i, record) = res.unwrap();
    assert_eq!(record.header.xl_tot_len, 50);
    assert_eq!(record.header.xl_xid, 0);

    assert_eq!(record.blocks.len(), 1);
    let block = &record.blocks[0];
    assert_eq!(block.blk_id, 0xff);
    assert_eq!(block.flags, 0);
    assert_eq!(block.data_len, 0x18);
    assert_eq!(block.data.len(), 0x18);

    assert!(i.is_empty(), "{:x?}", i);
}

#[test]
fn test_parse_heap_block() {
    //  block 1:
    //    id: \x00
    //    flags: \x60
    //    data_len: \x0a\x00 (SAME_REL)
    //    RelFileNode (12 bytes): \x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00
    //    BlockNo (4 bytes): \x00\x00\x00\x00
    //
    //  main data info:
    //    id: \xff
    //    main_data_len: \x03
    //
    //  Data blk 1:
    //    \x04\x00\x01\x08\x18\x01\x01\x00\x00\x00
    //
    //  main data:
    //    \x01\x00\x08
    //
    //  Padding: \x00\x00\x00\x00\x00
    //
    // rmgr: Heap        len (rec/tot):     59/    59, tx:        744, lsn: 0/01400028, prev 0/013FCC70, desc: INSERT+INIT off 1 flags 0x08, blkref #0: rel 1663/12976/16406 blk 0

    // let input = b"\x3b\x00\x00\x00\xe8\x02\x00\x00\x70\xcc\x3f\x01\x00\x00\x00\x00\x80\x0a\x00\x00\x25\xcb\x5b\xc0\x00\x60\x0a\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00\x00\x00\x00\x00\xff\x03\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00";
    let input = b"\x00\x60\x0a\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00\x00\x00\x00\x00\xff\x03\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x01\x00\x08";
    let res = wal_analyzer::xlog_record::parse_block_headers(input);
    assert!(res.is_ok(), "{:?}", res);

    let (i, blocks) = res.unwrap();
    assert_eq!(blocks.len(), 1);
    let block = &blocks[0];

    assert_eq!(block.blk_id, 0);
    assert_eq!(block.fork_num, 0);
    assert_eq!(block.flags, 0x60);
    assert_eq!(block.data_len, 0x0a);
    assert!(i.is_empty(), "{:?}", i);

    let main_block = &blocks[1];
    assert_eq!(main_block.blk_id, 0xff);
    assert_eq!(main_block.data_len, 10);
}
