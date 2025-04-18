use nom::error::dbg_dmp;
use wal_analyzer::xlog_record::{parse_xlog_record, parse_xlog_record_header};

#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

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
    assert_eq!(block.data.as_ref().unwrap().len(), 0x18);

    assert!(i.is_empty(), "{:x?}", i);
}

#[test]
fn test_parse_fpw() {
    let input = b"\xe8\x00\x00\x00\xec\x02\x00\x00\x00\x01\x60\x01\x00\x00\x00\x00\x00\x0a\x00\x00\x7e\x34\x63\xfd\x00\x30\x0a\x00\xa8\x00\x28\x00\x05\x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00\x00\x00\x00\x00\xff\x03\x00\x00\x00\x00\x68\x00\x60\x01\x00\x00\x00\x00\x28\x00\x80\x1f\x00\x20\x04\x20\x00\x00\x00\x00\xe0\x9f\x38\x00\xc0\x9f\x38\x00\xa0\x9f\x38\x00\x80\x9f\x38\x00\xec\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x00\x00\x00\x00\xeb\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x00\x00\x00\x00\xea\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x00\x00\x00\x00\xe8\x02\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x04\x00\x01\x09\x18\x01\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x04\x00\x08";
    let res = dbg_dmp(parse_xlog_record, "record")(input);
    assert!(res.is_ok(), "{:x?}", res);

    let (i, record) = res.unwrap();
    assert_eq!(record.header.xl_tot_len, 232);
    assert_eq!(record.header.xl_xid, 748);

    assert_eq!(record.blocks.len(), 2);
    let block = &record.blocks[0];
    assert_eq!(block.blk_id, 0);
    assert_eq!(block.flags, 0x30);
    assert_eq!(block.data_len, 0x0a);
    assert_eq!(block.data.as_ref().unwrap().len(), 0x0a);
    assert!(i.is_empty(), "{:x?}", i);
    assert!(block.image.is_some());

    let image = block.image.as_ref().unwrap();
    assert_eq!(image.bimg_len, 168);

    let block = &record.blocks[1];
    assert_eq!(block.blk_id, 0xff);
    assert_eq!(block.flags, 0x0);
    assert_eq!(block.data_len, 0x03);
}
