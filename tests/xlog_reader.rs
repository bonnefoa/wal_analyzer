use wal_analyzer::{
    xlog_page::{parse_xlog_page_header, XLogPageHeader, XLP_BKP_REMOVABLE, XLP_LONG_HEADER},
    xlog_reader::{parse_filename, XLogFilePos},
    xlog_record::{parse_xlog_record, RmgrId},
};

#[test]
fn test_parse_filename() {
    let input = "000000010000000000000002";
    let res = parse_filename(input);
    match res {
        Ok(XLogFilePos { tli, log, seg }) => {
            assert_eq!(tli, 1);
            assert_eq!(log, 0);
            assert_eq!(seg, 2);
        }
        e => {
            panic!("Unexpected output: {:?}", e)
        }
    }
}

#[test]
fn test_xlog_file_pos_to_recptr() {
    let walsegsize = 16 * 1024 * 1024;
    let tli = 1;
    let log = 2;
    let seg = 0;
    let res = XLogFilePos { tli, log, seg }.get_xlog_rec_ptr(walsegsize);
    assert_eq!(res, 33554432);
}

#[test]
fn test_page_with_two_records() {
    // Page:
    //  xlp_magic: \x0d\xd1
    //  xlp_info: \x06\x00
    //  xlp_tli: \x01\x00
    //  xlp_pageaddr: \x00\x00\x00\x00\x40\x01
    //  xlp_rem_len: \x00\x00\x00\x00
    //  padding: \x00\x00\x00\x00
    //  xlp_sys_id = \x71\x7c\xc5\x31\x82\x1d\xf1\x67
    //  xlp_seg_size = \x00\x00\x10\x00
    //  xlp_xlog_blcksz = \x00\x20\x00\x00
    // Record1
    //   header:
    //    xl_tot_len: \x3b\x00\x00\x00
    //    xl_xid: \xe8\x02\x00\x00
    //    xl_prev: \x70\xcc\x3f\x01\x00\x00\x00\x00
    //    xl_info: \x80
    //    xl_rmid: \x0a
    //    padding: \x00\x00
    //    xl_crc: \x25\xcb\x5b\xc0
    //  block:
    //    \x00\x60\x0a\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00\x00\x00\x00\x00\xff\x03\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00
    // Record2:
    //   header:
    //    xl_tot_len: \x5a\x00\x00\x00
    //  \xe8\x02\x00\x00\x28\x00\x40\x01\x00\x00\x00\x00\xa0\x0b\x00\x00\x14\x78\x7e\x7d\x00\x40\x00\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x17\x40\x00\x00\x01\x00\x00\x00\x02\xe0\x1c\x00\x00\x00\x00\x00\xff\x08\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa9\xb4\x3e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
    let input = b"\x0d\xd1\x06\x00\x01\x00\x00\x00\x00\x00\x40\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x71\x7c\xc5\x31\x82\x1d\xf1\x67\x00\x00\x10\x00\x00\x20\x00\x00\x3b\x00\x00\x00\xe8\x02\x00\x00\x70\xcc\x3f\x01\x00\x00\x00\x00\x80\x0a\x00\x00\x25\xcb\x5b\xc0\x00\x60\x0a\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x16\x40\x00\x00\x00\x00\x00\x00\xff\x03\x04\x00\x01\x08\x18\x01\x01\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00\x5a\x00\x00\x00\xe8\x02\x00\x00\x28\x00\x40\x01\x00\x00\x00\x00\xa0\x0b\x00\x00\x14\x78\x7e\x7d\x00\x40\x00\x00\x7f\x06\x00\x00\xb0\x32\x00\x00\x17\x40\x00\x00\x01\x00\x00\x00\x02\xe0\x1c\x00\x00\x00\x00\x00\xff\x08\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa9\xb4\x3e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let (i, page_header) = parse_xlog_page_header(input).unwrap();

    let long_page_header = match page_header {
        XLogPageHeader::Short(_) => panic!("Expected short page header"),
        XLogPageHeader::Long(xlog_long_page_header) => xlog_long_page_header,
    };
    assert_eq!(
        long_page_header.std.xlp_info,
        XLP_LONG_HEADER | XLP_BKP_REMOVABLE
    );
    assert_eq!(long_page_header.std.xlp_tli, 1);
    assert_eq!(long_page_header.std.xlp_pageaddr, 0x1400000);
    assert_eq!(long_page_header.std.xlp_rem_len, 0);

    assert_eq!(long_page_header.xlp_sysid, 0x67f11d8231c57c71);
    assert_eq!(long_page_header.xlp_seg_size, 0x100000);
    assert_eq!(long_page_header.xlp_xlog_blcksz, 0x2000);

    let (i, record) = parse_xlog_record(i).unwrap();
    assert_eq!(record.header.xl_rmid, RmgrId::Heap);
    assert_eq!(record.header.xl_xid, 744);
    assert_eq!(record.header.xl_crc, 3227241253);

    let (i, record) = parse_xlog_record(i).unwrap();
    assert_eq!(record.header.xl_rmid, RmgrId::Btree);
    assert_eq!(record.header.xl_xid, 744);
    assert_eq!(record.header.xl_crc, 2105440276);
    assert_eq!(i.len(), 0);
}
