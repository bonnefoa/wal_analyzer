use wal_analyzer::xlog::{parse_filename, xlog_seg_to_recptr, XLogFilePos, XLogRecPtr};

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
fn test_xlog_seg_to_recptr() {
    let walsegsize = 16 * 1024 * 1024; // 16MB
    let XLogRecPtr(res) = xlog_seg_to_recptr(2, walsegsize, 0);
    assert_eq!(res, 33554432);
}
