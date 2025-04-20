use wal_analyzer::xlog_reader::{parse_filename, XLogFilePos};

#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

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
