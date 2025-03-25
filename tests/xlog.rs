use wal_analyzer::xlog::{parse_filename, XLogFilePos};

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
