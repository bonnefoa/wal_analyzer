use wal_analyzer::xlog_block::parse_blocks;

#[cfg(test)]
#[ctor::ctor]
fn init() {
    env_logger::init();
}

#[test]
fn test_parse_heap_block() {
    //  block 1:
    //    id: \x00
    //    flags: \x60
    //    data_len: \x0a\x00
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
    let res = parse_blocks(input);
    assert!(res.is_ok(), "{:?}", res);

    let (i, blocks) = res.unwrap();
    assert_eq!(blocks.len(), 2);
    let block = &blocks[0];

    assert_eq!(block.blk_id, 0);
    assert_eq!(block.fork_num, 0);
    assert_eq!(block.flags, 0x60);
    assert_eq!(block.data_len, 0x0a);

    let main_block = &blocks[1];
    assert_eq!(main_block.blk_id, 0xff);
    assert_eq!(main_block.data_len, 3);

    assert!(i.is_empty(), "{:?}", i);
}
