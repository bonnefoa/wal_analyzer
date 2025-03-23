use clap::Parser;
mod xlog;
use std::path::PathBuf;
use std::env;

/// A PostgreSQL XLOG analyzer CLI tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to WAL segment to process
    wal_segment: PathBuf,

    /// Limit of records to process
    #[arg(short, long)]
    record_limit: Option<u64>,
}

// fn process_xlog_file(path: PathBuf) -> Result<(), XLogError<&[u8]>> {
//     println!("Processing XLOG file: {}", path.display());
// 
// //    let reader = XLogReader::new(path, None)?;
// 
// //    for (page_num, page_result) in reader.enumerate() {
// //        match page_result {
// //            Ok(records) => {
// //                println!("\nPage {}: {} records", page_num + 1, records.len());
// //                for (record_num, record) in records.iter().enumerate() {
// //                    println!("  Record {}:", record_num + 1);
// //                    println!("    Total length: {} bytes", record.xl_tot_len);
// //                    println!("    Transaction ID: {}", record.xl_xid);
// //                    println!("    Previous LSN: 0x{:X}", record.xl_prev);
// //                    println!("    Info: 0x{:X}", record.xl_info);
// //                    println!("    Resource Manager: {:?}", record.xl_rmid);
// //                    println!("    CRC: 0x{:X}", record.xl_crc);
// //                    println!("    Data length: {} bytes", record.xl_data.len());
// //                    if !record.xl_data.is_empty() {
// //                        println!("    First 16 bytes of data: {:?}",
// //                            record.xl_data.iter().take(16).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
// //                    }
// //                }
// //            }
// //            Err(e) => {
// //                println!("Error reading page {}: {}", page_num + 1, e);
// //            }
// //        }
// //    }
// 
//     Ok(())
// }

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <wal_segment>", args[0]);
        std::process::exit(1);
    }

//    let path = PathBuf::from(&args[1]);
//    if let Err(e) = process_xlog_file(path) {
//        eprintln!("Error: {}", e);
//        std::process::exit(1);
//    }
}
