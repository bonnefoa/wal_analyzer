use clap::Parser;
mod xlog;
use xlog::{XLogError, XLogReader};
use std::path::PathBuf;

/// A PostgreSQL XLOG analyzer CLI tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the XLOG file
    path: PathBuf,
    /// Limit the number of pages to process
    #[arg(short, long)]
    limit: Option<u64>,
}

fn process_xlog_file(path: &PathBuf, limit: Option<u64>) -> Result<(), XLogError> {
    println!("PostgreSQL XLOG Analyzer");
    println!("=======================");
    
    let reader = XLogReader::new(path, limit)?;
    let file_size = reader.file_size;
    println!("File size: {} bytes ({} pages)", file_size, file_size / 8192);
    println!("\nProcessing XLOG segment...\n");

    let mut pages_processed = 0;
    for result in reader {
        match result {
            Ok(header) => {
                pages_processed += 1;
                println!("Page {}: magic={:X}, info={:X}, timeline={}, lsn={}, rem_len={}", 
                    pages_processed, header.magic, header.info, header.timeline, header.pageaddr, header.rem_len);
            }
            Err(e) => {
                println!("Error reading page {}: {}", pages_processed + 1, e);
                break;
            }
        }
    }

    println!("\nAnalysis complete:");
    println!("Total pages processed: {}", pages_processed);
    if let Some(limit) = limit {
        println!("Page limit: {}", limit);
    }

    Ok(())
}

fn main() -> Result<(), XLogError> {
    let args = Args::parse();
    process_xlog_file(&args.path, args.limit)
}
