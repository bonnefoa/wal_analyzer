use clap::Parser;
use std::path::PathBuf;
use wal_analyzer::xlog_reader::XLogReader;

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

fn main() {
    let args = Args::parse();
    env_logger::init();

    let reader = XLogReader::new_from_filename(args.wal_segment).expect("Error building reader");

    for record in reader {
        print!("{}", record);
    }
}
