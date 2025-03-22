# PostgreSQL WAL Analyzer

A command-line tool for analyzing PostgreSQL Write-Ahead Log (WAL) files.

## Installation

Make sure you have Rust installed on your system. Then clone this repository and build the project:

```bash
cargo build --release
```

## Usage

The tool can be run with the following command:

```bash
cargo run -- [STARTSEG] [ENDSEG] [OPTIONS]
```

### Arguments

- `STARTSEG`: First WAL segment file to process (e.g., 000000010000000000000001)
- `ENDSEG`: Last WAL segment file to process (e.g., 000000010000000000000002)

### Options

- `-n, --limit`: Number of records to display
- `-p, --path`: Directory containing WAL files
- `-s, --start`: Start reading at this WAL location
- `-e, --end`: Stop reading at this WAL location
- `-r, --rmgr`: Filter on rmgr (e.g., XLOG, STANDBY, HEAP, Btree, etc.)
- `-b, --bkp-details`: Show detailed information about backup blocks
- `-v, --verbose`: Output a more verbose description of the commands

### Examples

```bash
# Process a single WAL segment
cargo run -- 000000010000000000000001

# Process a range of WAL segments
cargo run -- 000000010000000000000001 000000010000000000000002

# Process WAL segments from a specific directory
cargo run -- 000000010000000000000001 000000010000000000000002 --path /var/lib/postgresql/14/main/pg_wal

# Process WAL segments with a record limit
cargo run -- 000000010000000000000001 000000010000000000000002 --limit 100

# Process WAL segments with rmgr filter
cargo run -- 000000010000000000000001 000000010000000000000002 -r XLOG
# or
cargo run -- 000000010000000000000001 000000010000000000000002 --rmgr XLOG
```

## Development

To run the project in development mode:

```bash
cargo run
```

## License

This project is licensed under the MIT License. 