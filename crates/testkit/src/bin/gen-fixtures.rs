//! Writes the PCAP fixtures used by integration tests and manual testing.
//!
//! Usage: `cargo run -p nettrace-testkit --bin gen-fixtures -- [out_dir] [--large N]`

use std::path::PathBuf;

use nettrace_testkit::scenarios;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut out = PathBuf::from("fixtures");
    let mut large = None;
    while let Some(a) = args.next() {
        if a == "--large" {
            large = args.next().and_then(|n| n.parse::<u32>().ok());
        } else {
            out = PathBuf::from(a);
        }
    }
    std::fs::create_dir_all(&out)?;
    scenarios::tcp_basic().write_pcap(&out.join("tcp_basic.pcap"))?;
    scenarios::tcp_problems().write_pcap(&out.join("tcp_problems.pcap"))?;
    scenarios::demo().write_pcapng(&out.join("demo.pcapng"))?;
    scenarios::demo().write_pcap(&out.join("demo.pcap"))?;
    if let Some(n) = large {
        let path = out.join(format!("large_{n}.pcap"));
        scenarios::large(n).write_pcap(&path)?;
        println!("wrote {}", path.display());
    }
    println!("fixtures written to {}", out.display());
    Ok(())
}
