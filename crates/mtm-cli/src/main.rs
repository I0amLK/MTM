#![forbid(unsafe_code)]

use std::env;

use mtm_contracts::ContractSnapshot;

fn main() {
    let command = env::args().nth(1);
    match command.as_deref() {
        Some("--version" | "-V") => {
            println!("mtm-reboot {}", env!("CARGO_PKG_VERSION"));
        }
        Some("contract") => {
            println!("{}", ContractSnapshot::source_baseline().to_json());
        }
        Some("status") => {
            const STATUS_JSON: &str = concat!(
                "{\"project\":\"MTM-reboot\",",
                "\"milestone\":\"MTM-002\",",
                "\"production_authority\":\"python\",",
                "\"rust_production_components\":0,",
                "\"completed_milestones\":1}"
            );
            println!("{STATUS_JSON}");
        }
        Some("help" | "--help" | "-h") | None => print_help(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    const HELP: &str = concat!(
        "MTM-reboot bootstrap\n\n",
        "Usage:\n",
        "  mtm-reboot --version\n",
        "  mtm-reboot contract\n",
        "  mtm-reboot status\n"
    );
    println!("{HELP}");
}
