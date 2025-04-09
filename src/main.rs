use std::env;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::Path;
use std::process;

#[macro_use]
extern crate r2pipe;

mod crash_log_analyzer;
mod r2pipe_cache;
mod structs;

use crash_log_analyzer::CrashLogAnalyzer;

pub const OUTPUT_FOLDER: &str = "output";

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <ips_file_path>", args[0]);
        process::exit(1);
    }

    let ips_file: &String = &args[1];
    let path: &Path = Path::new(ips_file);
    if !path.exists() {
        println!("{} does not exist.", ips_file);

        return Ok(());
    }

    let ips_data: String = read_to_string(ips_file).unwrap();
    if ips_data.is_empty() {
        println!("Given file ({}) is empty", ips_file);
        return Ok(());
    }

    let mut analyzer: CrashLogAnalyzer = CrashLogAnalyzer::new(ips_data);

    let filename: &str = path.file_stem().unwrap().to_str().unwrap();
    let mut file: File = File::create(format!("{OUTPUT_FOLDER}/{filename}"))?;

    let general_info: String = analyzer.parse_general_info();
    let _ = file.write_all(general_info.as_bytes());
    let exception_info: String = analyzer.parse_exception_info();
    let _ = file.write_all(exception_info.as_bytes());
    let registers: String = analyzer.parse_registers();
    let _ = file.write_all(registers.as_bytes());
    let stacktrace: String = analyzer.analyze_faulting_thread();
    let _ = file.write_all(stacktrace.as_bytes()).unwrap();

    Ok(())
}
