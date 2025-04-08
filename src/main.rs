use std::env;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::Path;
use std::process;

#[macro_use]
extern crate r2pipe;

mod structs;
use crate::structs::crash_log::CrashLog;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <ips_file_path>", args[0]);
        process::exit(1);
    }

    let ips_file: &String = &args[1];
    let path = Path::new(ips_file);
    if !path.exists() {
        println!("{} does not exist.", ips_file);

        return Ok(());
    }

    let ips_data: String = read_to_string(ips_file).unwrap();
    if ips_data.is_empty() {
        println!("Given file ({}) is empty", ips_file);
        return Ok(());
    }

    let crash_log = CrashLog::new(ips_data);

    let filename = path.file_stem().unwrap().to_str().unwrap();
    let mut file: File = File::create(format!("assemblicated/{filename}"))?;
    file.write_all(format!("{}", crash_log).as_bytes()).unwrap();

    Ok(())
}
