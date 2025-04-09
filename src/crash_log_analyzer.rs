use lazy_static::lazy_static;
use r2pipe::R2Pipe;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

use crate::r2pipe_cache::R2PipeCache;
use crate::structs::crash_info::*;
use crate::structs::incident_report::IncidentReport;

lazy_static! {
    pub static ref OBJC_METHOD: Regex = Regex::new(
        r#"[-|+]\[(.*) (.*)][\._]*(block_invoke[\._]*[0-9]*)*[\._]*(cold[\._]*[0-9]*)*"#
    )
    .unwrap();
}

pub const OTA_FOLDER: &str = "dylibs";
pub const APPS_FOLDER: &str = "apps";

fn resolve_symbol_address(r2: &mut R2Pipe, symbol_name: &String) -> Option<String> {
    if symbol_name.contains("[") {
        if let Some(matches) = OBJC_METHOD.captures(symbol_name) {
            let class_name: &str = matches.get(1).unwrap().as_str();
            let selector_name: &str = matches.get(2).unwrap().as_str();
            let block_invoke: Option<regex::Match<'_>>  = matches.get(3);
            let cold: Option<regex::Match<'_>> = matches.get(4);

            let mut search_command: String = String::from("is");
            search_command.push_str(format!(" ~{}", class_name).as_str());
            search_command.push_str(format!("~{}]", selector_name).as_str());
            
            match block_invoke {
                Some(b) => search_command.push_str(format!("~{}", b.as_str()).as_str()),
                None => search_command.push_str(format!("~!block_invoke").as_str())
            }

            match cold {
                Some(c) => search_command.push_str(format!("~{}", c.as_str()).as_str()),
                None => search_command.push_str(format!("~!cold").as_str())
            }
            
            search_command = format!("{}[2]", search_command);

            /*if cold_num.is_empty() && block_invoke_num.is_empty() {
                search_command = format!("{}:0", search_command);
            }*/

            //println!("{}", search_command);

            let symbol_address = r2.cmd(&search_command).unwrap();

            Some(symbol_address)
        } else {
            println!("No match found!");

            None
        }
    } else {
        let mut search_command: String = format!("is ~{}", symbol_name);
        search_command.push_str(format!(
            "~{}block_invoke",
            if symbol_name.contains("block_invoke") {
                ""
            } else {
                "!"
            }
        ).as_str());
        search_command.push_str("[2]:0"); // ~FUNC~GLOBAL

        //println!("{}", search_command);

        let symbol_address: String = r2.cmd(&search_command).unwrap();

        Some(symbol_address)
    }
}

pub struct CrashLogAnalyzer<'a> {
    pub general_info: IncidentReport,
    pub crash_info: CrashInfo,
    pub r2_cache: R2PipeCache,
    pub filtered_dylibs: HashSet<&'a str>,
}

impl<'a> CrashLogAnalyzer<'a> {
    pub fn new(ips_data: String) -> CrashLogAnalyzer<'a> {
        let (gen_info, crash_details): (&str, &str) = ips_data.split_once("}").unwrap();

        CrashLogAnalyzer {
            general_info: serde_json::from_str(format!("{}}}", gen_info).as_str())
                .expect("Failed to parse general info"),
            crash_info: serde_json::from_str(crash_details).expect("Failed to parse crash details"),
            r2_cache: R2PipeCache::new(),
            filtered_dylibs: HashSet::from(["UIKitCore", "libdispatch.dylib", "CoreFoundation", "CFNetwork"]),
        }
    }

    pub fn parse_general_info(&self) -> String {
        let mut res: String = String::from("GENERAL INFO\n\n");

        res.push_str(format!("{:<15} {:<15}\n", "Name:", self.general_info.name).as_str());
        res.push_str(format!("{:<15} {:<15}\n", "App Name:", self.general_info.app_name).as_str());
        res.push_str(format!(
            "{:<15} {:<15}\n",
            "Bundle ID:",
            self.crash_info
                .coalition_name
                .as_ref()
                .unwrap_or(&String::default())
        ).as_str());
        res.push_str(
            format!("{:<15} {:<15}\n", "Version:", self.general_info.app_version).as_str(),
        );
        res.push_str(
            format!(
                "{:<15} {:<15}\n",
                "OS Version:", self.general_info.os_version
            )
            .as_str(),
        );
        res.push_str(
            format!("{:<15} {:<15}\n", "Timestamp:", self.general_info.timestamp).as_str(),
        );
        res.push_str(format!(
            "{:<15} {:<15}\n",
            "OS build:", self.crash_info.os_version.build
        ).as_str());
        res.push_str(format!("{:<15} {:<15}\n", "OS model:", self.crash_info.model_code).as_str());
        res.push_str(format!("{:<15} {:<15}\n", "CPU:", self.crash_info.cpu_type).as_str());
        res.push_str(format!("{:<15} {:<15}\n", "User ID:", self.crash_info.user_id).as_str());
        res.push_str(format!("{:<15} {:<15}\n", "Proc Path:", self.crash_info.proc_path).as_str());
        res.push_str(format!(
            "{:<15} {:<15}\n",
            "Parent Proc:", self.crash_info.parent_proc
        ).as_str());
        res.push_str(format!(
            "{:<15} {:<15}\n",
            "Parent PID:", self.crash_info.parent_pid
        ).as_str());

        res.push_str(format!("{:-<20}\n\n", "").as_str());

        res
    }

    pub fn parse_exception_info(&self) -> String {
        let mut res: String = String::from("EXCEPTION INFO\n\n");

        res.push_str(
            format!(
                "{:<20} {:<20}\n",
                "Exception type:", self.crash_info.exception.r#type,
            )
            .as_str(),
        );
        res.push_str(
            format!(
                "{:<20} {:<20}\n",
                "Exception subtype:",
                self.crash_info
                    .exception
                    .subtype
                    .as_ref()
                    .unwrap_or(&String::from("None"))
            )
            .as_str(),
        );
        res.push_str(
            format!(
                "{:<20} {:<20}\n",
                "Exception signal:", self.crash_info.exception.signal
            )
            .as_str(),
        );
        res.push_str(
            format!(
                "{:<20} {:<20}\n",
                "Exception codes:", self.crash_info.exception.codes
            )
            .as_str(),
        );
        if self.crash_info.termination.is_some() {
            res.push_str(
                format!(
                    "{:<20} {:<20}\n",
                    "Termination:",
                    self.crash_info
                        .termination
                        .as_ref()
                        .unwrap()
                        .indicator
                        .as_ref()
                        .unwrap_or(&String::from("None"))
                )
                .as_str(),
            );
        }

        res.push_str(format!("{:-<20}\n\n", "").as_str());

        res
    }

    fn get_frame_info(&mut self, i: usize, frame: &Frame) -> String {
        let mut res: String = String::new();

        let image: &UsedImage = self
            .crash_info
            .used_images
            .get(frame.image_index as usize)
            .unwrap();
        let image_name: Option<&String> = image.name.as_ref();
        if image_name.is_none() {
            println!("Image has no name");

            res.push_str(
                format!("{:<10} {:<25} 0x{:<25X}\n", i, "???", frame.image_offset).as_str(),
            );
            res.push_str("\n");

            return res;
        }

        let symbol_name = match frame.symbol.as_ref() {
            Some(name) => name,
            None => &format!("{:#0x} + {:#0x}", image.base, frame.image_offset),
        };
        res.push_str(
            format!(
                "{:<10} {:<25} {:<25}\n",
                i,
                image.name.as_ref().unwrap(),
                symbol_name
            )
            .as_str(),
        );
        res.push_str("\n");

        let image_path: String;
        // Check if is main exe/main app
        println!("IMAGE: {}", image_name.unwrap());
        if image_name.unwrap() == &self.crash_info.proc_name {
            if self.general_info.is_first_party == 1 {
                image_path = format!(
                    "{APPS_FOLDER}/{}",
                    self.crash_info.proc_name
                );
            }
            else{
                image_path = format!(
                    "{APPS_FOLDER}/{}.app/{}",
                    self.crash_info.proc_name, self.crash_info.proc_name
                );
            }
        } else if image.path
            .as_ref()
            .unwrap()
            .contains(&self.crash_info.proc_name){
            image_path = format!(
                "{APPS_FOLDER}/{}.app/Frameworks/{}.framework/{}",
                self.crash_info.proc_name,
                image_name.unwrap(),
                image_name.unwrap()
            );
        }        
        else {
            image_path = format!("{}/{}", OTA_FOLDER, image_name.unwrap());
        }

        if self.filtered_dylibs.contains(image_name.unwrap().as_str()) {
            return res;
        }

        if !Path::new(&image_path).exists() {
            println!("{image_path} not found.");
            return res;
        }

        println!("SYMBOL: {}", symbol_name);

        let r2: &mut R2Pipe = self.r2_cache.get_or_create(image_path.as_str());
        if symbol_name.contains(" + ") {
            let image_base_no_aslr = r2.cmdj("iSSj").unwrap().get(0).unwrap()["vaddr"]
                .as_u64()
                .unwrap();
            //println!("REAL BASE: {:#0x}", image_base_no_aslr);
            let aslr_slide: u64 = image.base - image_base_no_aslr;
            let to_address: u64 = (image.base - aslr_slide) + frame.image_offset;
            let asm = r2
                .cmd(format!("s {:#0x}; sf.; pdua {:#0x}", to_address, to_address).as_str())
                .unwrap();
            res.push_str(format!("{asm}").as_str());
            res.push_str("\n");
        } else {
            let symbol_address = resolve_symbol_address(r2, symbol_name);
            match symbol_address {
                Some(address) => {
                    //println!("{}", address.trim());

                    if frame.symbol_location.is_some() {
                        let mut bytes_count = frame.symbol_location.unwrap();
                        if i == 0 {
                            bytes_count += 4;
                        }

                        r2.cmd(format!("s {}", address).as_str()).unwrap();
                        let asm = r2.cmd(format!("pD {}", bytes_count).as_str()).unwrap();
                        res.push_str(format!("{asm}").as_str());
                    }
                }
                None => {
                    let image_base_no_aslr = r2.cmdj("iSSj").unwrap().get(0).unwrap()["vaddr"]
                        .as_u64()
                        .unwrap();

                    let aslr_slide = image.base - image_base_no_aslr;
                    let to_address = (image.base - aslr_slide) + frame.image_offset;
                    let asm = r2
                        .cmd(format!("s {:#0x}; sf.; pdua {:#0x}", to_address, to_address).as_str())
                        .unwrap();
                    res.push_str(format!("{asm}").as_str());
                    res.push_str("\n");
                }
            }
        }

        //res.push_str(format!("{:>70}\n", "-".repeat(60)).as_str());
        res.push_str("\n");

        res
    }

    pub fn analyze_faulting_thread(&mut self) -> String {
        let mut res: String = String::from("STACK TRACE\n\n");

        if self.crash_info.last_exception_backtrace.is_some() {
            let backtrace: Option<Vec<Frame>> = self.crash_info.last_exception_backtrace.clone();

            backtrace
                .as_ref()
                .unwrap()
                .iter()
                .enumerate()
                .rev()
                .for_each(|(i, frame)| {
                    res.push_str(self.get_frame_info(i, frame).as_str());
                });
        } else {
            let threads = self.crash_info.threads.clone();
            threads.iter().for_each(|thread| {
                if thread.triggered.is_some() {
                    thread
                        .frames
                        .iter()
                        .enumerate()
                        .rev()
                        .for_each(|(i, frame)| {
                            res.push_str(self.get_frame_info(i, frame).as_str());
                        });
                }
            });
        }

        res
    }

    pub fn parse_registers(&self) -> String {
        let mut res: String = String::from("REGISTERS\n\n");

        if self.crash_info.cpu_type == "X86-64" {
        } else {
            self.crash_info.threads.iter().for_each(|thread| {
                if thread.triggered.is_some() {
                    thread
                        .thread_state
                        .as_ref()
                        .unwrap()
                        .x
                        .iter()
                        .enumerate()
                        .for_each(|(i, r)| {
                            res.push_str(format!("x{i}: {:#x}", r.value).as_str());
                            if r.objc_selector.is_some() {
                                res.push_str(
                                    format!("{:>50}\n", r.objc_selector.as_ref().unwrap()).as_str(),
                                );
                            } else if r.symbol.is_some() {
                                res.push_str(
                                    format!("{:>50}\n", r.symbol.as_ref().unwrap()).as_str(),
                                );
                            } else {
                                res.push_str("\n");
                            }
                        });

                    res.push_str(
                        format!(
                            "pc: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().pc.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "sp: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().sp.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "fp: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().fp.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "esr: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().esr.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "lr: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().lr.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "cpsr: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().cpsr.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!(
                            "far: {:#x}\n",
                            thread.thread_state.as_ref().unwrap().far.value
                        )
                        .as_str(),
                    );
                    res.push_str(
                        format!("flavor: {}\n", thread.thread_state.as_ref().unwrap().flavor)
                            .as_str(),
                    );
                }
            });
        }

        res.push_str(format!("{:-<20}\n\n", "").as_str());

        res
    }
}
