use r2pipe::R2Pipe;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use super::constants::*;
use super::r2pipe_cache::R2PipeCache;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OSVersion {
    is_embedded: bool,
    pub train: String,
    release_type: String,
    pub build: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exception {
    pub codes: String,
    pub raw_codes: Vec<u64>,
    pub r#type: String,
    pub signal: String,
    pub subtype: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Termination {
    flags: i32,
    code: i64,
    namespace: String,
    pub indicator: Option<String>,
    by_proc: Option<String>,
    by_pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    id: u32,
    name: Option<String>,
    pub triggered: Option<bool>,
    pub frames: Vec<Frame>,
    pub thread_state: Option<ThreadState>,
    queue: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    pub image_offset: u64,
    pub symbol: Option<String>,
    pub symbol_location: Option<u32>,
    pub image_index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadState {
    pub flavor: String,
    pub lr: Register,
    pub cpsr: Register,
    pub fp: Register,
    pub sp: Register,
    pub esr: Esr,
    pub pc: Register,
    pub far: Register,
    pub x: Vec<Register>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Register {
    value: u64,
    symbol_location: Option<u64>,
    symbol: Option<String>,
    #[serde(alias = "objc-selector")]
    objc_selector: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Esr {
    value: u64,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsedImage {
    source: String,
    arch: Option<String>,
    base: u64,
    size: u64,
    uuid: String,
    path: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SharedCache {
    base: u64,
    size: u64,
    uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyInfo {
    thread_triggered: ThreadTriggered,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadTriggered {
    name: Option<String>,
    queue: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrialInfo {
    rollouts: Vec<Rollout>,
    //experiments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollout {
    rollout_id: String,
    factor_pack_ids: FactorPackIds,
    deployment_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FactorPackIds {
    siri_morphun_assets: Option<String>,
    #[serde(alias = "SIRI_HOME_AUTOMATION_INTENT_SELECTION_CACHE")]
    siri_home_automation_intent_selection_cache: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstructionByteStream {
    #[serde(alias = "beforePC")]
    before_pc: String,
    #[serde(alias = "atPC")]
    at_pc: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashInfo {
    /*uptime: u64,
    proc_launch: String,
    proc_role: String,
    version: u32,*/
    #[serde(alias = "userID")]
    pub user_id: u32,
    //deploy_version: u32,
    pub model_code: String,
    //proc_start_abs_time: u64,
    //#[serde(alias = "coalitionID")]
    //coalition_id: u32,
    pub os_version: OSVersion,
    /*capture_time: String,
    incident: String,
    #[serde(alias = "bug_type")]
    bug_type: String,
    pid: u32,
    proc_exit_abs_time: u64,*/
    pub cpu_type: String,
    pub proc_name: String,
    pub proc_path: String,
    pub parent_proc: String,
    pub parent_pid: u32,
    pub coalition_name: Option<String>,
    //crash_reporter_key: String,
    //baseband_version: String,
    //is_corpse: Option<u32>,
    pub exception: Exception,
    pub faulting_thread: u32,
    pub threads: Vec<Thread>,
    used_images: Vec<UsedImage>,
    //shared_cache: SharedCache,
    //vm_summary: String,
    //legacy_info: LegacyInfo,
    //trial_info: TrialInfo,
    pub termination: Termination,
    /*was_unlocked_since_boot: Option<u8>,
    log_writing_signature: Option<String>,
    ldm: Option<i64>,
    is_locked: Option<i64>,
    #[serde(alias = "codeSigningID")]
    code_signing_id: Option<String>,
    #[serde(alias = "codeSigningTeamID")]
    code_signing_team_id: Option<String>,
    code_signing_flags: Option<i64>,
    code_signing_validation_category: Option<i64>,
    code_signing_trust_level: Option<i64>,
    instruction_byte_stream: Option<InstructionByteStream>,
    asi: Option<HashMap<String, Vec<String>>>,*/
}

impl CrashInfo {
    fn _resolve_symbol_address(&self, r2: &mut R2Pipe, symbol_name: &String) -> Option<String> {
        if symbol_name.contains("[") {
            if let Some(matches) = OBJC_METHOD.captures(symbol_name) {
                let class_name = matches.get(1).unwrap().as_str();
                let selector_name = matches.get(2).unwrap().as_str();
                let block_invoke = matches.get(3);
                let block_invoke_num = matches.get(4).unwrap().as_str();
                let cold = matches.get(5);
                let cold_num = matches.get(6).unwrap().as_str();

                let mut search_command = String::from("is");
                search_command = format!("{}~{}", search_command, class_name);
                search_command = format!("{}~{}]", search_command, selector_name);
                search_command = match block_invoke {
                    Some(b) => format!("{}~{}", search_command, b.as_str()),
                    None => format!("{}~!block_invoke", search_command),
                };
                search_command = format!(
                    "{}~{}block_invoke",
                    search_command,
                    if block_invoke.is_some() { "" } else { "!" }
                );
                search_command = format!(
                    "{}~{}",
                    search_command,
                    if block_invoke_num.is_empty() {
                        block_invoke_num
                    } else {
                        ""
                    }
                );
                search_command = format!(
                    "{}~{}cold",
                    search_command,
                    if cold.is_some() { "" } else { "!" }
                );
                search_command = format!(
                    "{}~{}",
                    search_command,
                    if cold_num.is_empty() { cold_num } else { "" }
                );
                search_command = format!("{}[2]", search_command);

                if cold_num.is_empty() && block_invoke_num.is_empty() {
                    search_command = format!("{}:0", search_command);
                }

                //println!("{}", search_command);

                let symbol_address = r2.cmd(&search_command).unwrap();

                Some(symbol_address)
            } else {
                println!("No match found!");

                None
            }
        } else {
            let mut search_command = format!("is~{}", symbol_name);
            search_command = format!(
                "{}~{}block_invoke",
                search_command,
                if symbol_name.contains("block_invoke") {
                    ""
                } else {
                    "!"
                }
            );
            search_command = format!("{}[2]:0", search_command); // ~FUNC~GLOBAL

            println!("{}", search_command);

            let symbol_address = r2.cmd(&search_command).unwrap();

            Some(symbol_address)
        }
    }

    fn analyze_faulting_thread(&self) -> String {
        let mut r2_cache: R2PipeCache = R2PipeCache::new();
        let filtered_dylibs = HashSet::from(["UIKitCore", "libdispatch.dylib", "CoreFoundation"]);

        let mut res: String = String::from("STACK TRACE\n");
        res.push_str(format!("{:-<20}\n", "").as_str());

        self.threads.iter().for_each(|thread| {
            if thread.triggered.is_some() {
                thread
                    .frames
                    .iter()
                    .enumerate()
                    .rev()
                    .for_each(|(i, frame)| {
                        //println!("{}: {:?}", i, frame);
                        let image = self.used_images.get(frame.image_index as usize).unwrap();
                        let image_name = image.name.as_ref();
                        if image_name.is_none() {
                            println!("Image has no name");

                            res.push_str(
                                format!("{:<10} {:<25} 0x{:<25X}\n", i, "???", frame.image_offset)
                                    .as_str(),
                            );
                            res.push_str("\n");

                            return;
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

                        let image_path;
                        // Check if is main exe/main app
                        println!("IMAGE: {}", image_name.unwrap());
                        if image_name.unwrap() == &self.proc_name {
                            image_path =
                                format!("{APPS_FOLDER}/{}.app/{}", self.proc_name, self.proc_name);
                        } else if image.path.as_ref().unwrap().contains(&self.proc_name) {
                            image_path = format!(
                                "{APPS_FOLDER}/{}.app/Frameworks/{}.framework/{}",
                                self.proc_name,
                                image_name.unwrap(),
                                image_name.unwrap()
                            );
                        } else {
                            image_path = format!("{}/{}", OTA_FOLDER, image_name.unwrap());
                        }

                        if filtered_dylibs.contains(image_name.unwrap().as_str()) {
                            return;
                        }

                        if !Path::new(&image_path).exists() {
                            println!("{image_path} not found.");
                            return;
                        }

                        println!("SYMBOL: {}", symbol_name);

                        let r2 = r2_cache.get_or_create(image_path.as_str());
                        if symbol_name.contains(" + ") {
                            let image_base_no_aslr = r2.cmdj("iSSj").unwrap().get(0).unwrap()
                                ["vaddr"]
                                .as_u64()
                                .unwrap();
                            //println!("REAL BASE: {:#0x}", image_base_no_aslr);
                            let aslr_slide = image.base - image_base_no_aslr;
                            let to_address = (image.base - aslr_slide) + frame.image_offset;
                            let asm = r2
                                .cmd(
                                    format!("s {:#0x}; sf.; pdua {:#0x}", to_address, to_address)
                                        .as_str(),
                                )
                                .unwrap();
                            res.push_str(format!("{asm}").as_str());
                            res.push_str("\n");
                        } else {
                            let symbol_address = self._resolve_symbol_address(r2, symbol_name);
                            match symbol_address {
                                Some(address) => {
                                    //println!("{}", address.trim());

                                    if frame.symbol_location.is_some() {
                                        let mut bytes_count = frame.symbol_location.unwrap();
                                        if i == 0 {
                                            bytes_count += 4;
                                        }

                                        r2.cmd(format!("s {}", address).as_str()).unwrap();
                                        let asm =
                                            r2.cmd(format!("pD {}", bytes_count).as_str()).unwrap();
                                        res.push_str(format!("{asm}").as_str());
                                    }
                                }
                                None => {
                                    let image_base_no_aslr =
                                        r2.cmdj("iSSj").unwrap().get(0).unwrap()["vaddr"]
                                            .as_u64()
                                            .unwrap();

                                    let aslr_slide = image.base - image_base_no_aslr;
                                    let to_address = (image.base - aslr_slide) + frame.image_offset;
                                    let asm = r2
                                        .cmd(
                                            format!(
                                                "s {:#0x}; sf.; pdua {:#0x}",
                                                to_address, to_address
                                            )
                                            .as_str(),
                                        )
                                        .unwrap();
                                    res.push_str(format!("{asm}").as_str());
                                    res.push_str("\n");
                                }
                            }
                        }

                        res.push_str(format!("{:-<100}\n\n", "").as_str());
                    })
            }
        });

        res
    }

    fn print_registers(&self) -> String {
        let mut res: String = String::from("REGISTERS\n");
        res.push_str(format!("{:-<20}\n\n", "").as_str());

        if self.cpu_type == "X86-64" {
        } else {
            self.threads.iter().for_each(|thread| {
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

        res
    }
}

impl std::fmt::Display for CrashInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut res: std::fmt::Result;
        res = writeln!(f, "{}", self.print_registers());
        res = writeln!(f, "{}", self.analyze_faulting_thread());

        return res;
    }
}
