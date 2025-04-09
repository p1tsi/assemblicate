use serde::{Deserialize, Serialize};

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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Frame {
    pub image_offset: u64,
    pub symbol: Option<String>,
    pub symbol_location: Option<u32>,
    pub image_index: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Clone)]
pub struct Register {
    pub value: u64,
    symbol_location: Option<u64>,
    pub symbol: Option<String>,
    #[serde(alias = "objc-selector")]
    pub objc_selector: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Esr {
    pub value: u64,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsedImage {
    source: String,
    arch: Option<String>,
    pub base: u64,
    size: u64,
    uuid: String,
    pub path: Option<String>,
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
    pub used_images: Vec<UsedImage>,
    //shared_cache: SharedCache,
    //vm_summary: String,
    //legacy_info: LegacyInfo,
    //trial_info: TrialInfo,
    pub termination: Option<Termination>,
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
    pub last_exception_backtrace: Option<Vec<Frame>>,
}
