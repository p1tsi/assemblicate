use serde::{Deserialize, Serialize};

use crate::structs::crash_info::CrashInfo;
use crate::structs::incident_report::IncidentReport;

#[derive(Debug, Serialize, Deserialize)]
pub struct CrashLog {
    general_info: IncidentReport,
    crash_info: CrashInfo,
}

impl CrashLog {
    pub fn new(ips_data: String) -> CrashLog {
        let (gen_info, crash_details): (&str, &str) = ips_data.split_once("}").unwrap();

        CrashLog {
            general_info: serde_json::from_str(format!("{}}}", gen_info).as_str())
                .expect("Failed to parse general info"),
            crash_info: serde_json::from_str(crash_details).expect("Failed to parse crash details"),
        }
    }
}

impl std::fmt::Display for CrashLog {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut res: std::fmt::Result = writeln!(f, "GENERAL INFO");
        res = writeln!(f, "{:-<20}", "");
        res = writeln!(f, "{:<15} {:<15}", "Name:", self.general_info.name);
        res = writeln!(f, "{:<15} {:<15}", "App Name:", self.general_info.app_name);
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "Bundle ID:",
            self.crash_info
                .coalition_name
                .as_ref()
                .unwrap_or(&String::default())
        );
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "Version:", self.general_info.app_version
        );
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "OS version:", self.crash_info.os_version.train
        );
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "OS build:", self.crash_info.os_version.build
        );
        res = writeln!(f, "{:<15} {:<15}", "OS model:", self.crash_info.model_code);
        res = writeln!(f, "{:<15} {:<15}", "CPU:", self.crash_info.cpu_type);
        res = writeln!(f, "{:<15} {:<15}", "User ID:", self.crash_info.user_id);
        res = writeln!(f, "{:<15} {:<15}", "Proc Path:", self.crash_info.proc_path);
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "Parent Proc:", self.crash_info.parent_proc
        );
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "Parent PID:", self.crash_info.parent_pid
        );
        //res = writeln!(f, "{}", format!("{:<15} {:<15}", "OS Version:", self.general_info.os_version));
        res = writeln!(
            f,
            "{:<15} {:<15}",
            "Timestamp:", self.general_info.timestamp
        );
        res = writeln!(f);

        res = writeln!(f, "EXCEPTION INFO");
        res = writeln!(f, "{:-<20}", "");
        res = writeln!(
            f,
            "{:<20} {:<20}",
            "Exception type:", self.crash_info.exception.r#type,
        );
        res = writeln!(
            f,
            "{:<20?} {:<20?}",
            "Exception subtype:",
            self.crash_info
                .exception
                .subtype
                .as_ref()
                .unwrap_or(&String::from("None"))
        );
        res = writeln!(
            f,
            "{:<20} {:<20}",
            "Exception signal:", self.crash_info.exception.signal
        );
        res = writeln!(
            f,
            "{:<20} {:<20}",
            "Exception codes:", self.crash_info.exception.codes
        );
        res = writeln!(
            f,
            "{:<20?} {:<20?}",
            "Termination:",
            self.crash_info
                .termination
                .indicator
                .as_ref()
                .unwrap_or(&String::from("None"))
        );
        res = writeln!(f);

        let mut res: std::fmt::Result = writeln!(f, "REGISTERS");
        res = writeln!(f, "{:-<20}", "");

        // PRINT REGISTERS VALUES

        res = writeln!(f, "{}", self.crash_info);

        res
    }
}
