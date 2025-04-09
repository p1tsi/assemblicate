use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentReport {
    pub name: String,
    pub app_name: String,
    pub timestamp: String,
    pub app_version: String,
    slice_uuid: String,
    pub build_version: String,
    pub platform: i32,
    share_with_app_devs: u8,
    pub is_first_party: u8,
    bug_type: String,
    pub os_version: String,
    incident_id: String,
    roots_installed: Option<u8>,
    sroute_id: Option<i32>,
    #[serde(alias = "bundleID")]
    bundle_id: Option<String>,
}

impl std::fmt::Display for IncidentReport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut res: std::fmt::Result = writeln!(f, "GENERAL INFO");
        res = writeln!(f, "{:-<20}", "");
        res = writeln!(f, "{:<15} {:<15}", "Name:", self.name);
        res = writeln!(f, "{:<15} {:<15}", "App Name:", self.app_name);
        res = writeln!(f, "{:<15} {:<15}", "Version:", self.app_version);
        res = writeln!(f, "{:<15} {:<15}", "OS Version:", self.os_version);
        res = writeln!(f, "{:<15} {:<15}", "Timestamp:", self.timestamp);

        res
    }
}
