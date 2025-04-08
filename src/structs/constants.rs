use lazy_static::lazy_static;
use regex::Regex;

pub const OTA_FOLDER: &str = "otas";
pub const APPS_FOLDER: &str = "apps";
pub const OUTPUT_FOLDER: &str = "assemblicated";

lazy_static! {
    pub static ref OBJC_METHOD: Regex = Regex::new(
        r#"[-|+]\[(.*) (.*)][\._]*(block_invoke)*[\._]*([0-9]*)[\._]*(cold)*[\._]*([0-9]*)"#
    )
    .unwrap();
}

// Radare2 Commands
