use r2pipe::R2Pipe;
use std::collections::HashMap;
use std::path::Path;

// Struct that maintains a cache of R2Pipe instances associated with binary file names
pub struct R2PipeCache {
    map: HashMap<String, R2Pipe>,
}

impl R2PipeCache {
    // Creates a new, empty cache instance
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    // Returns a mutable reference to the R2Pipe instance for a given binary path.
    // If it doesn't exist in the cache, it's created and initialized.
    pub fn get_or_create(&mut self, image_path: &str) -> &mut R2Pipe {
        // Extract binary name from full path
        let binary_name: String = Path::new(image_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Open R2Pipe only if it's not already in the cache
        self.map.entry(binary_name).or_insert_with(|| {
            let mut r2: R2Pipe = open_pipe!(Some(image_path)).expect("Failed to open r2pipe");
            r2.cmd("aaa").unwrap();

            r2
        })
    }
}
