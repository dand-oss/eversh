//! Named finite limits for the supervisor layer.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    // --- contract (wire) values ---
    /// Maximum encoded remote-control request bytes before decoding.
    pub remote_control_max: usize,
    /// Maximum argument count in a remote-control request.
    pub arg_count_max: usize,
    /// Maximum session name length in bytes (mirrors everpty).
    pub name_max: usize,
    /// Maximum Unix socket pathname bytes (107) plus NUL.
    pub unix_path_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            remote_control_max: 64 * 1024,
            arg_count_max: 64,
            name_max: 64,
            unix_path_max: 107, // + NUL = sun_path[108]
        }
    }
}
