pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

pub fn is_health_method(path: &str) -> bool {
    path.ends_with("/Health/Check")
}
