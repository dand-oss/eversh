//! Compile-time trait assertions.
#![allow(clippy::unwrap_used)]

#[test]
fn error_is_static_send_sync() {
    fn assert_traits<T: std::error::Error + Send + Sync + 'static>() {}
    assert_traits::<eversh::Error>();
}
