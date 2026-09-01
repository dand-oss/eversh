//! eversh: the multi-role supervisor library for eversh.
//!
//! M4 scope: typed errors, bounded remote-control requests (generic vector
//! and typed control request over unpadded base64url), session name rules,
//! pure role selection, the private everpty-role remote grammar, pure argv
//! construction for every supervised process, and thin process supervision
//! with probe-gated fresh-SSH reconnect. Library code never prints, reads
//! global arguments, or exits; the supervisor never owns a PTY fd, QUIC
//! endpoint, or terminal relay loop, and never constructs a runtime.

pub mod command;
pub mod error;
pub mod limits;
pub mod remote;
pub mod role;
pub mod supervisor;

pub use error::Error;
pub use limits::Limits;
