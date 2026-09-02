//! Named finite limits for the supervisor layer. Wire caps are contract
//! values; supervisor runtime values are configuration with measured
//! selection recorded in the release profile (design section 4).

use crate::error::Error;

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
    /// Maximum origin entries in a control request (mirrors everpty).
    pub origin_count_max: usize,
    /// Per-origin label cap in bytes (mirrors everpty).
    pub origin_label_max: usize,

    // --- supervisor runtime values ---
    /// Maximum reconnect attempts after an established session ends
    /// unexpectedly for an ordinary in-episode failure (design 7: finite
    /// attempts). A Busy reattach does not consume this budget — the
    /// episode deadline alone bounds the Busy-retry path, because the
    /// remote writer slot can stay legitimately held far longer than a
    /// small attempt budget could span.
    pub retry_attempts_max: u32,
    /// First backoff delay in milliseconds.
    pub retry_backoff_base_ms: u64,
    /// Backoff ceiling in milliseconds (bounded exponential).
    pub retry_backoff_cap_ms: u64,
    /// Overall reconnect deadline in milliseconds.
    pub retry_deadline_ms: u64,
    /// Invocation-wide cap on reconnect-episode restarts: a reattach that
    /// genuinely carried the session before dying again starts a fresh
    /// episode, but never more than this many times — past the cap the
    /// invocation ends as a visible ordinary failure instead of looping
    /// forever on a flapping topology.
    pub episode_restarts_max: u32,
    /// Cap on captured remote list output bytes.
    pub list_output_max: usize,
    /// Maximum sessions resume-all will launch in one invocation.
    pub resume_sessions_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            remote_control_max: 64 * 1024,
            arg_count_max: 64,
            name_max: 64,
            unix_path_max: 107, // + NUL = sun_path[108]
            origin_count_max: 4,
            origin_label_max: 64,
            retry_attempts_max: 5,
            retry_backoff_base_ms: 250,
            retry_backoff_cap_ms: 5_000,
            retry_deadline_ms: 60_000,
            episode_restarts_max: 3,
            list_output_max: 1024 * 1024,
            resume_sessions_max: 64,
        }
    }
}

impl Limits {
    /// Reject configurations that would unbound or wedge the supervisor.
    pub fn validate(&self) -> Result<(), Error> {
        if self.remote_control_max < 8
            || self.arg_count_max == 0
            || self.name_max == 0
            || self.unix_path_max == 0
            || self.origin_count_max == 0
            || self.origin_label_max == 0
            || self.retry_attempts_max == 0
            || self.retry_backoff_base_ms == 0
            || self.retry_backoff_cap_ms < self.retry_backoff_base_ms
            || self.retry_deadline_ms == 0
            || self.episode_restarts_max == 0
            || self.list_output_max == 0
            || self.resume_sessions_max == 0
        {
            return Err(Error::LimitsInvalid);
        }
        Ok(())
    }
}
