//! Small, opt-in process resource snapshots for floor attribution.
//!
//! This module deliberately has no output or tracing policy.  A caller takes
//! one snapshot around a diagnostic window and may compute a checked delta.
//! `ru_maxrss` is retained as a lifetime high-water mark: it is reported by
//! the delta object as the ending high-water mark, never as live memory or a
//! subtraction of two samples.

use std::io;
use std::time::Instant;

/// Number of paired reads collected by [`calibrate_thread_clock`].
pub const CPU_CLOCK_CALIBRATION_SAMPLES: usize = 64;

/// A bounded correspondence between Rust's monotonic [`Instant`] and the
/// Linux `CLOCK_MONOTONIC` nanosecond domain.
///
/// The instant is sampled between the two clock reads, so callers must treat
/// `lower_ns..=upper_ns` as an uncertainty interval.  This is intentionally a
/// startup/export diagnostic primitive; it is not used on a per-event path.
/// Rust documents UNIX `Instant::now` as using `CLOCK_MONOTONIC`:
/// <https://doc.rust-lang.org/std/time/struct.Instant.html#underlying-system-calls>.
/// The export-side second bracket checks that this mapping remains consistent;
/// no assumption about the opaque `Instant` memory layout is made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockAnchor {
    pub instant: Instant,
    pub lower_ns: u64,
    pub upper_ns: u64,
}

/// Host and time-namespace identity for comparing diagnostic clock anchors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockIdentity {
    pub boot_id: String,
    pub time_namespace_dev: u64,
    pub time_namespace_ino: u64,
}

/// Sample an [`Instant`] bracketed by two `CLOCK_MONOTONIC` reads.
pub fn clock_anchor() -> io::Result<ClockAnchor> {
    #[cfg(target_os = "linux")]
    {
        let lower_ns = monotonic_clock_ns()?;
        let instant = Instant::now();
        let upper_ns = monotonic_clock_ns()?;
        clock_anchor_from_bounds(instant, lower_ns, upper_ns)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "monotonic clock anchors require Linux",
        ))
    }
}

/// Return the identity needed to decide whether two diagnostic anchors are
/// comparable.  No subprocesses or external commands are used.
pub fn clock_identity() -> io::Result<ClockIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot_id = boot_id.trim();
        if !valid_boot_id(boot_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Linux boot ID",
            ));
        }
        let time_namespace = std::fs::metadata("/proc/self/ns/time")?;
        Ok(ClockIdentity {
            boot_id: boot_id.to_owned(),
            time_namespace_dev: time_namespace.dev(),
            time_namespace_ino: time_namespace.ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "clock identity requires Linux",
        ))
    }
}

/// Calling-thread CPU consumption, not process CPU or wall time.
pub fn thread_cpu_ns() -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut raw = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the writable timespec on success.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, raw.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful call above initialized both fields.
        let raw = unsafe { raw.assume_init() };
        thread_timespec_ns(raw.tv_sec, raw.tv_nsec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "thread CPU clock requires Linux",
        ))
    }
}

/// Collect a startup reference distribution for the calling-thread CPU clock.
///
/// Each sample is the checked delta between two back-to-back clock reads. The
/// returned values describe clock-read cost and are not a correction to apply
/// to individual recorder samples. This intentionally performs no allocation.
pub fn calibrate_thread_clock() -> io::Result<[u64; CPU_CLOCK_CALIBRATION_SAMPLES]> {
    calibrate_thread_clock_with(thread_cpu_ns)
}

fn calibrate_thread_clock_with<F>(mut read: F) -> io::Result<[u64; CPU_CLOCK_CALIBRATION_SAMPLES]>
where
    F: FnMut() -> io::Result<u64>,
{
    let mut samples = [0_u64; CPU_CLOCK_CALIBRATION_SAMPLES];
    for sample in &mut samples {
        let before = read()?;
        let after = read()?;
        *sample = after.checked_sub(before).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "thread CPU clock regressed")
        })?;
    }
    Ok(samples)
}

#[cfg(target_os = "linux")]
fn thread_timespec_ns(seconds: libc::time_t, nanos: libc::c_long) -> io::Result<u64> {
    checked_timespec_ns(seconds, nanos, "thread CPU")
}

#[cfg(target_os = "linux")]
fn checked_timespec_ns(seconds: libc::time_t, nanos: libc::c_long, label: &str) -> io::Result<u64> {
    let seconds = u64::try_from(seconds);
    let nanos = u64::try_from(nanos);
    match (seconds, nanos) {
        (Ok(seconds), Ok(nanos)) if nanos < 1_000_000_000 => seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanos))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{label} overflow"))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {label} timespec"),
        )),
    }
}

#[cfg(target_os = "linux")]
fn monotonic_clock_ns() -> io::Result<u64> {
    let mut raw = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes the writable timespec on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, raw.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call above initialized both fields.
    let raw = unsafe { raw.assume_init() };
    checked_timespec_ns(raw.tv_sec, raw.tv_nsec, "monotonic clock")
}

fn clock_anchor_from_bounds(
    instant: Instant,
    lower_ns: u64,
    upper_ns: u64,
) -> io::Result<ClockAnchor> {
    if upper_ns < lower_ns {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "monotonic clock regressed while sampling anchor",
        ));
    }
    Ok(ClockAnchor {
        instant,
        lower_ns,
        upper_ns,
    })
}

#[cfg(target_os = "linux")]
fn valid_boot_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, &byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Cumulative process counters and the process lifetime RSS high-water mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    /// User CPU consumed by this process, in nanoseconds.
    pub user_cpu_ns: u64,
    /// System CPU consumed by this process, in nanoseconds.
    pub system_cpu_ns: u64,
    /// Voluntary context switches, cumulative since process start.
    pub voluntary_context_switches: u64,
    /// Involuntary context switches, cumulative since process start.
    pub involuntary_context_switches: u64,
    /// Linux `ru_maxrss`, in KiB.  This is a lifetime high-water mark.
    pub max_rss_kib: u64,
}

/// Checked change in cumulative counters over a diagnostic window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceDelta {
    pub user_cpu_ns: u64,
    pub system_cpu_ns: u64,
    pub voluntary_context_switches: u64,
    pub involuntary_context_switches: u64,
    /// Ending lifetime high-water mark, not a subtraction and not live RSS.
    pub max_rss_kib: u64,
}

impl ResourceSnapshot {
    /// Capture this process's resource counters.
    pub fn capture() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut raw = std::mem::MaybeUninit::<libc::rusage>::zeroed();
            // SAFETY: libc initializes every field of the writable rusage
            // structure when getrusage succeeds.
            let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, raw.as_mut_ptr()) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: success above means libc initialized `raw`.
            Self::from_raw(unsafe { raw.assume_init_ref() })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process resource snapshots are only implemented on Linux",
            ))
        }
    }

    /// Compute a checked delta from `before` to this sample.
    ///
    /// All four cumulative counters must be monotonic.  A regression is an
    /// invalid sample rather than a silently wrapped or clamped value.
    pub fn delta_since(self, before: Self) -> io::Result<ResourceDelta> {
        Ok(ResourceDelta {
            user_cpu_ns: checked_delta(self.user_cpu_ns, before.user_cpu_ns, "user CPU")?,
            system_cpu_ns: checked_delta(self.system_cpu_ns, before.system_cpu_ns, "system CPU")?,
            voluntary_context_switches: checked_delta(
                self.voluntary_context_switches,
                before.voluntary_context_switches,
                "voluntary context switches",
            )?,
            involuntary_context_switches: checked_delta(
                self.involuntary_context_switches,
                before.involuntary_context_switches,
                "involuntary context switches",
            )?,
            // ru_maxrss is a high-water mark.  Do not report a fake "RSS
            // delta" that could be mistaken for current resident memory.
            max_rss_kib: self.max_rss_kib,
        })
    }

    #[cfg(target_os = "linux")]
    fn from_raw(raw: &libc::rusage) -> io::Result<Self> {
        Ok(Self {
            user_cpu_ns: timeval_to_ns(raw.ru_utime.tv_sec, raw.ru_utime.tv_usec, "user CPU")?,
            system_cpu_ns: timeval_to_ns(raw.ru_stime.tv_sec, raw.ru_stime.tv_usec, "system CPU")?,
            voluntary_context_switches: nonnegative(raw.ru_nvcsw, "voluntary context switches")?,
            involuntary_context_switches: nonnegative(
                raw.ru_nivcsw,
                "involuntary context switches",
            )?,
            max_rss_kib: nonnegative(raw.ru_maxrss, "maximum RSS")?,
        })
    }
}

fn checked_delta(current: u64, before: u64, label: &str) -> io::Result<u64> {
    current.checked_sub(before).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} counter regressed"),
        )
    })
}

fn nonnegative(value: std::os::raw::c_long, label: &str) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} counter was negative"),
        )
    })
}

fn timeval_to_ns(
    seconds: std::os::raw::c_long,
    micros: std::os::raw::c_long,
    label: &str,
) -> io::Result<u64> {
    let seconds = u64::try_from(seconds).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} seconds was negative"),
        )
    })?;
    let micros = u64::try_from(micros).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} microseconds was negative"),
        )
    })?;
    if micros >= 1_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} microseconds out of range"),
        ));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(micros * 1_000))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{label} overflow")))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        calibrate_thread_clock_with, checked_delta, clock_anchor_from_bounds, timeval_to_ns,
        ResourceSnapshot, CPU_CLOCK_CALIBRATION_SAMPLES,
    };

    #[test]
    fn clock_calibration_reads_exactly_two_values_per_sample() {
        let reads = Cell::new(0_usize);
        let samples = calibrate_thread_clock_with(|| {
            let read = reads.get();
            reads.set(read + 1);
            Ok((read / 2) as u64 + (read % 2) as u64)
        })
        .unwrap();
        assert_eq!(reads.get(), CPU_CLOCK_CALIBRATION_SAMPLES * 2);
        assert!(samples.iter().all(|&sample| sample == 1));
    }

    #[test]
    fn clock_calibration_preserves_known_deltas() {
        let mut reads = 0_u64;
        let samples = calibrate_thread_clock_with(|| {
            let value = (reads / 2) * 10 + (reads % 2) * 3;
            reads += 1;
            Ok(value)
        })
        .unwrap();
        assert!(samples.iter().all(|&sample| sample == 3));
    }

    #[test]
    fn clock_calibration_propagates_read_failure() {
        let mut reads = 0_usize;
        let error = calibrate_thread_clock_with(|| {
            reads += 1;
            if reads == 5 {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "sentinel"))
            } else {
                Ok(reads as u64)
            }
        })
        .unwrap_err();
        assert_eq!(reads, 5);
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn clock_calibration_rejects_regression() {
        let mut reads = [10_u64, 9_u64].into_iter();
        let error = calibrate_thread_clock_with(|| Ok(reads.next().unwrap())).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thread_clock_is_checked_and_monotonic() {
        assert_eq!(super::thread_timespec_ns(2, 3).unwrap(), 2_000_000_003);
        assert!(super::thread_timespec_ns(-1, 0).is_err());
        assert!(super::thread_timespec_ns(0, -1).is_err());
        assert!(super::thread_timespec_ns(0, 1_000_000_000).is_err());
        assert!(super::thread_timespec_ns(i64::MAX, 0).is_err());
        let start = super::thread_cpu_ns().unwrap();
        assert!(super::thread_cpu_ns().unwrap() >= start);
        let samples = super::calibrate_thread_clock().unwrap();
        assert_eq!(samples.len(), CPU_CLOCK_CALIBRATION_SAMPLES);
    }

    #[test]
    fn clock_anchor_rejects_regressed_bounds() {
        let error = clock_anchor_from_bounds(std::time::Instant::now(), 11, 10).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn clock_anchor_accepts_equal_bounds() {
        let anchor = clock_anchor_from_bounds(std::time::Instant::now(), 42, 42).unwrap();
        assert_eq!((anchor.lower_ns, anchor.upper_ns), (42, 42));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_clock_anchor_and_identity_are_valid() {
        let anchor = super::clock_anchor().expect("CLOCK_MONOTONIC anchor");
        assert!(anchor.lower_ns <= anchor.upper_ns);
        let identity = super::clock_identity().expect("Linux clock identity");
        assert!(super::valid_boot_id(&identity.boot_id));
        assert_ne!(identity.time_namespace_dev, 0);
        assert_ne!(identity.time_namespace_ino, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boot_id_validation_rejects_bad_shapes() {
        assert!(!super::valid_boot_id(""));
        assert!(!super::valid_boot_id(
            "00000000-0000-0000-0000-00000000000z"
        ));
        assert!(!super::valid_boot_id("00000000000000000000000000000000"));
        assert!(super::valid_boot_id("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn timeval_conversion_is_checked() {
        assert_eq!(timeval_to_ns(2, 345_678, "cpu").unwrap(), 2_345_678_000);
        assert!(timeval_to_ns(-1, 0, "cpu").is_err());
        assert!(timeval_to_ns(0, 1_000_000, "cpu").is_err());
        assert!(timeval_to_ns(i64::MAX, 0, "cpu").is_err());
    }

    #[test]
    fn cumulative_delta_rejects_regression_and_keeps_highwater() {
        let before = ResourceSnapshot {
            user_cpu_ns: 10,
            system_cpu_ns: 20,
            voluntary_context_switches: 30,
            involuntary_context_switches: 40,
            max_rss_kib: 100,
        };
        let after = ResourceSnapshot {
            user_cpu_ns: 13,
            system_cpu_ns: 25,
            voluntary_context_switches: 31,
            involuntary_context_switches: 45,
            max_rss_kib: 101,
        };
        assert_eq!(after.delta_since(before).unwrap().user_cpu_ns, 3);
        assert_eq!(after.delta_since(before).unwrap().max_rss_kib, 101);
        assert!(checked_delta(1, 2, "counter").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_snapshot_is_nonnegative_and_cumulative() {
        let before = ResourceSnapshot::capture().expect("getrusage");
        let mut burn = 0_u64;
        for value in 0..100_000 {
            burn = burn.wrapping_add(value);
        }
        std::hint::black_box(burn);
        let after = ResourceSnapshot::capture().expect("getrusage");
        let delta = after.delta_since(before).expect("monotonic counters");
        assert_eq!(delta.max_rss_kib, after.max_rss_kib);
    }
}
