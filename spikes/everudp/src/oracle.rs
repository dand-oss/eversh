//! Independent terminal-grid oracle backed by the vt100 terminal model.

use crate::state::{EchoPolicy, PredictionState, Reconciliation};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const READY: &[u8] = b"EVERUDP_ORACLE_READY";
const RESIZE_MARKER: &[u8] = b"\x1bPeverudp-resize\x1b\\";
const INITIAL_ROWS: u16 = 24;
const INITIAL_COLS: u16 = 80;
const RESIZED_ROWS: u16 = 30;
const RESIZED_COLS: u16 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CellSnapshot {
    contents: String,
    foreground: vt100::Color,
    background: vt100::Color,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
    wide: bool,
    wide_continuation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GridSnapshot {
    size: (u16, u16),
    cursor: (u16, u16),
    cursor_foreground: vt100::Color,
    cursor_background: vt100::Color,
    cursor_bold: bool,
    cursor_dim: bool,
    cursor_italic: bool,
    cursor_underline: bool,
    cursor_inverse: bool,
    alternate_screen: bool,
    hidden_cursor: bool,
    wrapped_rows: Vec<bool>,
    cells: Vec<CellSnapshot>,
}

impl GridSnapshot {
    fn capture(screen: &vt100::Screen) -> Result<Self, String> {
        let (rows, cols) = screen.size();
        let mut cells = Vec::with_capacity(usize::from(rows) * usize::from(cols));
        for row in 0..rows {
            for col in 0..cols {
                let cell = screen
                    .cell(row, col)
                    .ok_or_else(|| format!("terminal grid omitted cell {row},{col}"))?;
                cells.push(CellSnapshot {
                    contents: cell.contents().to_string(),
                    foreground: cell.fgcolor(),
                    background: cell.bgcolor(),
                    bold: cell.bold(),
                    dim: cell.dim(),
                    italic: cell.italic(),
                    underline: cell.underline(),
                    inverse: cell.inverse(),
                    wide: cell.is_wide(),
                    wide_continuation: cell.is_wide_continuation(),
                });
            }
        }
        Ok(Self {
            size: (rows, cols),
            cursor: screen.cursor_position(),
            cursor_foreground: screen.fgcolor(),
            cursor_background: screen.bgcolor(),
            cursor_bold: screen.bold(),
            cursor_dim: screen.dim(),
            cursor_italic: screen.italic(),
            cursor_underline: screen.underline(),
            cursor_inverse: screen.inverse(),
            alternate_screen: screen.alternate_screen(),
            hidden_cursor: screen.hide_cursor(),
            wrapped_rows: (0..rows).map(|row| screen.row_wrapped(row)).collect(),
            cells,
        })
    }

    fn has_styled_cell(&self) -> bool {
        self.cells.iter().any(|cell| {
            cell.foreground != vt100::Color::Default
                || cell.background != vt100::Color::Default
                || cell.bold
                || cell.dim
                || cell.italic
                || cell.underline
                || cell.inverse
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    pub workloads: Vec<&'static str>,
    pub correction_us: u128,
    pub password_prediction_displays: u64,
}

fn render(bytes: &[u8], rows: u16, cols: u16) -> Result<GridSnapshot, String> {
    let mut parser = vt100::Parser::new(rows, cols, 0);
    parser.process(bytes);
    GridSnapshot::capture(parser.screen())
}

fn render_with_resize(before: &[u8], after: &[u8]) -> Result<GridSnapshot, String> {
    let mut parser = vt100::Parser::new(INITIAL_ROWS, INITIAL_COLS, 0);
    parser.process(before);
    parser.screen_mut().set_size(RESIZED_ROWS, RESIZED_COLS);
    parser.process(after);
    GridSnapshot::capture(parser.screen())
}

fn require_same_grid(
    name: &str,
    authoritative: GridSnapshot,
    reconstructed: GridSnapshot,
) -> Result<GridSnapshot, String> {
    if authoritative != reconstructed {
        return Err(format!(
            "{name}: terminal-grid mismatch (authority size/cursor {:?}/{:?}, replica {:?}/{:?})",
            authoritative.size, authoritative.cursor, reconstructed.size, reconstructed.cursor,
        ));
    }
    Ok(authoritative)
}

fn child_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/net/oracle-child.py")
}

fn python_command(mode: &str, argument: Option<usize>) -> String {
    match argument {
        Some(argument) => format!("/usr/bin/python3 -u {} {mode} {argument}", child_path()),
        None => format!("/usr/bin/python3 -u {} {mode}", child_path()),
    }
}

fn capture_pty(command: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    let wrapped = format!(
        "stty raw -echo rows {INITIAL_ROWS} cols {INITIAL_COLS}; printf {}; exec {command}",
        std::str::from_utf8(READY).expect("ASCII readiness marker")
    );
    let mut child = Command::new("/usr/bin/timeout")
        .args([
            "--signal=KILL",
            "5s",
            "/usr/bin/script",
            "-qefc",
            &wrapped,
            "/dev/null",
        ])
        .env("TERM", "xterm-256color")
        .env_remove("TMUX")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn PTY workload: {error}"))?;
    let mut stdout = child.stdout.take().ok_or("PTY workload has no stdout")?;
    let mut prefix = vec![0u8; READY.len()];
    stdout
        .read_exact(&mut prefix)
        .map_err(|error| format!("read PTY readiness marker: {error}"))?;
    if prefix != READY {
        return Err(format!("invalid PTY readiness marker: {prefix:?}"));
    }
    let mut stdin = child.stdin.take().ok_or("PTY workload has no stdin")?;
    stdin
        .write_all(input)
        .and_then(|()| stdin.flush())
        .map_err(|error| format!("write PTY workload: {error}"))?;
    drop(stdin);
    let mut output = Vec::new();
    stdout
        .read_to_end(&mut output)
        .map_err(|error| format!("read PTY workload: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("wait for PTY workload: {error}"))?;
    if !status.success() {
        return Err(format!("PTY workload exited with {status}"));
    }
    Ok(output)
}

fn capture_python(mode: &str, argument: Option<usize>, input: &[u8]) -> Result<Vec<u8>, String> {
    capture_pty(&python_command(mode, argument), input)
}

fn capture_tmux() -> Result<Vec<u8>, String> {
    static NEXT_TMUX: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_TMUX.fetch_add(1, Ordering::Relaxed);
    let label = format!("everudp-oracle-{}-{id}", std::process::id());
    let command = format!(
        "/usr/bin/tmux -L {label} -f /dev/null new-session -x {INITIAL_COLS} -y {INITIAL_ROWS} '/usr/bin/python3 -u {} tmux'",
        child_path()
    );
    let result = capture_pty(&command, &[]);
    let _ = Command::new("/usr/bin/tmux")
        .args(["-L", &label, "kill-server"])
        .env_remove("TMUX")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    result
}

fn split_once<'a>(bytes: &'a [u8], marker: &[u8]) -> Result<(&'a [u8], &'a [u8]), String> {
    let index = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("resize workload omitted its marker")?;
    if bytes[index + marker.len()..]
        .windows(marker.len())
        .any(|window| window == marker)
    {
        return Err("resize workload repeated its marker".into());
    }
    Ok((&bytes[..index], &bytes[index + marker.len()..]))
}

fn reconcile_one(state: &mut PredictionState, input: &[u8], output: &[u8]) -> Reconciliation {
    let (seq, _) = state.send(input);
    state.reconcile(seq, output)
}

pub fn run() -> Result<OracleReport, String> {
    let mut workloads = Vec::new();

    let echo_input = b"hello everudp";
    let echo_output = capture_python("echo", Some(echo_input.len()), echo_input)?;
    let mut echo = PredictionState::new(1, EchoPolicy::Predict);
    let (echo_seq, echo_displayed) = echo.send(echo_input);
    if !echo_displayed
        || echo.reconcile(echo_seq, &echo_output) != (Reconciliation::Confirmed { predicted: true })
    {
        return Err("echo: matching printable input was not confirmed as predicted".into());
    }
    require_same_grid(
        "echo",
        render(&echo_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&echo.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    workloads.push("echo");

    let mismatch_output = capture_python("mismatch", None, b"x")?;
    let mut mismatch = PredictionState::new(1, EchoPolicy::Predict);
    let (mismatch_seq, displayed) = mismatch.send(b"x");
    if !displayed {
        return Err("mismatch: printable input was not predicted".into());
    }
    let correction_started = Instant::now();
    if mismatch.reconcile(mismatch_seq, &mismatch_output) != Reconciliation::Corrected {
        return Err("mismatch: divergent authority was not corrected".into());
    }
    let correction_us = correction_started.elapsed().as_micros();
    if correction_us >= 300_000 {
        return Err(format!("mismatch: correction took {correction_us} us"));
    }
    require_same_grid(
        "mismatch correction",
        render(&mismatch_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&mismatch.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    workloads.push("mismatch-correction");

    let reorder_output = capture_python("echo", Some(2), b"ab")?;
    if reorder_output.len() != 2 {
        return Err(format!(
            "duplicate/reorder: expected two PTY bytes, got {}",
            reorder_output.len()
        ));
    }
    let mut reordered = PredictionState::new(1, EchoPolicy::Predict);
    let (first, _) = reordered.send(&reorder_output[..1]);
    let (second, _) = reordered.send(&reorder_output[1..]);
    if reordered.reconcile(second, &reorder_output[1..]) != Reconciliation::Buffered {
        return Err("duplicate/reorder: future acknowledgement was not buffered".into());
    }
    if reordered.reconcile(first, &reorder_output[..1])
        != (Reconciliation::Confirmed { predicted: true })
        || reordered.reconcile(second, &reorder_output[1..]) != Reconciliation::Duplicate
    {
        return Err("duplicate/reorder: convergence or duplicate suppression failed".into());
    }
    require_same_grid(
        "duplicate/reorder",
        render(&reorder_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&reordered.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    workloads.push("duplicate-reorder");

    let full_screen_output = capture_python("full-screen", None, &[])?;
    let mut full_screen = PredictionState::new(1, EchoPolicy::Predict);
    if reconcile_one(&mut full_screen, b"f", &full_screen_output) != Reconciliation::Corrected {
        return Err("full-screen: trigger prediction was not replaced by authority".into());
    }
    let full_grid = require_same_grid(
        "full-screen",
        render(&full_screen_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&full_screen.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    if !full_grid.has_styled_cell() {
        return Err("full-screen: fixture exercised no cell attributes".into());
    }
    workloads.push("full-screen");

    let resize_output = capture_python("resize", None, b"r")?;
    let (before_resize, after_resize) = split_once(&resize_output, RESIZE_MARKER)?;
    let mut resized = PredictionState::new(1, EchoPolicy::Predict);
    if reconcile_one(&mut resized, b"s", before_resize) != Reconciliation::Corrected
        || reconcile_one(&mut resized, b"r", after_resize) != Reconciliation::Corrected
    {
        return Err("resize: authoritative redraw did not replace predictions".into());
    }
    let reconstructed_resize = resized.rendered_bytes();
    let resize_grid = require_same_grid(
        "resize",
        render_with_resize(before_resize, after_resize)?,
        render_with_resize(
            &reconstructed_resize[..before_resize.len()],
            &reconstructed_resize[before_resize.len()..],
        )?,
    )?;
    if resize_grid.size != (RESIZED_ROWS, RESIZED_COLS) {
        return Err(format!(
            "resize: wrong final dimensions {:?}",
            resize_grid.size
        ));
    }
    workloads.push("resize");

    let tmux_output = capture_tmux()?;
    if !tmux_output.windows(6).any(|window| window == b"pane-1") {
        return Err("tmux: real tmux stream omitted pane fixture".into());
    }
    let mut tmux = PredictionState::new(1, EchoPolicy::Predict);
    if reconcile_one(&mut tmux, b"t", &tmux_output) != Reconciliation::Corrected {
        return Err("tmux: authoritative stream did not replace prediction".into());
    }
    require_same_grid(
        "tmux",
        render(&tmux_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&tmux.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    workloads.push("tmux");

    let password_input = b"secret";
    let password_output = capture_python("no-echo", Some(password_input.len()), password_input)?;
    let mut password = PredictionState::new(1, EchoPolicy::NoEcho);
    let (password_seq, password_displayed) = password.send(password_input);
    if password_displayed
        || password.reconcile(password_seq, &password_output) != Reconciliation::Corrected
        || password.predicted_echo_displays != 0
    {
        return Err("no-echo: password prediction policy failed".into());
    }
    let password_grid = require_same_grid(
        "no-echo",
        render(&password_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&password.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    if password_grid
        .cells
        .iter()
        .any(|cell| cell.contents.contains("secret"))
    {
        return Err("no-echo: password appeared in the reconstructed grid".into());
    }
    workloads.push("no-echo");

    let mut resync = PredictionState::new(1, EchoPolicy::Predict);
    reconcile_one(&mut resync, b"stale", b"stale");
    resync.reset(2);
    if reconcile_one(&mut resync, b"\x0c", &full_screen_output) != Reconciliation::Corrected
        || resync
            .rendered_bytes()
            .windows(5)
            .any(|bytes| bytes == b"stale")
    {
        return Err("epoch reset/resync retained stale terminal state".into());
    }
    require_same_grid(
        "epoch reset/resync",
        render(&full_screen_output, INITIAL_ROWS, INITIAL_COLS)?,
        render(&resync.rendered_bytes(), INITIAL_ROWS, INITIAL_COLS)?,
    )?;
    workloads.push("epoch-reset-resync");

    Ok(OracleReport {
        workloads,
        correction_us,
        password_prediction_displays: password.predicted_echo_displays,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_detect_cell_attribute_and_cursor_divergence() {
        let plain = render(b"X", 2, 4).unwrap();
        let red = render(b"\x1b[31mX", 2, 4).unwrap();
        let moved = render(b"X\x1b[2;2H", 2, 4).unwrap();
        assert_ne!(plain, red);
        assert_ne!(plain, moved);
    }

    #[test]
    fn real_pty_terminal_grid_matrix_passes() {
        let report = run().unwrap();
        assert_eq!(report.workloads.len(), 8);
        assert!(report.correction_us < 300_000);
        assert_eq!(report.password_prediction_displays, 0);
    }
}
