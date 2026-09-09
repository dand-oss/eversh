//! Independent terminal-grid oracle backed by the vt100 terminal model.

use crate::state::{EchoPolicy, PredictionState, Reconciliation, StateError};
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

    fn contains_text(&self, text: &str) -> bool {
        self.cells
            .iter()
            .map(|cell| cell.contents.as_str())
            .collect::<String>()
            .contains(text)
    }
}

struct ReplicaTerminal {
    parser: vt100::Parser,
    initial_rows: u16,
    initial_cols: u16,
}

impl ReplicaTerminal {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
            initial_rows: rows,
            initial_cols: cols,
        }
    }

    fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    fn redraw(&mut self, bytes: &[u8]) {
        self.reset();
        self.process(bytes);
    }

    fn redraw_with_resize(&mut self, before: &[u8], after: &[u8]) {
        self.reset();
        self.process(before);
        self.parser
            .screen_mut()
            .set_size(RESIZED_ROWS, RESIZED_COLS);
        self.process(after);
    }

    fn reset(&mut self) {
        self.parser = vt100::Parser::new(self.initial_rows, self.initial_cols, 0);
    }

    fn snapshot(&self) -> Result<GridSnapshot, String> {
        GridSnapshot::capture(self.parser.screen())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    pub workloads: Vec<&'static str>,
    pub correction_us: u128,
    pub password_prediction_displays: u64,
    pub persistent_predictions_applied: u64,
    pub persistent_corrections: u64,
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

fn state_result<T>(result: Result<T, StateError>) -> Result<T, String> {
    result.map_err(|error| format!("prediction state: {error}"))
}

fn apply_prediction(
    state: &mut PredictionState,
    replica: &mut ReplicaTerminal,
    input: &[u8],
) -> Result<(u64, bool), String> {
    let (seq, displayed) = state_result(state.send(input))?;
    if displayed {
        replica.process(input);
    }
    Ok((seq, displayed))
}

fn reconcile_replica(
    state: &mut PredictionState,
    replica: &mut ReplicaTerminal,
    seq: u64,
    output: &[u8],
    prediction_displayed: bool,
    persistent_corrections: &mut u64,
) -> Result<Reconciliation, String> {
    let reconciliation = state_result(state.reconcile(seq, output))?;
    match reconciliation {
        Reconciliation::Confirmed { predicted } => {
            if predicted != prediction_displayed {
                return Err("reconciliation disagreed with displayed prediction state".into());
            }
            if !predicted {
                replica.process(output);
            }
        }
        Reconciliation::Corrected => {
            if prediction_displayed {
                *persistent_corrections = persistent_corrections.saturating_add(1);
            }
            replica.redraw(&state.rendered_bytes());
        }
        Reconciliation::Buffered | Reconciliation::Duplicate | Reconciliation::Unexpected => {}
    }
    Ok(reconciliation)
}

pub fn run() -> Result<OracleReport, String> {
    let mut workloads = Vec::new();
    let mut persistent_predictions_applied = 0u64;
    let mut persistent_corrections = 0u64;

    let echo_input = b"hello everudp";
    let echo_output = capture_python("echo", Some(echo_input.len()), echo_input)?;
    let mut echo = PredictionState::new(1, EchoPolicy::Predict);
    let mut echo_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (echo_seq, echo_displayed) = apply_prediction(&mut echo, &mut echo_replica, echo_input)?;
    persistent_predictions_applied += u64::from(echo_displayed);
    if !echo_displayed
        || reconcile_replica(
            &mut echo,
            &mut echo_replica,
            echo_seq,
            &echo_output,
            echo_displayed,
            &mut persistent_corrections,
        )? != (Reconciliation::Confirmed { predicted: true })
    {
        return Err("echo: matching printable input was not confirmed as predicted".into());
    }
    require_same_grid(
        "echo",
        render(&echo_output, INITIAL_ROWS, INITIAL_COLS)?,
        echo_replica.snapshot()?,
    )?;
    workloads.push("echo");

    let mismatch_output = capture_python("mismatch", None, b"x")?;
    let mismatch_authority = render(&mismatch_output, INITIAL_ROWS, INITIAL_COLS)?;
    let mut mismatch = PredictionState::new(1, EchoPolicy::Predict);
    let mut mismatch_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (mismatch_seq, displayed) = apply_prediction(&mut mismatch, &mut mismatch_replica, b"x")?;
    persistent_predictions_applied += u64::from(displayed);
    if !displayed {
        return Err("mismatch: printable input was not predicted".into());
    }
    if !mismatch_replica.snapshot()?.contains_text("x") {
        return Err("mismatch: prediction was not visible in the persistent grid".into());
    }
    let correction_started = Instant::now();
    if reconcile_replica(
        &mut mismatch,
        &mut mismatch_replica,
        mismatch_seq,
        &mismatch_output,
        displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Corrected
    {
        return Err("mismatch: divergent authority was not corrected".into());
    }
    let mismatch_corrected = mismatch_replica.snapshot()?;
    let correction_us = correction_started.elapsed().as_micros();
    if correction_us >= 300_000 {
        return Err(format!("mismatch: correction took {correction_us} us"));
    }
    require_same_grid(
        "mismatch correction",
        mismatch_authority,
        mismatch_corrected,
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
    let mut reordered_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (first, first_displayed) =
        apply_prediction(&mut reordered, &mut reordered_replica, &reorder_output[..1])?;
    let (second, second_displayed) =
        apply_prediction(&mut reordered, &mut reordered_replica, &reorder_output[1..])?;
    persistent_predictions_applied += u64::from(first_displayed) + u64::from(second_displayed);
    if reconcile_replica(
        &mut reordered,
        &mut reordered_replica,
        second,
        &reorder_output[1..],
        second_displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Buffered
    {
        return Err("duplicate/reorder: future acknowledgement was not buffered".into());
    }
    if reconcile_replica(
        &mut reordered,
        &mut reordered_replica,
        first,
        &reorder_output[..1],
        first_displayed,
        &mut persistent_corrections,
    )? != (Reconciliation::Confirmed { predicted: true })
        || reconcile_replica(
            &mut reordered,
            &mut reordered_replica,
            second,
            &reorder_output[1..],
            second_displayed,
            &mut persistent_corrections,
        )? != Reconciliation::Duplicate
    {
        return Err("duplicate/reorder: convergence or duplicate suppression failed".into());
    }
    require_same_grid(
        "duplicate/reorder",
        render(&reorder_output, INITIAL_ROWS, INITIAL_COLS)?,
        reordered_replica.snapshot()?,
    )?;
    workloads.push("duplicate-reorder");

    let full_screen_output = capture_python("full-screen", None, &[])?;
    let mut full_screen = PredictionState::new(1, EchoPolicy::Predict);
    let mut full_screen_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (full_screen_seq, full_screen_displayed) =
        apply_prediction(&mut full_screen, &mut full_screen_replica, b"f")?;
    persistent_predictions_applied += u64::from(full_screen_displayed);
    if reconcile_replica(
        &mut full_screen,
        &mut full_screen_replica,
        full_screen_seq,
        &full_screen_output,
        full_screen_displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Corrected
    {
        return Err("full-screen: trigger prediction was not replaced by authority".into());
    }
    let full_grid = require_same_grid(
        "full-screen",
        render(&full_screen_output, INITIAL_ROWS, INITIAL_COLS)?,
        full_screen_replica.snapshot()?,
    )?;
    if !full_grid.has_styled_cell() {
        return Err("full-screen: fixture exercised no cell attributes".into());
    }
    workloads.push("full-screen");

    let resize_output = capture_python("resize", None, b"r")?;
    let (before_resize, after_resize) = split_once(&resize_output, RESIZE_MARKER)?;
    let mut resized = PredictionState::new(1, EchoPolicy::Predict);
    let mut resized_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (before_seq, before_displayed) =
        apply_prediction(&mut resized, &mut resized_replica, b"s")?;
    persistent_predictions_applied += u64::from(before_displayed);
    if reconcile_replica(
        &mut resized,
        &mut resized_replica,
        before_seq,
        before_resize,
        before_displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Corrected
    {
        return Err("resize: authoritative redraw did not replace predictions".into());
    }
    let (after_seq, after_displayed) = apply_prediction(&mut resized, &mut resized_replica, b"r")?;
    persistent_predictions_applied += u64::from(after_displayed);
    if state_result(resized.reconcile(after_seq, after_resize))? != Reconciliation::Corrected {
        return Err("resize: authoritative redraw did not replace predictions".into());
    }
    if after_displayed {
        persistent_corrections = persistent_corrections.saturating_add(1);
    }
    resized_replica.redraw_with_resize(before_resize, after_resize);
    let resize_grid = require_same_grid(
        "resize",
        render_with_resize(before_resize, after_resize)?,
        resized_replica.snapshot()?,
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
    let mut tmux_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (tmux_seq, tmux_displayed) = apply_prediction(&mut tmux, &mut tmux_replica, b"t")?;
    persistent_predictions_applied += u64::from(tmux_displayed);
    if reconcile_replica(
        &mut tmux,
        &mut tmux_replica,
        tmux_seq,
        &tmux_output,
        tmux_displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Corrected
    {
        return Err("tmux: authoritative stream did not replace prediction".into());
    }
    require_same_grid(
        "tmux",
        render(&tmux_output, INITIAL_ROWS, INITIAL_COLS)?,
        tmux_replica.snapshot()?,
    )?;
    workloads.push("tmux");

    let password_input = b"secret";
    let password_output = capture_python("no-echo", Some(password_input.len()), password_input)?;
    let mut password = PredictionState::new(1, EchoPolicy::NoEcho);
    let mut password_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (password_seq, password_displayed) =
        apply_prediction(&mut password, &mut password_replica, password_input)?;
    if password_displayed
        || reconcile_replica(
            &mut password,
            &mut password_replica,
            password_seq,
            &password_output,
            password_displayed,
            &mut persistent_corrections,
        )? != Reconciliation::Corrected
        || password.predicted_echo_displays != 0
    {
        return Err("no-echo: password prediction policy failed".into());
    }
    let password_grid = require_same_grid(
        "no-echo",
        render(&password_output, INITIAL_ROWS, INITIAL_COLS)?,
        password_replica.snapshot()?,
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
    let mut resync_replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
    let (stale_seq, stale_displayed) =
        apply_prediction(&mut resync, &mut resync_replica, b"stale")?;
    persistent_predictions_applied += u64::from(stale_displayed);
    if reconcile_replica(
        &mut resync,
        &mut resync_replica,
        stale_seq,
        b"stale",
        stale_displayed,
        &mut persistent_corrections,
    )? != (Reconciliation::Confirmed { predicted: true })
    {
        return Err("epoch reset/resync did not confirm its pre-reset fixture".into());
    }
    resync.reset(2);
    resync_replica.reset();
    let (resync_seq, resync_displayed) =
        apply_prediction(&mut resync, &mut resync_replica, b"\x0c")?;
    if reconcile_replica(
        &mut resync,
        &mut resync_replica,
        resync_seq,
        &full_screen_output,
        resync_displayed,
        &mut persistent_corrections,
    )? != Reconciliation::Corrected
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
        resync_replica.snapshot()?,
    )?;
    workloads.push("epoch-reset-resync");

    Ok(OracleReport {
        workloads,
        correction_us,
        password_prediction_displays: password.predicted_echo_displays,
        persistent_predictions_applied,
        persistent_corrections,
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
    fn persistent_replica_visibly_replaces_a_rendered_prediction() {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let mut replica = ReplicaTerminal::new(INITIAL_ROWS, INITIAL_COLS);
        let (seq, displayed) = state.send(b"x").unwrap();
        assert!(displayed);
        replica.process(b"x");
        assert!(replica.snapshot().unwrap().contains_text("x"));

        let started = Instant::now();
        assert_eq!(
            state.reconcile(seq, b"y").unwrap(),
            Reconciliation::Corrected
        );
        replica.redraw(&state.rendered_bytes());
        let corrected = replica.snapshot().unwrap();
        let correction_us = started.elapsed().as_micros();

        assert!(!corrected.contains_text("x"));
        assert!(corrected.contains_text("y"));
        assert_eq!(corrected, render(b"y", INITIAL_ROWS, INITIAL_COLS).unwrap());
        assert!(correction_us < 300_000);
    }

    #[test]
    fn real_pty_terminal_grid_matrix_passes() {
        let report = run().unwrap();
        assert_eq!(report.workloads.len(), 8);
        assert!(report.correction_us < 300_000);
        assert_eq!(report.password_prediction_displays, 0);
        assert_eq!(report.persistent_predictions_applied, 9);
        assert_eq!(report.persistent_corrections, 5);
    }
}
