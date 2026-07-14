use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sonar_core::CommandInvocation;
use tauri::Emitter;

const LIVE_OUTPUT_MAX_LINES: usize = 10_000;
const LIVE_OUTPUT_MAX_BYTES: usize = 2 * 1024 * 1024;

type ProcessRegistry = Arc<Mutex<HashMap<String, Arc<Mutex<Child>>>>>;

struct RegisteredProcess {
    processes: ProcessRegistry,
    run_id: String,
}

impl RegisteredProcess {
    fn new(processes: ProcessRegistry, run_id: String) -> Self {
        Self { processes, run_id }
    }
}

impl Drop for RegisteredProcess {
    fn drop(&mut self) {
        if let Ok(mut processes) = self.processes.lock() {
            processes.remove(&self.run_id);
        }
    }
}

#[derive(Default)]
pub(crate) struct LiveProcesses {
    processes: ProcessRegistry,
}

impl LiveProcesses {
    pub(crate) fn registry(&self) -> ProcessRegistry {
        Arc::clone(&self.processes)
    }

    pub(crate) fn cancel(&self, run_id: &str) -> Result<bool, String> {
        let child = self
            .processes
            .lock()
            .map_err(|_| "live process registry is poisoned".to_string())?
            .get(run_id)
            .cloned();

        let Some(child) = child else {
            return Ok(false);
        };
        let mut child = child
            .lock()
            .map_err(|_| "live process handle is poisoned".to_string())?;
        if child.try_wait().map_err(|err| err.to_string())?.is_some() {
            return Ok(false);
        }
        child.kill().map_err(|err| err.to_string())?;
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LiveEventKind {
    Start,
    Stdout,
    Stderr,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveStreamKind {
    Stdout,
    Stderr,
}

impl LiveStreamKind {
    fn event_kind(self) -> LiveEventKind {
        match self {
            Self::Stdout => LiveEventKind::Stdout,
            Self::Stderr => LiveEventKind::Stderr,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

struct BufferedLiveLine {
    kind: LiveStreamKind,
    line: String,
    bytes: usize,
}

struct LiveOutputBuffer {
    lines: VecDeque<BufferedLiveLine>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    truncated: bool,
}

impl LiveOutputBuffer {
    fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            bytes: 0,
            max_lines,
            max_bytes,
            truncated: false,
        }
    }

    fn push(&mut self, kind: LiveStreamKind, line: String) {
        if self.max_lines == 0 || self.max_bytes == 0 {
            self.truncated = true;
            return;
        }
        let (line, line_truncated) = truncate_tail(line, self.max_bytes);
        let bytes = line.len();
        while self.lines.len() >= self.max_lines
            || self.bytes.saturating_add(bytes) > self.max_bytes
        {
            let Some(removed) = self.lines.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(removed.bytes);
            self.truncated = true;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.lines.push_back(BufferedLiveLine { kind, line, bytes });
        self.truncated |= line_truncated;
    }

    fn into_streams(self) -> (Vec<String>, Vec<String>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for entry in self.lines {
            match entry.kind {
                LiveStreamKind::Stdout => stdout.push(entry.line),
                LiveStreamKind::Stderr => stderr.push(entry.line),
            }
        }
        (stdout, stderr)
    }
}

#[derive(Clone, Serialize)]
struct ProbeLiveEvent {
    run_id: String,
    kind: LiveEventKind,
    line: Option<String>,
    command: Option<String>,
    exit_code: Option<i32>,
    done: bool,
}

#[derive(Serialize)]
pub(crate) struct ProbeLiveSummary {
    pub(crate) command: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: Vec<String>,
    pub(crate) stderr: Vec<String>,
    pub(crate) truncated: bool,
    pub(crate) raw_output_path: Option<String>,
}

pub(crate) fn run_live_command(
    app: tauri::AppHandle,
    run_id: String,
    invocation: CommandInvocation,
    live_processes: ProcessRegistry,
) -> Result<ProbeLiveSummary, String> {
    emit_live(
        &app,
        ProbeLiveEvent {
            run_id: run_id.clone(),
            kind: LiveEventKind::Start,
            line: None,
            command: Some(invocation.display()),
            exit_code: None,
            done: false,
        },
    );

    let mut child = Command::new(&invocation.program)
        .args(&invocation.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{}: {err}", invocation.display()))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(child));
    live_processes
        .lock()
        .map_err(|_| "live process registry is poisoned".to_string())?
        .insert(run_id.clone(), Arc::clone(&child));
    let _registration = RegisteredProcess::new(Arc::clone(&live_processes), run_id.clone());

    let (tx, rx) = mpsc::channel::<(LiveStreamKind, String)>();
    if let Some(stdout) = stdout {
        let tx = tx.clone();
        thread::spawn(move || read_stream(LiveStreamKind::Stdout, stdout, tx));
    }
    if let Some(stderr) = stderr {
        let tx = tx.clone();
        thread::spawn(move || read_stream(LiveStreamKind::Stderr, stderr, tx));
    }
    drop(tx);

    let mut output = LiveOutputBuffer::new(LIVE_OUTPUT_MAX_LINES, LIVE_OUTPUT_MAX_BYTES);
    let (raw_log_path, mut raw_log) = create_live_output_log()
        .map(|(path, file)| (Some(path), Some(file)))
        .unwrap_or((None, None));
    let mut raw_log_complete = raw_log.is_some();

    for (kind, line) in rx {
        if let Some(file) = raw_log.as_mut() {
            if writeln!(file, "[{}] {line}", kind.label()).is_err() {
                raw_log_complete = false;
                raw_log = None;
                if let Some(path) = raw_log_path.as_ref() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        output.push(kind, line.clone());
        emit_live(
            &app,
            ProbeLiveEvent {
                run_id: run_id.clone(),
                kind: kind.event_kind(),
                line: Some(line),
                command: None,
                exit_code: None,
                done: false,
            },
        );
    }

    let status = child
        .lock()
        .map_err(|_| "live process handle is poisoned".to_string())?
        .wait()
        .map_err(|err| err.to_string())?;
    let exit_code = status.code();
    emit_live(
        &app,
        ProbeLiveEvent {
            run_id,
            kind: LiveEventKind::Exit,
            line: None,
            command: None,
            exit_code,
            done: true,
        },
    );

    let truncated = output.truncated;
    let raw_output_path = if truncated && raw_log_complete {
        let flush_ok = raw_log.as_mut().is_some_and(|file| file.flush().is_ok());
        if flush_ok {
            raw_log_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
        } else {
            remove_log(raw_log_path.as_ref());
            None
        }
    } else {
        remove_log(raw_log_path.as_ref());
        None
    };
    let (stdout, stderr) = output.into_streams();
    Ok(ProbeLiveSummary {
        command: invocation.display(),
        exit_code,
        stdout,
        stderr,
        truncated,
        raw_output_path,
    })
}

fn remove_log(path: Option<&PathBuf>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

fn create_live_output_log() -> std::io::Result<(PathBuf, File)> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sonarnwork-live-{}-{timestamp}.log",
        std::process::id()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    Ok((path, file))
}

fn read_stream<R: std::io::Read + Send + 'static>(
    kind: LiveStreamKind,
    stream: R,
    tx: mpsc::Sender<(LiveStreamKind, String)>,
) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                let _ = tx.send((kind, line));
            }
            Err(err) => {
                let _ = tx.send((LiveStreamKind::Stderr, format!("stream read failed: {err}")));
                break;
            }
        }
    }
}

fn emit_live(app: &tauri::AppHandle, event: ProbeLiveEvent) {
    let _ = app.emit("probe-live-output", event);
}

fn truncate_tail(line: String, max_bytes: usize) -> (String, bool) {
    if line.len() <= max_bytes {
        return (line, false);
    }
    const ELLIPSIS: &str = "…";
    if max_bytes < ELLIPSIS.len() {
        return (String::new(), true);
    }
    let mut start = line.len().saturating_sub(max_bytes - ELLIPSIS.len());
    while start < line.len() && !line.is_char_boundary(start) {
        start += 1;
    }
    (format!("{ELLIPSIS}{}", &line[start..]), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_output_buffer_keeps_only_the_newest_lines() {
        let mut output = LiveOutputBuffer::new(2, 1024);
        output.push(LiveStreamKind::Stdout, "first".into());
        output.push(LiveStreamKind::Stderr, "second".into());
        output.push(LiveStreamKind::Stdout, "third".into());

        assert!(output.truncated);
        let (stdout, stderr) = output.into_streams();
        assert_eq!(stdout, ["third"]);
        assert_eq!(stderr, ["second"]);
    }

    #[test]
    fn live_output_buffer_enforces_the_byte_limit() {
        let mut output = LiveOutputBuffer::new(10, 5);
        output.push(LiveStreamKind::Stdout, "1234".into());
        output.push(LiveStreamKind::Stdout, "56".into());

        assert!(output.truncated);
        let (stdout, stderr) = output.into_streams();
        assert_eq!(stdout, ["56"]);
        assert!(stderr.is_empty());
    }

    #[test]
    fn oversized_utf8_line_keeps_a_valid_tail() {
        let mut output = LiveOutputBuffer::new(10, 10);
        output.push(LiveStreamKind::Stdout, "đầu-cuối-cùng".into());
        let (stdout, _) = output.into_streams();

        assert!(stdout[0].starts_with('…'));
        assert!(stdout[0].len() <= 10);
    }

    #[test]
    fn event_kinds_keep_the_existing_ipc_names() {
        assert_eq!(
            serde_json::to_string(&LiveEventKind::Start).unwrap(),
            "\"start\""
        );
        assert_eq!(
            serde_json::to_string(&LiveEventKind::Stdout).unwrap(),
            "\"stdout\""
        );
        assert_eq!(
            serde_json::to_string(&LiveEventKind::Stderr).unwrap(),
            "\"stderr\""
        );
        assert_eq!(
            serde_json::to_string(&LiveEventKind::Exit).unwrap(),
            "\"exit\""
        );
    }
}
