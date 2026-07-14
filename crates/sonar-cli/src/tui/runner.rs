use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Context;

use super::event::UiEvent;
use super::transcript::TranscriptKind;
use super::TuiState;

#[derive(Debug)]
pub(super) enum RunnerEvent {
    Line {
        run_id: u64,
        kind: TranscriptKind,
        line: String,
    },
    Finished {
        run_id: u64,
        code: Option<i32>,
    },
    Failed {
        run_id: u64,
        error: String,
    },
}

pub(super) struct ProcessRunner {
    child: Option<Arc<Mutex<Child>>>,
    active_run_id: Option<u64>,
    next_run_id: u64,
}

impl ProcessRunner {
    pub(super) fn new() -> Self {
        Self {
            child: None,
            active_run_id: None,
            next_run_id: 1,
        }
    }

    pub(super) fn start(
        &mut self,
        args: Vec<String>,
        sender: Sender<UiEvent>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.child.is_none(), "an operation is already running");
        let executable = std::env::current_exe().context("resolve SonarNwork executable")?;
        let mut child = Command::new(executable)
            .args(args)
            .env("SONARNWORK_TUI", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start SonarNwork operation")?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let child = Arc::new(Mutex::new(child));
        let run_id = self.next_run_id;
        self.next_run_id = self.next_run_id.wrapping_add(1).max(1);

        let mut readers = Vec::with_capacity(2);
        if let Some(stdout) = stdout {
            readers.push(spawn_reader(
                stdout,
                run_id,
                TranscriptKind::Stdout,
                sender.clone(),
            ));
        }
        if let Some(stderr) = stderr {
            readers.push(spawn_reader(
                stderr,
                run_id,
                TranscriptKind::Stderr,
                sender.clone(),
            ));
        }

        let wait_child = Arc::clone(&child);
        thread::spawn(move || loop {
            let result = match wait_child.lock() {
                Ok(mut child) => child.try_wait(),
                Err(_) => {
                    send_runner(
                        &sender,
                        RunnerEvent::Failed {
                            run_id,
                            error: "process lock is poisoned".into(),
                        },
                    );
                    return;
                }
            };
            match result {
                Ok(Some(status)) => {
                    // Pipes can still contain buffered lines after the child exits. Drain them before
                    // delivering Finished so the UI never drops the tail of a command transcript.
                    for reader in readers {
                        let _ = reader.join();
                    }
                    send_runner(
                        &sender,
                        RunnerEvent::Finished {
                            run_id,
                            code: status.code(),
                        },
                    );
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    send_runner(
                        &sender,
                        RunnerEvent::Failed {
                            run_id,
                            error: error.to_string(),
                        },
                    );
                    return;
                }
            }
        });

        self.child = Some(child);
        self.active_run_id = Some(run_id);
        Ok(())
    }

    pub(super) fn cancel(&self) -> anyhow::Result<()> {
        let Some(child) = &self.child else {
            return Ok(());
        };
        child
            .lock()
            .map_err(|_| anyhow::anyhow!("process lock is poisoned"))?
            .kill()
            .context("cancel operation")
    }

    /// Returns true when a matching run completed and monitor state should be refreshed.
    pub(super) fn handle_event(&mut self, state: &mut TuiState, event: RunnerEvent) -> bool {
        let run_id = match &event {
            RunnerEvent::Line { run_id, .. }
            | RunnerEvent::Finished { run_id, .. }
            | RunnerEvent::Failed { run_id, .. } => *run_id,
        };
        if self.active_run_id != Some(run_id) {
            return false;
        }

        match event {
            RunnerEvent::Line { kind, line, .. } => {
                state.push_output(kind, line);
                false
            }
            RunnerEvent::Finished { code, .. } => {
                state.status = format!(
                    "Operation finished with exit code {}",
                    code.map_or_else(|| "unknown".into(), |code| code.to_string())
                );
                state.running = false;
                self.child = None;
                self.active_run_id = None;
                true
            }
            RunnerEvent::Failed { error, .. } => {
                state.status = format!("Operation failed: {error}");
                state.running = false;
                self.child = None;
                self.active_run_id = None;
                true
            }
        }
    }
}

fn spawn_reader(
    reader: impl std::io::Read + Send + 'static,
    run_id: u64,
    kind: TranscriptKind,
    sender: Sender<UiEvent>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    if sender
                        .send(UiEvent::Runner(RunnerEvent::Line { run_id, kind, line }))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(UiEvent::Runner(RunnerEvent::Line {
                        run_id,
                        kind: TranscriptKind::Stderr,
                        line: format!("stream read failed: {error}"),
                    }));
                    return;
                }
            }
        }
    })
}

fn send_runner(sender: &Sender<UiEvent>, event: RunnerEvent) {
    let _ = sender.send(UiEvent::Runner(event));
}

#[cfg(test)]
mod tests {
    use super::*;
    use sonar_tools::ToolCatalog;

    #[test]
    fn stale_run_events_do_not_mutate_the_active_transcript() {
        let catalog = ToolCatalog::phase_zero_defaults().interaction_catalog();
        let mut state = TuiState::new(catalog);
        let mut runner = ProcessRunner::new();
        runner.active_run_id = Some(2);

        let finished = runner.handle_event(
            &mut state,
            RunnerEvent::Line {
                run_id: 1,
                kind: TranscriptKind::Stdout,
                line: "stale".into(),
            },
        );

        assert!(!finished);
        assert!(state.output.iter().all(|entry| entry.text != "stale"));
        assert_eq!(runner.active_run_id, Some(2));
    }
}
