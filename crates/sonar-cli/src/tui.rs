use std::collections::BTreeMap;
use std::sync::mpsc::{self, RecvTimeoutError};

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use sonar_core::{
    InteractionCatalog, InteractionField, InteractionFieldKind, InteractionNamespace,
};
use sonar_tools::{
    operations::{default_app_data_dir, OperationsService},
    ToolCatalog,
};

mod event;
mod runner;
mod transcript;
mod view;

use self::event::{spawn_terminal_reader, FramePacer, UiEvent, OUTPUT_SCROLL_PAGE};
use self::runner::ProcessRunner;
use self::transcript::{BoundedTranscript, TranscriptKind};
use self::view::render;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputMode {
    Command,
    Palette,
    Form,
}

#[derive(Debug, PartialEq, Eq)]
enum TuiAction {
    Run(Vec<String>),
    RefreshStatus(String),
    Install(String),
    Update(String),
    Cancel,
    Quit,
}

struct TuiState {
    catalog: InteractionCatalog,
    mode: InputMode,
    command_input: String,
    palette_selection: usize,
    selected_namespace_id: Option<String>,
    values: BTreeMap<String, String>,
    focused_field: usize,
    scope_confirmed: bool,
    output: BoundedTranscript,
    output_scroll_from_bottom: usize,
    output_follow_tail: bool,
    status: String,
    running: bool,
}

impl TuiState {
    fn new(catalog: InteractionCatalog) -> Self {
        debug_assert!(catalog.validate().is_ok());
        Self {
            catalog,
            mode: InputMode::Command,
            command_input: String::new(),
            palette_selection: 0,
            selected_namespace_id: None,
            values: BTreeMap::new(),
            focused_field: 0,
            scope_confirmed: false,
            output: {
                let mut output = BoundedTranscript::with_defaults();
                output.push(
                    TranscriptKind::Status,
                    "Type / to choose a diagnostic or plugin workflow.",
                );
                output.push(
                    TranscriptKind::Status,
                    "The highlighted form is previewed here before selection.",
                );
                output
            },
            output_scroll_from_bottom: 0,
            output_follow_tail: true,
            status: "Ready".into(),
            running: false,
        }
    }

    fn selected_namespace(&self) -> Option<&InteractionNamespace> {
        self.selected_namespace_id
            .as_deref()
            .and_then(|id| self.catalog.namespace(id))
    }

    fn preview_namespace(&self) -> Option<&InteractionNamespace> {
        if self.mode == InputMode::Palette {
            let indices = self.filtered_indices();
            indices
                .get(self.palette_selection)
                .and_then(|index| self.catalog.namespaces.get(*index))
        } else {
            self.selected_namespace()
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let needle = self
            .command_input
            .trim_start_matches('/')
            .trim()
            .to_ascii_lowercase();
        self.catalog
            .namespaces
            .iter()
            .enumerate()
            .filter(|(_, namespace)| {
                needle.is_empty()
                    || namespace.trigger[1..].contains(&needle)
                    || namespace.label.to_ascii_lowercase().contains(&needle)
                    || namespace
                        .aliases
                        .iter()
                        .any(|alias| alias[1..].contains(&needle))
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn visible_fields(&self) -> Vec<&InteractionField> {
        let Some(namespace) = self.selected_namespace() else {
            return vec![];
        };
        namespace
            .fields
            .iter()
            .filter(|field| {
                field.visible_when.as_ref().is_none_or(|visibility| {
                    self.values
                        .get(&visibility.field_id)
                        .is_some_and(|value| value == &visibility.equals)
                })
            })
            .collect()
    }

    fn focus_count(&self) -> usize {
        self.visible_fields().len()
            + usize::from(
                self.selected_namespace()
                    .is_some_and(|namespace| namespace.requires_scope_confirmation),
            )
    }

    fn open_palette(&mut self) {
        self.mode = InputMode::Palette;
        self.command_input.clear();
        self.command_input.push('/');
        self.palette_selection = 0;
        self.status = "Choose a namespace; its form is previewed in the workspace.".into();
    }

    fn move_palette(&mut self, delta: isize) {
        let count = self.filtered_indices().len();
        if count == 0 {
            self.palette_selection = 0;
        } else {
            self.palette_selection =
                (self.palette_selection as isize + delta).rem_euclid(count as isize) as usize;
        }
    }

    fn select_palette(&mut self) -> Option<TuiAction> {
        let index = *self.filtered_indices().get(self.palette_selection)?;
        let namespace = self.catalog.namespaces.get(index)?.clone();
        self.selected_namespace_id = Some(namespace.id.clone());
        self.values = namespace
            .fields
            .iter()
            .filter_map(|field| {
                field
                    .default_value
                    .as_ref()
                    .map(|value| (field.id.clone(), value.clone()))
            })
            .collect();
        self.command_input = namespace.trigger.clone();
        self.focused_field = 0;
        self.scope_confirmed = false;
        self.mode = InputMode::Form;
        self.clear_output();
        self.push_output(TranscriptKind::Status, namespace.description.clone());
        self.status = "Edit the form. Tab moves fields; Enter or F5 runs.".into();
        if namespace.id == "open-ui" {
            return self.prepared_action();
        }
        namespace
            .id
            .strip_prefix("scanner.")
            .map(|tool_id| TuiAction::RefreshStatus(tool_id.to_string()))
    }

    fn move_focus(&mut self, delta: isize) {
        let count = self.focus_count();
        if count == 0 {
            self.focused_field = 0;
        } else {
            self.focused_field =
                (self.focused_field as isize + delta).rem_euclid(count as isize) as usize;
        }
    }

    fn edit_current(&mut self, character: char) {
        let field_id = self
            .visible_fields()
            .get(self.focused_field)
            .filter(|field| field.kind != InteractionFieldKind::Choice)
            .map(|field| field.id.clone());
        if let Some(field_id) = field_id {
            self.values.entry(field_id).or_default().push(character);
        }
    }

    fn backspace_current(&mut self) {
        let field_id = self
            .visible_fields()
            .get(self.focused_field)
            .filter(|field| field.kind != InteractionFieldKind::Choice)
            .map(|field| field.id.clone());
        if let Some(field_id) = field_id {
            self.values.entry(field_id).or_default().pop();
        }
    }

    fn cycle_choice(&mut self, delta: isize) {
        let visible_fields = self.visible_fields();
        let Some(field) = visible_fields.get(self.focused_field) else {
            return;
        };
        if field.kind != InteractionFieldKind::Choice || field.choices.is_empty() {
            return;
        }
        let field_id = field.id.clone();
        let choices = field
            .choices
            .iter()
            .map(|choice| choice.value.clone())
            .collect::<Vec<_>>();
        let current = self
            .values
            .get(&field_id)
            .and_then(|value| choices.iter().position(|choice| choice == value))
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(choices.len() as isize) as usize;
        self.values.insert(field_id, choices[next].clone());
        self.focused_field = self.focused_field.min(self.focus_count().saturating_sub(1));
    }

    fn toggle_scope_if_focused(&mut self) -> bool {
        let Some(namespace) = self.selected_namespace() else {
            return false;
        };
        if namespace.requires_scope_confirmation
            && self.focused_field == self.visible_fields().len()
        {
            self.scope_confirmed = !self.scope_confirmed;
            true
        } else {
            false
        }
    }

    fn current_tool_id(&self) -> Option<String> {
        self.selected_namespace_id
            .as_deref()
            .and_then(|id| id.strip_prefix("scanner."))
            .map(str::to_string)
    }

    fn handle_key(&mut self, key: KeyEvent) -> Option<TuiAction> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(if self.running {
                TuiAction::Cancel
            } else {
                TuiAction::Quit
            });
        }
        match key.code {
            KeyCode::F(10) => return Some(TuiAction::Quit),
            KeyCode::F(2) => return self.current_tool_id().map(TuiAction::RefreshStatus),
            KeyCode::F(3) if !self.running => {
                return self.current_tool_id().map(TuiAction::Install)
            }
            KeyCode::F(4) if !self.running => return self.current_tool_id().map(TuiAction::Update),
            KeyCode::F(5) if !self.running && self.mode == InputMode::Form => {
                return self.prepared_action();
            }
            KeyCode::F(6) if self.running => return Some(TuiAction::Cancel),
            _ => {}
        }
        if self.mode != InputMode::Palette {
            match key.code {
                KeyCode::PageUp => {
                    self.scroll_output_up(OUTPUT_SCROLL_PAGE);
                    return None;
                }
                KeyCode::PageDown => {
                    self.scroll_output_down(OUTPUT_SCROLL_PAGE);
                    return None;
                }
                KeyCode::End => {
                    self.follow_output_tail();
                    return None;
                }
                _ => {}
            }
        }

        match self.mode {
            InputMode::Command => match key.code {
                KeyCode::Char('/') => self.open_palette(),
                KeyCode::Esc => self.command_input.clear(),
                _ => self.status = "Type / to open the command palette (F10 exits).".into(),
            },
            InputMode::Palette => match key.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Command;
                    self.command_input.clear();
                    self.status = "Palette closed.".into();
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_palette(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_palette(-1),
                KeyCode::Enter => return self.select_palette(),
                KeyCode::Backspace => {
                    if self.command_input.len() > 1 {
                        self.command_input.pop();
                    }
                    self.palette_selection = 0;
                }
                KeyCode::Char(character) => {
                    self.command_input.push(character);
                    self.palette_selection = 0;
                }
                _ => {}
            },
            InputMode::Form => match key.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Command;
                    self.command_input.clear();
                    self.status = "Type / to switch workflow.".into();
                }
                KeyCode::Tab => self.move_focus(1),
                KeyCode::BackTab => self.move_focus(-1),
                KeyCode::Left => self.cycle_choice(-1),
                KeyCode::Right => self.cycle_choice(1),
                KeyCode::Char(' ') if self.toggle_scope_if_focused() => {}
                KeyCode::Backspace => self.backspace_current(),
                KeyCode::Enter if !self.running => return self.prepared_action(),
                KeyCode::Char(character) => self.edit_current(character),
                _ => {}
            },
        }
        None
    }

    fn prepared_action(&mut self) -> Option<TuiAction> {
        match self.prepare_run() {
            Ok(args) => Some(TuiAction::Run(args)),
            Err(error) => {
                self.status = error;
                None
            }
        }
    }

    fn prepare_run(&self) -> Result<Vec<String>, String> {
        let namespace = self
            .selected_namespace()
            .ok_or_else(|| "select a workflow first".to_string())?;
        for field in self.visible_fields() {
            if field.required
                && self
                    .values
                    .get(&field.id)
                    .is_none_or(|value| value.trim().is_empty())
            {
                return Err(format!("{} is required", field.label));
            }
        }
        if namespace.requires_scope_confirmation && !self.scope_confirmed {
            return Err("confirm that you own or are authorized for this target".into());
        }
        interaction_args(namespace, &self.values)
    }

    fn clear_output(&mut self) {
        self.output.clear();
        self.follow_output_tail();
    }

    fn push_output(&mut self, kind: TranscriptKind, line: impl Into<String>) {
        self.output.push(kind, line);
        if !self.output_follow_tail {
            self.output_scroll_from_bottom = self.output_scroll_from_bottom.saturating_add(1);
        }
    }

    fn scroll_output_up(&mut self, rows: usize) {
        if self.output.is_empty() {
            return;
        }
        self.output_follow_tail = false;
        self.output_scroll_from_bottom = self.output_scroll_from_bottom.saturating_add(rows);
    }

    fn scroll_output_down(&mut self, rows: usize) {
        self.output_scroll_from_bottom = self.output_scroll_from_bottom.saturating_sub(rows);
        if self.output_scroll_from_bottom == 0 {
            self.output_follow_tail = true;
        }
    }

    fn follow_output_tail(&mut self) {
        self.output_scroll_from_bottom = 0;
        self.output_follow_tail = true;
    }
}

fn interaction_args(
    namespace: &InteractionNamespace,
    values: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let value = |id: &str| {
        values
            .get(id)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    };
    let args = match namespace.id.as_str() {
        "check" => vec!["check".into(), required(value("target"), "target")?],
        "ping" => {
            let mut args = vec!["ping".into(), required(value("target"), "target")?];
            push_option(&mut args, "--count", value("count"));
            push_option(&mut args, "--timeout", value("timeout_ms"));
            push_option(&mut args, "--size", value("packet_size"));
            args
        }
        "trace" => {
            let mut args = vec!["trace".into(), required(value("target"), "target")?];
            match value("protocol") {
                Some("tcp") => args.push("--tcp".into()),
                Some("udp") => args.push("--udp".into()),
                _ => {}
            }
            push_option(&mut args, "--port", value("port"));
            push_option(&mut args, "--max-hops", value("max_hops"));
            args
        }
        "dns" => {
            let mut args = vec!["dns".into(), required(value("domain"), "domain")?];
            push_option(&mut args, "--record", value("record"));
            push_option(&mut args, "--server", value("server"));
            args
        }
        "port" => {
            let mut args = vec!["port".into(), required(value("host"), "host")?];
            push_option(&mut args, "--port", value("port"));
            push_option(&mut args, "--timeout", value("timeout_ms"));
            args
        }
        "myip" => vec!["myip".into()],
        "probe" => vec![
            "probe".into(),
            "run".into(),
            required(value("probe_id"), "probe")?,
            required(value("target"), "target")?,
        ],
        "tools" => vec!["tools".into(), "catalog".into()],
        "open-ui" => vec!["open".into(), "ui".into()],
        "tool-status" => vec![
            "tools".into(),
            "status".into(),
            required(value("tool_id"), "tool")?,
        ],
        "tool-lifecycle" => vec![
            "tools".into(),
            "lifecycle".into(),
            required(value("tool_id"), "tool")?,
        ],
        "tool-install" => {
            require_confirmation(value("confirm"))?;
            vec![
                "tools".into(),
                "install".into(),
                required(value("tool_id"), "tool")?,
                "--yes".into(),
            ]
        }
        "tool-update" => {
            require_confirmation(value("confirm"))?;
            vec![
                "tools".into(),
                "update".into(),
                required(value("tool_id"), "tool")?,
                "--yes".into(),
            ]
        }
        "globalping" => {
            let measurement = match value("measurement") {
                Some("trace") => "traceroute",
                Some(measurement) => measurement,
                None => "ping",
            };
            let mut args = vec![
                "remote".into(),
                "globalping".into(),
                measurement.into(),
                required(value("target"), "target")?,
            ];
            push_option(&mut args, "--location", value("location"));
            args.push("--yes".into());
            args
        }
        "remote-port" => {
            let mut args = vec![
                "remote".into(),
                "port".into(),
                required(value("target"), "target")?,
            ];
            push_option(&mut args, "--port", value("port"));
            args.push("--yes".into());
            args
        }
        "capture" => {
            let mut args = vec!["capture".into(), "run".into()];
            push_option(&mut args, "--interface", value("interface_id"));
            push_option(&mut args, "--duration", value("duration_seconds"));
            push_option(&mut args, "--packets", value("packet_limit"));
            args.push("--yes".into());
            args
        }
        "capture-status" => vec!["capture".into(), "status".into()],
        "capture-interfaces" => vec!["capture".into(), "interfaces".into()],
        "capture-open" => vec![
            "capture".into(),
            "open".into(),
            required(value("path"), "capture path")?,
        ],
        "inventory" => vec!["inventory".into()],
        "monitor" => {
            let mut args = vec![
                "monitor".into(),
                "start".into(),
                required(value("target"), "target")?,
            ];
            push_option(&mut args, "--interval", value("interval_seconds"));
            push_option(&mut args, "--latency", value("latency_alert_ms"));
            push_option(&mut args, "--loss", value("loss_alert_percent"));
            args.push("--yes".into());
            args
        }
        "monitor-list" => vec!["monitor".into(), "list".into()],
        "monitor-stop" => vec![
            "monitor".into(),
            "stop".into(),
            required(value("monitor_id"), "monitor ID")?,
        ],
        "timeline" => vec!["timeline".into(), "list".into()],
        "timeline-clear" => {
            require_confirmation(value("confirm"))?;
            vec!["timeline".into(), "clear".into(), "--yes".into()]
        }
        "history" => vec!["history".into(), "list".into()],
        "history-get" => vec![
            "history".into(),
            "get".into(),
            required(value("run_id"), "run ID")?,
        ],
        "history-compare" => vec![
            "history".into(),
            "compare".into(),
            required(value("left_id"), "earlier run ID")?,
            required(value("right_id"), "later run ID")?,
        ],
        "history-delete" => {
            require_confirmation(value("confirm"))?;
            vec![
                "history".into(),
                "delete".into(),
                required(value("run_id"), "run ID")?,
                "--yes".into(),
            ]
        }
        id if id.starts_with("scanner.") => {
            let tool_id = id.trim_start_matches("scanner.");
            let mut args = vec![
                "scanner".into(),
                "run".into(),
                tool_id.into(),
                required(value("target"), "target")?,
            ];
            if let Some(profile) = value("profile") {
                args.extend(["--profile".into(), cli_profile(profile)?.into()]);
            }
            if matches!(tool_id, "nmap" | "naabu") {
                let ports = match value("ports") {
                    Some("custom") => required(value("custom_ports"), "custom ports")?,
                    Some(ports) => ports.into(),
                    None => "top".into(),
                };
                args.extend(["--ports".into(), ports]);
            }
            args.push("--yes".into());
            args
        }
        _ => {
            return Err(format!(
                "{} is not executable in the terminal adapter yet",
                namespace.label
            ))
        }
    };
    Ok(args)
}

fn required(value: Option<&str>, label: &str) -> Result<String, String> {
    value
        .map(str::to_string)
        .ok_or_else(|| format!("{label} is required"))
}

fn require_confirmation(value: Option<&str>) -> Result<(), String> {
    if value == Some("yes") {
        Ok(())
    } else {
        Err("select Yes to explicitly confirm this action".into())
    }
}

fn push_option(args: &mut Vec<String>, option: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.extend([option.into(), value.into()]);
    }
}

fn cli_profile(profile: &str) -> Result<&'static str, String> {
    match profile {
        "default" => Ok("default"),
        "nmap_top_ports" => Ok("fast"),
        "nmap_version" => Ok("version"),
        "nmap_service_deep" => Ok("deep"),
        "nmap_udp_quick" => Ok("udp_quick"),
        "nuclei_safe" => Ok("safe"),
        "nuclei_http_exposure" => Ok("http_exposure"),
        "nuclei_known_vulns" => Ok("known_vulns"),
        "nuclei_full" => Ok("full"),
        other => Err(format!("unknown scanner profile {other}")),
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub fn run() -> anyhow::Result<()> {
    let catalog = ToolCatalog::phase_zero_defaults().interaction_catalog();
    catalog.validate().map_err(|error| anyhow::anyhow!(error))?;
    let operations = OperationsService::new(default_app_data_dir());
    let mut state = TuiState::new(catalog);
    if let Err(error) = operations.resume_monitors() {
        state.push_output(
            TranscriptKind::Warning,
            format!("Could not resume monitors: {error}"),
        );
    }
    let mut terminal = ratatui::init();
    let _guard = TerminalGuard;
    run_loop(&mut terminal, state, operations)
}

fn run_loop(
    terminal: &mut DefaultTerminal,
    mut state: TuiState,
    operations: OperationsService,
) -> anyhow::Result<()> {
    let mut runner = ProcessRunner::new();
    let (sender, receiver) = mpsc::channel();
    spawn_terminal_reader(sender.clone());
    let mut frames = FramePacer::new(60);
    frames.request();

    loop {
        if frames.should_render() {
            terminal.draw(|frame| render(frame, &state))?;
            frames.rendered();
            continue;
        }

        let event = if let Some(timeout) = frames.wait_timeout() {
            match receiver.recv_timeout(timeout) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("terminal event channel disconnected")
                }
            }
        } else {
            receiver
                .recv()
                .map_err(|_| anyhow::anyhow!("terminal event channel disconnected"))?
        };

        match event {
            UiEvent::Terminal(Event::Key(key)) => {
                if let Some(action) = state.handle_key(key) {
                    match action {
                        TuiAction::Quit => {
                            if state.running {
                                state.status = "Stop the active operation before exiting.".into();
                            } else {
                                return Ok(());
                            }
                        }
                        TuiAction::Cancel => match runner.cancel() {
                            Ok(()) => state.status = "Cancellation requested.".into(),
                            Err(error) => state.status = format!("Cancellation failed: {error:#}"),
                        },
                        TuiAction::RefreshStatus(tool_id) => {
                            refresh_tool_status(&mut state, &tool_id)
                        }
                        TuiAction::Install(tool_id) => start_operation(
                            &mut runner,
                            &mut state,
                            vec!["tools".into(), "install".into(), tool_id, "--yes".into()],
                            &sender,
                        ),
                        TuiAction::Update(tool_id) => start_operation(
                            &mut runner,
                            &mut state,
                            vec!["tools".into(), "update".into(), tool_id, "--yes".into()],
                            &sender,
                        ),
                        TuiAction::Run(args) => {
                            start_operation(&mut runner, &mut state, args, &sender)
                        }
                    }
                }
            }
            UiEvent::Terminal(_) => {}
            UiEvent::TerminalError(error) => {
                anyhow::bail!("terminal input failed: {error}");
            }
            UiEvent::Runner(event) => {
                if runner.handle_event(&mut state, event) {
                    if let Err(error) = operations.resume_monitors() {
                        state.push_output(
                            TranscriptKind::Warning,
                            format!("Could not refresh monitors: {error}"),
                        );
                    }
                }
            }
        }
        frames.request();
    }
}

fn start_operation(
    runner: &mut ProcessRunner,
    state: &mut TuiState,
    args: Vec<String>,
    sender: &mpsc::Sender<UiEvent>,
) {
    state.clear_output();
    state.push_output(
        TranscriptKind::Command,
        format!("sonarnwork {}", args.join(" ")),
    );
    match runner.start(args, sender.clone()) {
        Ok(()) => {
            state.running = true;
            state.status = "Running… F6 or Ctrl+C cancels.".into();
        }
        Err(error) => state.status = format!("Could not start operation: {error:#}"),
    }
}

fn refresh_tool_status(state: &mut TuiState, tool_id: &str) {
    let catalog = ToolCatalog::phase_zero_defaults();
    match (
        catalog.runtime_status(tool_id),
        catalog.lifecycle_plan(tool_id),
    ) {
        (Ok(runtime), Ok(lifecycle)) => {
            state.clear_output();
            state.push_output(TranscriptKind::Status, format!("{tool_id} package"));
            state.push_output(
                TranscriptKind::Status,
                format!(
                    "Status: {}",
                    if runtime.available {
                        "installed"
                    } else {
                        "not installed"
                    }
                ),
            );
            if let Some(version) = runtime.version {
                state.push_output(TranscriptKind::Status, format!("Version: {version}"));
            }
            if let Some(executable) = runtime.executable {
                state.push_output(
                    TranscriptKind::Status,
                    format!("Path: {}", executable.display()),
                );
            }
            if let Some(error) = runtime.error {
                state.push_output(TranscriptKind::Warning, format!("Detection: {error}"));
            }
            state.push_output(
                TranscriptKind::Status,
                format!("Lifecycle: {:?}", lifecycle.install_strategy),
            );
            state.push_output(TranscriptKind::Status, lifecycle.note);
            state.status = "F2 refresh · F3 install · F4 update · F5 run".into();
        }
        (Err(error), _) | (_, Err(error)) => state.status = format!("Tool status failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn state() -> TuiState {
        TuiState::new(ToolCatalog::phase_zero_defaults().interaction_catalog())
    }

    fn select(state: &mut TuiState, trigger: &str) {
        state.handle_key(key(KeyCode::Char('/')));
        for character in trigger.trim_start_matches('/').chars() {
            state.handle_key(key(KeyCode::Char(character)));
        }
        state.handle_key(key(KeyCode::Enter));
    }

    #[test]
    fn slash_filters_and_selects_a_contextual_plugin_form() {
        let mut state = state();
        select(&mut state, "/nmap");

        assert_eq!(state.mode, InputMode::Form);
        assert_eq!(state.selected_namespace_id.as_deref(), Some("scanner.nmap"));
        assert!(state
            .visible_fields()
            .iter()
            .any(|field| field.id == "ports"));
        assert_eq!(
            state.values.get("profile").map(String::as_str),
            Some("nmap_top_ports")
        );
    }

    #[test]
    fn open_ui_palette_entry_routes_to_the_desktop_command() {
        let mut state = state();
        state.handle_key(key(KeyCode::Char('/')));
        for character in "open ui".chars() {
            state.handle_key(key(KeyCode::Char(character)));
        }
        let action = state.handle_key(key(KeyCode::Enter));
        assert_eq!(state.selected_namespace_id.as_deref(), Some("open-ui"));
        assert!(matches!(
            action,
            Some(TuiAction::Run(args)) if args == vec!["open".to_string(), "ui".to_string()]
        ));
    }

    #[test]
    fn selected_non_default_nmap_profile_survives_command_routing() {
        let mut state = state();
        select(&mut state, "/nmap");
        state
            .values
            .insert("target".into(), "192.168.1.0/24".into());
        state
            .values
            .insert("profile".into(), "nmap_service_deep".into());
        state.values.insert("ports".into(), "all".into());
        state.scope_confirmed = true;

        let args = state.prepare_run().unwrap();

        assert!(args.windows(2).any(|pair| pair == ["--profile", "deep"]));
        assert!(args.windows(2).any(|pair| pair == ["--ports", "all"]));
    }

    #[test]
    fn nuclei_form_requires_authorization_and_has_no_ports() {
        let mut state = state();
        select(&mut state, "/nuclei");
        state
            .values
            .insert("target".into(), "https://example.com".into());

        assert!(!state
            .visible_fields()
            .iter()
            .any(|field| field.id == "ports"));
        assert!(state.prepare_run().unwrap_err().contains("authorized"));
    }

    #[test]
    fn renderer_places_form_and_command_line_in_the_terminal() {
        let mut state = state();
        select(&mut state, "/nmap");
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &state)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("Nmap"));
        assert!(rendered.contains("Scan profile"));
        assert!(rendered.contains("Selected namespace"));
    }

    #[test]
    fn renderer_is_stable_at_compact_standard_and_wide_terminal_sizes() {
        let mut state = state();
        select(&mut state, "/nmap");
        state.clear_output();
        state.push_output(TranscriptKind::Command, "sonarnwork scanner run nmap");
        state.push_output(TranscriptKind::Stderr, "permission denied");

        for (width, height) in [(60, 20), (80, 24), (120, 40)] {
            let rendered = render_to_string(&state, width, height);
            assert!(
                rendered.contains("SONARNWORK"),
                "missing header at {width}x{height}"
            );
            assert!(
                rendered.contains("Nmap"),
                "missing form at {width}x{height}"
            );
            assert!(
                rendered.contains("Output / status"),
                "missing transcript pane at {width}x{height}"
            );
            assert!(
                rendered.contains("permission denied"),
                "missing stderr tail at {width}x{height}"
            );
        }
    }

    #[test]
    fn scrolled_transcript_exposes_the_truncation_marker_and_end_follows_tail() {
        let mut state = state();
        select(&mut state, "/nmap");
        state.clear_output();
        for index in 0..=transcript::DEFAULT_MAX_LINES {
            state.push_output(TranscriptKind::Stdout, format!("line {index}"));
        }
        state.scroll_output_up(usize::MAX / 2);

        let rendered = render_to_string(&state, 80, 24);
        assert!(rendered.contains("older output was truncated"));
        assert!(!state.output_follow_tail);

        state.follow_output_tail();
        assert!(state.output_follow_tail);
        assert_eq!(state.output_scroll_from_bottom, 0);
        let rendered = render_to_string(&state, 80, 24);
        assert!(rendered.contains("line 2000"));
    }

    fn render_to_string(state: &TuiState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn every_catalog_namespace_has_a_terminal_adapter() {
        let catalog = ToolCatalog::phase_zero_defaults().interaction_catalog();
        for namespace in &catalog.namespaces {
            let mut values = BTreeMap::new();
            for field in &namespace.fields {
                let fallback = match field.kind {
                    InteractionFieldKind::Target => "example.com",
                    InteractionFieldKind::Text if field.id == "probe_id" => "connectivity.ping",
                    InteractionFieldKind::Text if field.id == "interface_id" => "1",
                    InteractionFieldKind::Text => "80",
                    InteractionFieldKind::Integer if field.id == "port" => "443",
                    InteractionFieldKind::Integer if field.id == "interval_seconds" => "30",
                    InteractionFieldKind::Integer => "10",
                    InteractionFieldKind::Choice => field
                        .choices
                        .first()
                        .map(|choice| choice.value.as_str())
                        .unwrap_or("default"),
                    InteractionFieldKind::Toggle => "true",
                    InteractionFieldKind::Ports => "80,443",
                };
                values.insert(
                    field.id.clone(),
                    if field.id == "confirm" {
                        "yes".into()
                    } else {
                        field
                            .default_value
                            .clone()
                            .unwrap_or_else(|| fallback.into())
                    },
                );
            }

            assert!(
                interaction_args(namespace, &values).is_ok(),
                "missing terminal adapter for {}",
                namespace.id
            );
        }
    }

    #[test]
    fn destructive_palette_actions_default_to_not_confirmed() {
        let namespace = ToolCatalog::phase_zero_defaults()
            .interaction_catalog()
            .namespace("timeline-clear")
            .unwrap()
            .clone();
        let values = BTreeMap::from([("confirm".into(), "no".into())]);
        assert!(interaction_args(&namespace, &values)
            .unwrap_err()
            .contains("explicitly confirm"));

        let values = BTreeMap::from([("confirm".into(), "yes".into())]);
        assert_eq!(
            interaction_args(&namespace, &values).unwrap(),
            vec!["timeline", "clear", "--yes"]
        );
    }
}
