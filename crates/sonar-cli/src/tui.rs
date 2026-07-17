use std::collections::BTreeMap;
use std::sync::mpsc::{self, RecvTimeoutError};

use ratatui::crossterm::{
    event::{
        DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
};
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
    SelfUpdate(Vec<String>),
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
    output: BoundedTranscript,
    output_scroll_from_bottom: usize,
    output_follow_tail: bool,
    show_welcome: bool,
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
            output: {
                let mut output = BoundedTranscript::with_defaults();
                output.push(
                    TranscriptKind::Status,
                    "Type a Sonar command directly, without the program name.",
                );
                output.push(
                    TranscriptKind::Status,
                    "Use / or Ctrl+P to browse guided workflows and plugin forms.",
                );
                output
            },
            output_scroll_from_bottom: 0,
            output_follow_tail: true,
            show_welcome: true,
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
        let needle = normalized_palette_query(&self.command_input);
        self.catalog
            .namespaces
            .iter()
            .enumerate()
            .filter(|(_, namespace)| {
                needle.is_empty()
                    || trigger_text(&namespace.trigger).contains(&needle)
                    || namespace.label.to_ascii_lowercase().contains(&needle)
                    || namespace
                        .aliases
                        .iter()
                        .any(|alias| trigger_text(alias).contains(&needle))
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
    }

    fn open_palette(&mut self) {
        if self.running {
            self.status = "Stop the active operation before changing workflows.".into();
            return;
        }
        self.mode = InputMode::Palette;
        self.command_input.clear();
        self.palette_selection = 0;
        self.selected_namespace_id = None;
        self.values.clear();
        self.focused_field = 0;
        self.status = "Search workflows by name; / is optional.".into();
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
        self.select_namespace(index)
    }

    fn select_namespace(&mut self, index: usize) -> Option<TuiAction> {
        if self.running {
            self.status = "Stop the active operation before changing workflows.".into();
            return None;
        }
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
        self.command_input = trigger_text(&namespace.trigger).to_string();
        self.focused_field = 0;
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

    fn exact_namespace_index(&self, input: &str) -> Option<usize> {
        let needle = normalized_palette_query(input);
        if needle.is_empty() {
            return None;
        }
        self.catalog.namespaces.iter().position(|namespace| {
            trigger_text(&namespace.trigger) == needle
                || namespace.label.to_ascii_lowercase() == needle
                || namespace
                    .aliases
                    .iter()
                    .any(|alias| trigger_text(alias) == needle)
        })
    }

    fn cli_preview(&self, namespace: &InteractionNamespace, preview: bool) -> String {
        let mut values =
            if !preview && self.selected_namespace_id.as_deref() == Some(namespace.id.as_str()) {
                self.values.clone()
            } else {
                namespace
                    .fields
                    .iter()
                    .filter_map(|field| {
                        field
                            .default_value
                            .as_ref()
                            .map(|value| (field.id.clone(), value.clone()))
                    })
                    .collect()
            };

        for field in &namespace.fields {
            if preview && field.id == "confirm" {
                values.insert(field.id.clone(), "yes".into());
            } else if field.required
                && values
                    .get(&field.id)
                    .is_none_or(|value| value.trim().is_empty())
            {
                values.insert(
                    field.id.clone(),
                    format!("<{}>", field.id.replace('_', "-")),
                );
            }
        }

        interaction_args(namespace, &values)
            .map(|args| format_cli_command(&args))
            .unwrap_or_else(|_| format!("sonar {}", trigger_text(&namespace.trigger)))
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

    fn current_tool_id(&self) -> Option<String> {
        self.selected_namespace_id
            .as_deref()
            .and_then(|id| id.strip_prefix("scanner."))
            .map(str::to_string)
    }

    fn close_form(&mut self) {
        self.mode = InputMode::Command;
        self.command_input.clear();
        self.selected_namespace_id = None;
        self.values.clear();
        self.focused_field = 0;
        self.status = "Type a command, or press / or Ctrl+P for workflows.".into();
    }

    fn handle_paste(&mut self, text: &str) {
        let text = single_line_paste(text);
        if text.is_empty() {
            return;
        }
        match self.mode {
            InputMode::Command | InputMode::Palette => self.command_input.push_str(&text),
            InputMode::Form => {
                for character in text.chars() {
                    self.edit_current(character);
                }
            }
        }
        self.palette_selection = 0;
    }

    fn submit_command(&mut self) -> Option<TuiAction> {
        if self.running {
            self.status = "Stop the active operation before starting another command.".into();
            return None;
        }

        let line = self.command_input.trim().to_string();
        let args = match direct_command_args(&line) {
            Ok(args) => args,
            Err(error) => {
                self.status = error;
                return None;
            }
        };
        if args.len() == 1 {
            match args[0].to_ascii_lowercase().as_str() {
                "exit" | "quit" => return Some(TuiAction::Quit),
                "clear" | "cls" => {
                    self.clear_output();
                    self.show_welcome = true;
                    self.command_input.clear();
                    self.status = "Console cleared.".into();
                    return None;
                }
                "help" | "?" => {
                    self.command_input.clear();
                    return Some(TuiAction::Run(vec!["--help".into()]));
                }
                _ => {}
            }
        }

        match super::parse_shell_command(&line) {
            Ok(Some(_)) => {}
            Ok(None) => {
                self.status = "Type a command after the program name.".into();
                return None;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) => {}
            Err(error) => {
                if let Some(index) = self.exact_namespace_index(&line) {
                    return self.select_namespace(index);
                }
                self.clear_output();
                self.push_output(
                    TranscriptKind::Warning,
                    error.to_string().trim().to_string(),
                );
                self.status = "Invalid command. Review the CLI error in the console.".into();
                return None;
            }
        }

        self.command_input.clear();
        if args
            .first()
            .is_some_and(|arg| arg.eq_ignore_ascii_case("update"))
            && args.iter().any(|arg| arg == "--yes")
        {
            Some(TuiAction::SelfUpdate(args))
        } else {
            Some(TuiAction::Run(args))
        }
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
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('p') | KeyCode::Char('P'))
        {
            self.open_palette();
            return None;
        }
        match key.code {
            KeyCode::F(10) => return Some(TuiAction::Quit),
            KeyCode::F(2) if !self.running => {
                return self.current_tool_id().map(TuiAction::RefreshStatus)
            }
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
                KeyCode::Char('/')
                    if self.command_input.is_empty()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.open_palette()
                }
                KeyCode::Enter => return self.submit_command(),
                KeyCode::Backspace => {
                    self.command_input.pop();
                }
                KeyCode::Esc => {
                    self.command_input.clear();
                    self.status = "Command cleared.".into();
                }
                KeyCode::Tab => {
                    if self.running {
                        self.status = "Stop the active operation before changing workflows.".into();
                    } else {
                        self.mode = InputMode::Palette;
                        self.palette_selection = 0;
                        self.status = "Search workflows by name; Enter opens the form.".into();
                    }
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.command_input.push(character);
                }
                _ => {}
            },
            InputMode::Palette => match key.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Command;
                    self.command_input.clear();
                    self.status = "Workflow browser closed; direct command input is active.".into();
                }
                KeyCode::Down => self.move_palette(1),
                KeyCode::Up => self.move_palette(-1),
                KeyCode::Enter | KeyCode::Tab => return self.select_palette(),
                KeyCode::Backspace => {
                    self.command_input.pop();
                    self.palette_selection = 0;
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.command_input.push(character);
                    self.palette_selection = 0;
                }
                _ => {}
            },
            InputMode::Form => match key.code {
                KeyCode::Esc => self.close_form(),
                KeyCode::Tab => self.move_focus(1),
                KeyCode::BackTab => self.move_focus(-1),
                KeyCode::Left => self.cycle_choice(-1),
                KeyCode::Right => self.cycle_choice(1),
                KeyCode::Backspace => self.backspace_current(),
                KeyCode::Enter if !self.running => return self.prepared_action(),
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.edit_current(character)
                }
                _ => {}
            },
        }
        None
    }

    fn prepared_action(&mut self) -> Option<TuiAction> {
        match self.prepare_run() {
            Ok(args) if self.selected_namespace_id.as_deref() == Some("app-update") => {
                Some(TuiAction::SelfUpdate(args))
            }
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
        interaction_args(namespace, &self.values)
    }

    fn clear_output(&mut self) {
        self.output.clear();
        self.follow_output_tail();
    }

    fn push_output(&mut self, kind: TranscriptKind, line: impl Into<String>) {
        self.show_welcome = false;
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

fn trigger_text(trigger: &str) -> String {
    trigger.trim_start_matches('/').to_ascii_lowercase()
}

fn normalized_palette_query(input: &str) -> String {
    let query = input
        .trim()
        .trim_start_matches('/')
        .trim()
        .to_ascii_lowercase();
    query
        .strip_prefix("sonarnwork ")
        .or_else(|| query.strip_prefix("sonar "))
        .unwrap_or(&query)
        .trim()
        .to_string()
}

fn direct_command_args(input: &str) -> Result<Vec<String>, String> {
    let mut args = super::split_shell_line(input)?;
    if args.first().is_some_and(|arg| {
        arg.eq_ignore_ascii_case("sonar") || arg.eq_ignore_ascii_case("sonarnwork")
    }) {
        args.remove(0);
    }
    if args.is_empty() {
        Err("Type a command, for example: ping 1.1.1.1".into())
    } else {
        Ok(args)
    }
}

fn single_line_paste(text: &str) -> String {
    text.chars()
        .filter_map(|character| match character {
            '\r' | '\n' | '\t' => Some(' '),
            character if character.is_control() => None,
            character => Some(character),
        })
        .collect()
}

fn format_cli_command(args: &[String]) -> String {
    std::iter::once("sonar".to_string())
        .chain(args.iter().map(|arg| format_cli_arg(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_cli_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\'' | '"'))
    {
        return arg.to_string();
    }

    let mut escaped = String::with_capacity(arg.len() + 2);
    escaped.push('"');
    let mut pending_backslashes = 0usize;
    for character in arg.chars() {
        match character {
            '\\' => pending_backslashes += 1,
            '"' => {
                for _ in 0..(pending_backslashes * 2 + 1) {
                    escaped.push('\\');
                }
                pending_backslashes = 0;
                escaped.push('"');
            }
            character => {
                for _ in 0..pending_backslashes {
                    escaped.push('\\');
                }
                pending_backslashes = 0;
                escaped.push(character);
            }
        }
    }
    for _ in 0..(pending_backslashes * 2) {
        escaped.push('\\');
    }
    escaped.push('"');
    escaped
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
        "app-update" => {
            require_confirmation(value("confirm"))?;
            vec!["update".into(), "--yes".into()]
        }
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
            args
        }
        "remote-port" => {
            let mut args = vec![
                "remote".into(),
                "port".into(),
                required(value("target"), "target")?,
            ];
            push_option(&mut args, "--port", value("port"));
            args
        }
        "capture" => {
            let mut args = vec!["capture".into(), "run".into()];
            push_option(&mut args, "--interface", value("interface_id"));
            push_option(&mut args, "--duration", value("duration_seconds"));
            push_option(&mut args, "--packets", value("packet_limit"));
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
        let _ = execute!(std::io::stdout(), DisableBracketedPaste);
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
    execute!(std::io::stdout(), EnableBracketedPaste)?;
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
                        TuiAction::SelfUpdate(args) => match runner.start(args, sender.clone()) {
                            Ok(()) => return Ok(()),
                            Err(error) => {
                                state.status = format!("Could not start the updater: {error:#}")
                            }
                        },
                        TuiAction::Run(args) => {
                            start_operation(&mut runner, &mut state, args, &sender)
                        }
                    }
                }
            }
            UiEvent::Terminal(Event::Paste(text)) => state.handle_paste(&text),
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
    let command = format_cli_command(&args);
    match runner.start(args, sender.clone()) {
        Ok(()) => {
            state.clear_output();
            state.push_output(TranscriptKind::Command, command);
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

    fn submit(state: &mut TuiState, command: &str) -> Option<TuiAction> {
        for character in command.chars() {
            state.handle_key(key(KeyCode::Char(character)));
        }
        state.handle_key(key(KeyCode::Enter))
    }

    #[test]
    fn direct_cli_commands_run_without_slash_or_program_name() {
        let mut state = state();
        let action = submit(&mut state, "ping 1.1.1.1 --count 2");

        assert!(matches!(
            action,
            Some(TuiAction::Run(args))
                if args == ["ping", "1.1.1.1", "--count", "2"]
        ));
        assert!(state.command_input.is_empty());
    }

    #[test]
    fn direct_cli_accepts_program_prefix_urls_paste_and_windows_paths() {
        let mut direct = state();
        let action = submit(&mut direct, "sonar check https://example.com/a/b");
        assert!(matches!(
            action,
            Some(TuiAction::Run(args))
                if args == ["check", "https://example.com/a/b"]
        ));

        let args = direct_command_args(
            r#"sonarnwork capture open "C:\Program Files\SonarNwork\trace.pcapng""#,
        )
        .unwrap();
        assert_eq!(
            args,
            [
                "capture",
                "open",
                r"C:\Program Files\SonarNwork\trace.pcapng"
            ]
        );
        assert_eq!(
            format_cli_command(&args),
            r#"sonar capture open "C:\Program Files\SonarNwork\trace.pcapng""#
        );
        for argument in ["", r"C:\Temp Folder\", r#"C:\Temp\say "hello".txt"#] {
            let rendered = format_cli_arg(argument);
            assert_eq!(
                super::super::split_shell_line(&rendered).unwrap(),
                [argument],
                "failed to round-trip {rendered}"
            );
        }

        let mut pasted = state();
        pasted.handle_paste("ping 1.1.1.1\r\n--count 2");
        assert!(matches!(
            pasted.handle_key(key(KeyCode::Enter)),
            Some(TuiAction::Run(args)) if args == ["ping", "1.1.1.1", "--count", "2"]
        ));
    }

    #[test]
    fn bare_workflow_names_and_palette_shortcuts_open_forms() {
        let mut direct = state();
        let action = submit(&mut direct, "nmap");
        assert_eq!(direct.mode, InputMode::Form);
        assert_eq!(
            direct.selected_namespace_id.as_deref(),
            Some("scanner.nmap")
        );
        assert!(matches!(action, Some(TuiAction::RefreshStatus(tool)) if tool == "nmap"));

        let mut shortcut = state();
        shortcut.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(shortcut.mode, InputMode::Palette);
        assert!(shortcut.command_input.is_empty());
    }

    #[test]
    fn direct_update_with_confirmation_uses_the_self_update_path() {
        let mut state = state();
        assert!(matches!(
            submit(&mut state, "update --yes"),
            Some(TuiAction::SelfUpdate(args)) if args == ["update", "--yes"]
        ));
    }

    #[test]
    fn an_active_run_blocks_workflow_switching_and_status_refresh() {
        let mut direct = state();
        direct.clear_output();
        direct.push_output(TranscriptKind::Stdout, "active output");
        direct.running = true;

        direct.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(direct.mode, InputMode::Command);
        direct.handle_key(key(KeyCode::Char('/')));
        assert_eq!(direct.mode, InputMode::Command);
        direct.handle_key(key(KeyCode::Tab));
        assert_eq!(direct.mode, InputMode::Command);
        assert!(direct
            .output
            .iter()
            .any(|entry| entry.text == "active output"));

        let mut scanner = state();
        select(&mut scanner, "/nmap");
        scanner.push_output(TranscriptKind::Stdout, "scanner output");
        scanner.running = true;
        assert_eq!(scanner.handle_key(key(KeyCode::F(2))), None);
        assert!(scanner
            .output
            .iter()
            .any(|entry| entry.text == "scanner output"));
    }

    #[test]
    fn target_workflow_preview_and_run_need_no_confirmation() {
        let mut state = state();
        select(&mut state, "/nmap");
        state.values.insert("target".into(), "192.168.1.10".into());
        let preview = state.cli_preview(state.selected_namespace().unwrap(), false);
        assert!(!preview.contains("--yes"));

        let args = state.prepare_run().unwrap();
        assert!(!args.iter().any(|arg| arg == "--yes"));
    }

    #[test]
    fn leaving_a_form_keeps_the_existing_console_visible() {
        let mut state = state();
        select(&mut state, "/ping");
        state.push_output(TranscriptKind::Stdout, "previous result");

        state.handle_key(key(KeyCode::Esc));

        assert_eq!(state.mode, InputMode::Command);
        assert!(!state.show_welcome);
        assert!(render_to_string(&state, 80, 24).contains("previous result"));
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
    fn app_update_routes_to_a_child_process_before_the_tui_exits() {
        let mut state = state();
        select(&mut state, "/update");
        state.values.insert("confirm".into(), "yes".into());

        assert!(matches!(
            state.prepared_action(),
            Some(TuiAction::SelfUpdate(args))
                if args == vec!["update".to_string(), "--yes".to_string()]
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

        let args = state.prepare_run().unwrap();

        assert!(args.windows(2).any(|pair| pair == ["--profile", "deep"]));
        assert!(args.windows(2).any(|pair| pair == ["--ports", "all"]));
    }

    #[test]
    fn nuclei_form_runs_directly_and_has_no_ports() {
        let mut state = state();
        select(&mut state, "/nuclei");
        state
            .values
            .insert("target".into(), "https://example.com".into());

        assert!(!state
            .visible_fields()
            .iter()
            .any(|field| field.id == "ports"));
        assert!(!state
            .prepare_run()
            .unwrap()
            .iter()
            .any(|arg| arg == "--yes"));
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
        assert!(rendered.contains("Selected workflow"));
        assert!(rendered.contains("sonar scanner run nmap"));
    }

    #[test]
    fn compact_form_scrolls_the_focused_field_into_view() {
        let mut state = state();
        select(&mut state, "/nmap");
        state.focused_field = state.focus_count() - 1;

        let rendered = render_to_string(&state, 80, 24);
        assert!(rendered.contains("Ports"));
    }

    #[test]
    fn renderer_is_stable_at_compact_standard_and_wide_terminal_sizes() {
        let mut state = state();
        select(&mut state, "/nmap");
        state.clear_output();
        state.push_output(TranscriptKind::Command, "sonar scanner run nmap");
        state.push_output(TranscriptKind::Stderr, "permission denied");

        for (width, height) in [(60, 20), (80, 24), (120, 40)] {
            let rendered = render_to_string(&state, width, height);
            assert!(
                rendered.contains("SONARNWORK"),
                "missing header at {width}x{height}"
            );
            assert!(
                rendered.to_ascii_lowercase().contains("nmap"),
                "missing form at {width}x{height}:\n{rendered}"
            );
            assert!(
                rendered.contains("Console output"),
                "missing transcript pane at {width}x{height}"
            );
            assert!(
                rendered.contains("permission denied"),
                "missing stderr tail at {width}x{height}"
            );
        }
    }

    #[test]
    fn welcome_renderer_reuses_the_colored_cli_identity() {
        let rendered = render_to_string(&state(), 100, 28);
        assert!(rendered.contains("____   ___"));
        assert!(rendered.contains("Interactive CLI console"));
        assert!(rendered.contains("ping 1.1.1.1"));
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
