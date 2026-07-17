use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Wrap,
};
use ratatui::Frame;
use sonar_core::{InteractionFieldKind, InteractionNamespace};

use super::transcript::{TranscriptEntry, TranscriptKind};
use super::{InputMode, TuiState};
use crate::CLI_BANNER;

const BRAND: Color = Color::Rgb(34, 211, 238);
const COMMAND: Color = Color::Rgb(251, 191, 36);
const SUCCESS: Color = Color::Rgb(74, 222, 128);
const WARNING: Color = Color::Rgb(251, 191, 36);
const ERROR: Color = Color::Rgb(251, 113, 133);
const MUTED: Color = Color::Rgb(148, 163, 184);
const BORDER: Color = Color::Rgb(71, 85, 105);

pub(super) fn render(frame: &mut Frame, state: &TuiState) {
    let compact = frame.area().width < 80;
    let [header, workspace, input, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    let mut header_spans = vec![
        Span::styled(
            " SONARNWORK ",
            Style::new()
                .fg(Color::Black)
                .bg(BRAND)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  CLI CONSOLE",
            Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ];
    if !compact {
        header_spans.push(Span::styled(
            "  shared Rust core · guided workflows",
            Style::new().fg(MUTED),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(header_spans))
            .block(Block::bordered().border_style(Style::new().fg(BORDER))),
        header,
    );

    if state.mode == InputMode::Palette {
        let [palette, preview] =
            Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)])
                .areas(workspace);
        render_palette(frame, state, palette);
        render_namespace_form(frame, state.preview_namespace(), state, preview, true);
    } else if let Some(namespace) = state.selected_namespace() {
        let [form, output] =
            Layout::vertical([Constraint::Percentage(62), Constraint::Percentage(38)])
                .areas(workspace);
        render_namespace_form(frame, Some(namespace), state, form, false);
        render_output(frame, state, output, "Console output");
    } else if state.show_welcome {
        render_welcome(frame, workspace);
    } else {
        render_output(frame, state, workspace, "Console output");
    }

    let input_title = match state.mode {
        InputMode::Command => " Command · Enter runs ",
        InputMode::Palette => " Workflow search · Enter opens form ",
        InputMode::Form => " Selected workflow ",
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " sonar ",
                Style::new()
                    .fg(Color::Black)
                    .bg(BRAND)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" > ", Style::new().fg(MUTED)),
            Span::styled(&state.command_input, Style::new().fg(COMMAND)),
        ]))
        .block(
            Block::bordered()
                .title(input_title)
                .border_style(Style::new().fg(if state.mode == InputMode::Form {
                    BORDER
                } else {
                    BRAND
                })),
        ),
        input,
    );
    if matches!(state.mode, InputMode::Command | InputMode::Palette) {
        let cursor_x = input
            .x
            .saturating_add(11)
            .saturating_add(u16::try_from(state.command_input.chars().count()).unwrap_or(u16::MAX));
        frame.set_cursor_position(Position::new(
            cursor_x.min(input.right().saturating_sub(2)),
            input.y + 1,
        ));
    }

    let hints = match (compact, state.mode) {
        (true, InputMode::Command) => "Enter run · / workflows · F10 exit",
        (true, InputMode::Palette) => "Type filter · ↑↓ choose · Enter open · Esc",
        (true, InputMode::Form) => "Tab fields · Enter run · F6 stop · Esc",
        (false, InputMode::Command) => "Enter run · / or Ctrl+P workflows · Tab search · F10 exit",
        (false, InputMode::Palette) => "Type filter · ↑↓ choose · Enter/Tab open · Esc console",
        (false, InputMode::Form) => {
            "Tab fields · ←→ choices · Enter/F5 run · F6 stop · Esc console"
        }
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    if state.running {
                        " RUNNING "
                    } else {
                        " READY "
                    },
                    Style::new()
                        .fg(Color::Black)
                        .bg(if state.running { WARNING } else { SUCCESS })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(&state.status, Style::new().fg(Color::Reset)),
            ]),
            Line::styled(hints, Style::new().fg(MUTED)),
        ]),
        footer,
    );
}

fn render_welcome(frame: &mut Frame, area: Rect) {
    let block = Block::bordered()
        .title(" SonarNwork CLI ")
        .border_style(Style::new().fg(BORDER));
    let inner = block.inner(area);
    let mut lines = Vec::new();
    if inner.width >= 72 && inner.height >= 10 {
        lines.extend(
            CLI_BANNER.lines().map(|line| {
                Line::styled(line, Style::new().fg(BRAND).add_modifier(Modifier::BOLD))
            }),
        );
        lines.push(Line::from(""));
    } else {
        lines.push(Line::styled(
            "SONARNWORK",
            Style::new().fg(BRAND).add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(
        "Interactive CLI console",
        Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::styled(
        "Type canonical commands without the program name. Use / for guided workflows.",
        Style::new().fg(MUTED),
    ));
    lines.push(Line::from(vec![
        Span::styled("Try  ", Style::new().fg(BRAND)),
        Span::styled(
            "ping 1.1.1.1  ·  myip  ·  scanner run nmap <target>",
            Style::new().fg(COMMAND),
        ),
    ]));

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_palette(frame: &mut Frame, state: &TuiState, area: Rect) {
    let items = state
        .filtered_indices()
        .into_iter()
        .filter_map(|index| state.catalog.namespaces.get(index))
        .map(|namespace| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    namespace.trigger.trim_start_matches('/'),
                    Style::new().fg(COMMAND).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(&namespace.label, Style::new().fg(Color::Reset)),
            ]))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(state.palette_selection.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" Workflows · / shortcut ")
                .border_style(Style::new().fg(BRAND)),
        )
        .highlight_symbol("› ")
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(BRAND)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_namespace_form(
    frame: &mut Frame,
    namespace: Option<&InteractionNamespace>,
    state: &TuiState,
    area: Rect,
    preview: bool,
) {
    let Some(namespace) = namespace else {
        frame.render_widget(
            Paragraph::new("No command matches this filter.")
                .block(Block::bordered().title("Preview")),
            area,
        );
        return;
    };
    let cli_preview = state.cli_preview(namespace, preview);
    let mut lines = vec![
        Line::styled(
            format!(
                "{}  {}",
                namespace.trigger.trim_start_matches('/'),
                namespace.label
            ),
            Style::new().fg(BRAND).add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            namespace.description.as_str(),
            Style::new().fg(Color::Reset),
        ),
        Line::styled(
            format!("Risk: {:?}", namespace.action_class),
            Style::new().fg(MUTED),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled("CLI  ", Style::new().fg(BRAND).add_modifier(Modifier::BOLD)),
            Span::styled("$ ", Style::new().fg(MUTED)),
            Span::styled(cli_preview, Style::new().fg(COMMAND)),
        ]),
        Line::from(""),
    ];
    let fields = if preview {
        namespace.fields.iter().collect::<Vec<_>>()
    } else {
        state.visible_fields()
    };
    let mut focused_line = None;
    for (index, field) in fields.iter().enumerate() {
        let focused = !preview && state.focused_field == index;
        let value = if preview {
            field.default_value.as_deref().unwrap_or("")
        } else {
            state.values.get(&field.id).map_or("", String::as_str)
        };
        let display = if field.kind == InteractionFieldKind::Choice {
            field
                .choices
                .iter()
                .find(|choice| choice.value == value)
                .map_or(value, |choice| choice.label.as_str())
        } else if value.is_empty() {
            field.placeholder.as_deref().unwrap_or("")
        } else {
            value
        };
        if focused {
            focused_line = Some(lines.len());
        }
        lines.push(Line::from(vec![
            Span::styled(if focused { "› " } else { "  " }, Style::new().fg(BRAND)),
            Span::styled(
                format!("{}: ", field.label),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                display,
                if value.is_empty() {
                    Style::new().fg(MUTED)
                } else {
                    Style::new().fg(Color::Reset)
                },
            ),
        ]));
        if focused {
            lines.push(Line::styled(
                format!("    {}", field.help),
                Style::new().fg(MUTED),
            ));
            focused_line = Some(lines.len() - 1);
        }
    }
    if !namespace.examples.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Workflow shortcuts",
            Style::new().fg(BRAND).add_modifier(Modifier::BOLD),
        ));
        lines.extend(
            namespace
                .examples
                .iter()
                .map(|example| Line::styled(example, Style::new().fg(COMMAND))),
        );
    }
    let title = if preview {
        format!(" Workflow preview · {} ", namespace.label)
    } else {
        format!(" Workflow · {} ", namespace.label)
    };
    let block = Block::bordered()
        .title(title)
        .border_style(Style::new().fg(if preview { BORDER } else { BRAND }));
    let inner = block.inner(area);
    let scroll = focused_line.map_or(0, |focused_line| {
        let width = usize::from(inner.width.max(1));
        let rows_through_focus = lines[..=focused_line]
            .iter()
            .map(|line| line.width().max(1).div_ceil(width))
            .sum::<usize>();
        rows_through_focus.saturating_sub(usize::from(inner.height.max(1)))
    });
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0)),
        area,
    );
}

fn render_output(frame: &mut Frame, state: &TuiState, area: Rect, title: &str) {
    let block = Block::bordered()
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(
                format!(" {title} "),
                Style::new().fg(BRAND).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if state.output_follow_tail {
                    "  [following tail]"
                } else {
                    "  [scrolled · End returns to tail]"
                },
                Style::new().fg(MUTED),
            ),
        ]));
    let inner = block.inner(area);
    let text = transcript_text(state);
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    let total_rows = transcript_row_count(state, inner.width).max(1);
    let viewport_rows = usize::from(inner.height.max(1));
    let max_scroll = total_rows.saturating_sub(viewport_rows);
    let offset = max_scroll.saturating_sub(state.output_scroll_from_bottom.min(max_scroll));
    let paragraph = paragraph.scroll((u16::try_from(offset).unwrap_or(u16::MAX), 0));
    frame.render_widget(paragraph, area);

    if total_rows > viewport_rows && area.width > 2 && area.height > 2 {
        let mut scrollbar_state = ScrollbarState::new(total_rows)
            .position(offset)
            .viewport_content_length(viewport_rows);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn transcript_text(state: &TuiState) -> Text<'_> {
    let marker = state.output.was_truncated().then(|| {
        Line::styled(
            "… older output was truncated to protect memory …",
            Style::new().fg(WARNING),
        )
    });
    Text::from(
        marker
            .into_iter()
            .chain(state.output.iter().map(transcript_line))
            .collect::<Vec<_>>(),
    )
}

fn transcript_line(entry: &TranscriptEntry) -> Line<'_> {
    let (prefix, style) = match entry.kind {
        TranscriptKind::Command => ("$ ", Style::new().fg(COMMAND).add_modifier(Modifier::BOLD)),
        TranscriptKind::Stdout => ("", Style::new().fg(Color::Reset)),
        TranscriptKind::Stderr => ("! ", Style::new().fg(ERROR)),
        TranscriptKind::Warning => ("! ", Style::new().fg(WARNING)),
        TranscriptKind::Status => ("· ", Style::new().fg(MUTED)),
    };
    Line::styled(format!("{prefix}{}", entry.text), style)
}

fn transcript_row_count(state: &TuiState, width: u16) -> usize {
    let width = usize::from(width.max(1));
    let marker_rows = usize::from(state.output.was_truncated())
        * "… older output was truncated to protect memory …"
            .chars()
            .count()
            .max(1)
            .div_ceil(width);
    marker_rows
        + state
            .output
            .iter()
            .map(|entry| {
                let prefix_chars = match entry.kind {
                    TranscriptKind::Command
                    | TranscriptKind::Stderr
                    | TranscriptKind::Warning
                    | TranscriptKind::Status => 2,
                    TranscriptKind::Stdout => 0,
                };
                entry
                    .text
                    .chars()
                    .count()
                    .saturating_add(prefix_chars)
                    .max(1)
                    .div_ceil(width)
            })
            .sum::<usize>()
}
