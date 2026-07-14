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

pub(super) fn render(frame: &mut Frame, state: &TuiState) {
    let [header, workspace, input, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " SONARNWORK ",
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  shared core · Ratatui TUI · Tauri desktop"),
        ]))
        .block(Block::bordered()),
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
            Layout::vertical([Constraint::Percentage(58), Constraint::Percentage(42)])
                .areas(workspace);
        render_namespace_form(frame, Some(namespace), state, form, false);
        render_output(frame, state, output, "Output / status");
    } else {
        render_output(frame, state, workspace, "Workspace");
    }

    let input_title = match state.mode {
        InputMode::Command => "Command",
        InputMode::Palette => "Command palette",
        InputMode::Form => "Selected namespace",
    };
    frame.render_widget(
        Paragraph::new(format!("> {}", state.command_input))
            .block(Block::bordered().title(input_title)),
        input,
    );
    if matches!(state.mode, InputMode::Command | InputMode::Palette) {
        let cursor_x = input
            .x
            .saturating_add(3)
            .saturating_add(u16::try_from(state.command_input.chars().count()).unwrap_or(u16::MAX));
        frame.set_cursor_position(Position::new(
            cursor_x.min(input.right().saturating_sub(2)),
            input.y + 1,
        ));
    }

    frame.render_widget(
        Paragraph::new(format!(
            "{}  |  / palette · Tab fields · PgUp/PgDn output · End tail · F2 status · F3 install · F4 update · F5 run · F6 stop · F10 exit",
            state.status
        ))
        .style(Style::new().fg(if state.running {
            Color::Yellow
        } else {
            Color::DarkGray
        })),
        footer,
    );
}

fn render_palette(frame: &mut Frame, state: &TuiState, area: Rect) {
    let items = state
        .filtered_indices()
        .into_iter()
        .filter_map(|index| state.catalog.namespaces.get(index))
        .map(|namespace| {
            ListItem::new(Line::from(vec![
                Span::styled(&namespace.trigger, Style::new().fg(Color::Cyan)),
                Span::raw("  "),
                Span::raw(&namespace.label),
            ]))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(state.palette_selection.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(Block::bordered().title("/ commands"))
        .highlight_symbol("› ")
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
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
    let mut lines = vec![
        Line::styled(
            format!("{}  {}", namespace.trigger, namespace.label),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Line::from(namespace.description.as_str()),
        Line::from(format!(
            "Risk: {:?}{}",
            namespace.action_class,
            if namespace.requires_scope_confirmation {
                " · explicit target authorization required"
            } else {
                ""
            }
        )),
        Line::from(""),
    ];
    let fields = if preview {
        namespace.fields.iter().collect::<Vec<_>>()
    } else {
        state.visible_fields()
    };
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
        lines.push(Line::from(vec![
            Span::styled(
                if focused { "› " } else { "  " },
                Style::new().fg(Color::Cyan),
            ),
            Span::styled(
                format!("{}: ", field.label),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                display,
                if value.is_empty() {
                    Style::new().fg(Color::DarkGray)
                } else {
                    Style::new().fg(Color::White)
                },
            ),
        ]));
        lines.push(Line::styled(
            format!("    {}", field.help),
            Style::new().fg(Color::DarkGray),
        ));
    }
    if namespace.requires_scope_confirmation {
        let focused = !preview && state.focused_field == fields.len();
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!(
                "{}[{}] I own or am authorized to assess this target",
                if focused { "› " } else { "  " },
                if !preview && state.scope_confirmed {
                    "x"
                } else {
                    " "
                }
            ),
            Style::new().fg(Color::Yellow),
        ));
    }
    if !namespace.examples.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Examples",
            Style::new().add_modifier(Modifier::BOLD),
        ));
        lines.extend(
            namespace
                .examples
                .iter()
                .map(|example| Line::styled(example, Style::new().fg(Color::DarkGray))),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::bordered().title(if preview { "Form preview" } else { "Workflow" }))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_output(frame: &mut Frame, state: &TuiState, area: Rect, title: &str) {
    let block = Block::bordered().title(Line::from(vec![
        Span::raw(title),
        Span::styled(
            if state.output_follow_tail {
                "  [following tail]"
            } else {
                "  [scrolled · End returns to tail]"
            },
            Style::new().fg(Color::DarkGray),
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
            Style::new().fg(Color::Yellow),
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
        TranscriptKind::Command => (
            "$ ",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        TranscriptKind::Stdout => ("", Style::new().fg(Color::White)),
        TranscriptKind::Stderr => ("! ", Style::new().fg(Color::Red)),
        TranscriptKind::Warning => ("! ", Style::new().fg(Color::Yellow)),
        TranscriptKind::Status => ("", Style::new().fg(Color::Gray)),
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
                    TranscriptKind::Command | TranscriptKind::Stderr | TranscriptKind::Warning => 2,
                    TranscriptKind::Stdout | TranscriptKind::Status => 0,
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
