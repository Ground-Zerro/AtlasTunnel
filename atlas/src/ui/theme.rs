use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders};

pub const ACCENT: Color = Color::Rgb(56, 160, 245);
pub const TEXT: Color = Color::Rgb(214, 219, 226);
pub const DIM: Color = Color::Rgb(126, 134, 146);
pub const FRAME: Color = Color::Rgb(62, 68, 78);
pub const OK: Color = Color::Rgb(64, 196, 128);
pub const WARN: Color = Color::Rgb(232, 172, 62);
pub const ERROR: Color = Color::Rgb(226, 96, 92);
pub const BAR_BG: Color = Color::Rgb(24, 62, 96);
pub const SELECT_BG: Color = Color::Rgb(44, 52, 64);

pub fn text() -> Style {
    Style::default().fg(TEXT)
}

pub fn dim() -> Style {
    Style::default().fg(DIM)
}

pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

pub fn header() -> Style {
    Style::default()
        .fg(Color::White)
        .bg(BAR_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn selected() -> Style {
    Style::default()
        .fg(Color::White)
        .bg(SELECT_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(FRAME))
        .title(Span::styled(format!(" {title} "), Style::default().fg(DIM)))
}

pub fn framed(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(format!(" {title} "), bold(color)))
}

/// Строка «ключ — значение» с выровненной колонкой ключа.
pub fn field<'a>(key: &'a str, value: String, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<16}"), dim()),
        Span::styled(value, Style::default().fg(color)),
    ])
}

pub fn running(active: bool) -> Span<'static> {
    if active {
        Span::styled("● ЗАПУЩЕН", Style::default().fg(OK))
    } else {
        Span::styled("○ ОСТАНОВЛЕН", Style::default().fg(ERROR))
    }
}
