use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

use super::theme;

/// Общий каркас экрана: шапка, тело, строка уведомления и подсказки.
pub struct Chrome {
    pub title: String,
    pub subtitle: String,
    pub hint: String,
    pub toast: Option<Toast>,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub color: Color,
}

impl Toast {
    pub fn ok(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: theme::OK }
    }
    pub fn info(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: theme::ACCENT }
    }
    pub fn warn(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: theme::WARN }
    }
    pub fn error(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: theme::ERROR }
    }
}

impl Chrome {
    pub fn render(&self, frame: &mut Frame, area: Rect) -> Rect {
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

        let head = Line::from(vec![
            Span::styled(format!(" ATLASTUNNEL · {}", self.title), theme::header()),
            Span::styled(
                " ".repeat(
                    (area.width as usize)
                        .saturating_sub(self.title.chars().count() + self.subtitle.chars().count() + 17),
                ),
                theme::header(),
            ),
            Span::styled(format!("{} ", self.subtitle), theme::header()),
        ]);
        frame.render_widget(Paragraph::new(head).style(theme::header()), rows[0]);

        let toast = match &self.toast {
            Some(toast) => Line::from(Span::styled(
                format!(" {}", toast.text),
                Style::default().fg(toast.color),
            )),
            None => Line::from(""),
        };
        frame.render_widget(Paragraph::new(toast), rows[2]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(format!(" {}", self.hint), theme::dim()))),
            rows[3],
        );

        rows[1]
    }
}

/// Центрированное модальное окно поверх текущего экрана.
pub fn modal(frame: &mut Frame, area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let rect = Rect { x, y, width, height };
    frame.render_widget(Clear, rect);
    rect
}


pub fn centered(text: &str, style: Style) -> Paragraph<'_> {
    Paragraph::new(Line::from(Span::styled(text, style))).alignment(Alignment::Center)
}
