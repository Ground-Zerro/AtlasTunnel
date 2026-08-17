use anyhow::Result;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Gauge, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};

use super::chrome::{modal, Chrome, Toast};
use super::{hotkey, move_cursor, theme, Key, Session};
use crate::install::certs::Certificate;
use crate::install::{self, tx::Progress, Plan};
use crate::model::protocol::{compatible_set, Availability, Protocol};

const LOG_CAPACITY: usize = 400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
}

#[derive(Debug)]
pub enum Event {
    Step(String),
    Line(Level, String),
    Finished(Result<install::Outcome, String>),
}

/// Отправляет ход установки в поток интерфейса.
pub struct ChannelProgress {
    sender: Sender<Event>,
}

impl Progress for ChannelProgress {
    fn step(&mut self, title: &str) {
        let _ = self.sender.send(Event::Step(title.to_string()));
    }
    fn info(&mut self, text: &str) {
        let _ = self.sender.send(Event::Line(Level::Info, text.to_string()));
    }
    fn ok(&mut self, text: &str) {
        let _ = self.sender.send(Event::Line(Level::Ok, text.to_string()));
    }
    fn warn(&mut self, text: &str) {
        let _ = self.sender.send(Event::Line(Level::Warn, text.to_string()));
    }
}

pub struct Installer {
    availability: Vec<Availability>,
    marked: Vec<bool>,
    cursor: usize,
    toast: Option<Toast>,
    log_path: String,
}

pub enum Selection {
    Chosen(Vec<Protocol>),
    Cancelled,
}

impl Installer {
    pub fn new(log_path: String) -> Self {
        Self {
            availability: Protocol::ALL
                .into_iter()
                .map(|protocol| protocol.availability())
                .collect(),
            marked: vec![false; Protocol::ALL.len()],
            cursor: 0,
            toast: None,
            log_path,
        }
    }

    /// Экран выбора протоколов. Возвращает набор, уже проверенный на конфликты.
    pub fn select(&mut self, session: &mut Session) -> Result<Selection> {
        loop {
            session.terminal.draw(|frame| self.draw_select(frame))?;
            let key = super::read_key()?;
            self.toast = None;
            self.cursor = move_cursor(self.cursor, Protocol::ALL.len(), key, 5);

            match (key, hotkey(key)) {
                (Key::Space, _) => {
                    let availability = &self.availability[self.cursor];
                    let protocol = Protocol::ALL[self.cursor];
                    if !availability.is_selectable() {
                        self.toast = Some(Toast::error(format!(
                            "{} недоступен — {}",
                            protocol.display(),
                            availability.note().unwrap_or_default()
                        )));
                    } else {
                        self.marked[self.cursor] = !self.marked[self.cursor];
                        if self.marked[self.cursor] && availability.needs_legacy() {
                            self.toast = Some(Toast::warn(format!(
                                "{} потребует пакеты из архива прошлого выпуска Ubuntu",
                                protocol.display()
                            )));
                        }
                    }
                }
                (_, Some('a')) => self.mark_compatible(),
                (Key::Escape, _) | (_, Some('q')) => return Ok(Selection::Cancelled),
                (Key::Enter, _) => {
                    let chosen = self.chosen();
                    if chosen.is_empty() {
                        self.toast =
                            Some(Toast::warn("Отметьте хотя бы один протокол клавишей SPACE"));
                        continue;
                    }
                    match install::plan(&chosen, crate::install::certs::Certificate::SelfSigned) {
                        Ok(_) => return Ok(Selection::Chosen(chosen)),
                        Err(error) => {
                            self.toast = Some(Toast::error(format!("{error:#}")));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn chosen(&self) -> Vec<Protocol> {
        Protocol::ALL
            .into_iter()
            .enumerate()
            .filter(|(index, _)| self.marked[*index])
            .map(|(_, protocol)| protocol)
            .collect()
    }

    fn mark_compatible(&mut self) {
        let set = compatible_set();
        let mut skipped = Vec::new();
        for (index, protocol) in Protocol::ALL.into_iter().enumerate() {
            let included = set.contains(&protocol) && self.availability[index].is_selectable();
            self.marked[index] = included;
            if !included {
                skipped.push(protocol.display());
            }
        }
        self.toast = Some(if skipped.is_empty() {
            Toast::info("Отмечены все протоколы")
        } else {
            Toast::warn(format!(
                "Пропущены как несовместимые: {}",
                skipped.join(", ")
            ))
        });
    }

    fn draw_select(&self, frame: &mut Frame) {
        let chrome = Chrome {
            title: format!("установка v{}", env!("CARGO_PKG_VERSION")),
            subtitle: "выбор протоколов".into(),
            hint: "↑↓ выбор · SPACE отметить · A совместимый набор · ENTER далее · Q выход".into(),
            toast: self.toast.clone(),
        };
        let body = chrome.render(frame, frame.area());

        let installed = crate::model::state::installed_protocols();
        let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(body);

        let summary = if installed.is_empty() {
            Line::from(Span::styled(
                "ничего не установлено — выполняется первичная настройка",
                theme::dim(),
            ))
        } else {
            Line::from(Span::styled(
                installed
                    .iter()
                    .map(|protocol| protocol.display())
                    .collect::<Vec<_>>()
                    .join("  "),
                Style::default().fg(theme::WARN),
            ))
        };
        frame.render_widget(
            Paragraph::new(summary).block(theme::panel("Уже установлено")),
            rows[0],
        );

        let items: Vec<ListItem> = Protocol::ALL
            .into_iter()
            .enumerate()
            .map(|(index, protocol)| {
                let box_span = if self.marked[index] {
                    Span::styled("[✓] ", theme::accent())
                } else {
                    Span::styled("[ ] ", theme::dim())
                };
                let availability = &self.availability[index];
                let (name_style, note_style, note) = match availability.note() {
                    None => (theme::text(), theme::dim(), protocol.summary().to_string()),
                    Some(note) if availability.is_selectable() => (
                        theme::text(),
                        Style::default().fg(theme::WARN),
                        note,
                    ),
                    Some(note) => (theme::dim(), theme::dim(), note),
                };
                ListItem::new(Line::from(vec![
                    box_span,
                    Span::styled(format!("{:<16}", protocol.display()), name_style),
                    Span::styled(note, note_style),
                ]))
            })
            .collect();

        let mut state = ListState::default();
        state.select(Some(self.cursor));
        frame.render_stateful_widget(
            List::new(items)
                .highlight_style(theme::selected())
                .highlight_symbol(" ▸ "),
            rows[1],
            &mut state,
        );
    }

    /// Выбор сертификата для SSTP. Самоподписанный работает сразу, но требует
    /// импорта на клиенте; Let's Encrypt Windows принимает без действий,
    /// но нужен домен, чья A-запись указывает на этот сервер.
    pub fn certificate(&mut self, session: &mut Session) -> Result<Option<Certificate>> {
        let mut choice = 0usize;
        let mut domain = String::new();
        let mut editing = false;

        loop {
            session.terminal.draw(|frame| {
                let chrome = Chrome {
                    title: format!("установка v{}", env!("CARGO_PKG_VERSION")),
                    subtitle: "сертификат SSTP".into(),
                    hint: if editing {
                        "введите домен · ENTER подтвердить · ESC назад к выбору".into()
                    } else {
                        "↑↓ выбор · ENTER далее · ESC вернуться к протоколам".into()
                    },
                    toast: self.toast.clone(),
                };
                let body = chrome.render(frame, frame.area());
                let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(1)]).split(body);

                let items = vec![
                    ListItem::new(Line::from(vec![
                        Span::styled("Самоподписанный      ", theme::text()),
                        Span::styled(
                            "работает сразу, на клиенте нужен импорт сертификата",
                            theme::dim(),
                        ),
                    ])),
                    ListItem::new(Line::from(vec![
                        Span::styled("Let's Encrypt        ", theme::text()),
                        Span::styled(
                            "доверенный, Windows подключается без ручных действий",
                            theme::dim(),
                        ),
                    ])),
                ];
                let mut state = ListState::default();
                state.select(Some(choice));
                frame.render_stateful_widget(
                    List::new(items)
                        .block(theme::panel("Чем подписать"))
                        .highlight_style(theme::selected())
                        .highlight_symbol(" ▸ "),
                    rows[0],
                    &mut state,
                );

                if choice == 1 {
                    let mut lines = vec![
                        Line::from(Span::styled(
                            "Домен должен уже указывать A-записью на этот сервер.",
                            theme::dim(),
                        )),
                        Line::from(Span::styled(
                            "Для проверки домена certbot занимает порт 80.",
                            theme::dim(),
                        )),
                        Line::from(""),
                        Line::from(vec![
                            Span::styled("Домен: ", theme::bold(theme::ACCENT)),
                            Span::styled(domain.clone(), theme::bold(theme::TEXT)),
                            Span::styled(if editing { "▏" } else { "" }, theme::accent()),
                        ]),
                    ];
                    if !editing {
                        lines.push(Line::from(Span::styled(
                            "ENTER — ввести домен",
                            theme::dim(),
                        )));
                    }
                    frame.render_widget(
                        Paragraph::new(lines).block(theme::framed("Let's Encrypt", theme::WARN)),
                        rows[1],
                    );
                }
            })?;

            let key = super::read_key()?;
            if editing {
                match key {
                    Key::Escape => editing = false,
                    Key::Backspace => {
                        domain.pop();
                    }
                    Key::Enter => {
                        if domain.trim().is_empty() {
                            self.toast = Some(Toast::warn("Домен не может быть пустым"));
                        } else {
                            return Ok(Some(Certificate::LetsEncrypt {
                                domain: domain.trim().to_string(),
                                email: None,
                            }));
                        }
                    }
                    Key::Char(ch) => domain.push(ch),
                    _ => {}
                }
                continue;
            }

            self.toast = None;
            match key {
                Key::Up | Key::Down => choice = 1 - choice,
                Key::Escape => return Ok(None),
                Key::Enter if choice == 0 => return Ok(Some(Certificate::SelfSigned)),
                Key::Enter => editing = true,
                _ => {}
            }
        }
    }

    /// Экран подтверждения перед первой записью на диск.
    pub fn confirm(&mut self, session: &mut Session, plan: &Plan) -> Result<bool> {
        loop {
            session.terminal.draw(|frame| {
                let chrome = Chrome {
                    title: format!("установка v{}", env!("CARGO_PKG_VERSION")),
                    subtitle: "подтверждение".into(),
                    hint: "ENTER начать установку · ESC вернуться к выбору".into(),
                    toast: None,
                };
                let body = chrome.render(frame, frame.area());
                let legacy_lines: Vec<String> = plan
                    .legacy
                    .iter()
                    .flat_map(|need| {
                        crate::sys::legacy::warning_lines(
                            need.protocol.display(),
                            &need.packages,
                            need.suites,
                        )
                    })
                    .collect();
                let heights = [
                    Constraint::Length(
                        plan.selected.len() as u16
                            + 2
                            + u16::from(plan.selected.contains(&Protocol::Sstp)),
                    ),
                    Constraint::Length(plan.replaced.len() as u16 + 2),
                    Constraint::Length(if legacy_lines.is_empty() {
                        0
                    } else {
                        legacy_lines.len() as u16 + 2
                    }),
                    Constraint::Length(plan.warnings.len() as u16 + 2),
                    Constraint::Min(0),
                ];
                let rows = Layout::vertical(heights).split(body);

                let mut chosen: Vec<Line> = plan
                    .selected
                    .iter()
                    .map(|protocol| {
                        Line::from(Span::styled(
                            format!("{} — {}", protocol.display(), protocol.summary()),
                            theme::text(),
                        ))
                    })
                    .collect();
                if plan.selected.contains(&Protocol::Sstp) {
                    chosen.push(Line::from(Span::styled(
                        match plan.certificate.domain() {
                            Some(domain) => format!("Сертификат SSTP: Let\u{2019}s Encrypt для {domain}"),
                            None => "Сертификат SSTP: самоподписанный (импорт на клиенте)".into(),
                        },
                        Style::default().fg(theme::WARN),
                    )));
                }
                frame.render_widget(
                    Paragraph::new(chosen).block(theme::framed("Будут установлены", theme::ACCENT)),
                    rows[0],
                );

                if !plan.replaced.is_empty() {
                    let replaced: Vec<Line> = plan
                        .replaced
                        .iter()
                        .map(|protocol| {
                            Line::from(Span::styled(
                                format!(
                                    "{} — конфигурация будет перезаписана, протокол снят с учёта",
                                    protocol.display()
                                ),
                                Style::default().fg(theme::ERROR),
                            ))
                        })
                        .collect();
                    frame.render_widget(
                        Paragraph::new(replaced)
                            .block(theme::framed("Будут заменены", theme::ERROR)),
                        rows[1],
                    );
                }

                if !legacy_lines.is_empty() {
                    let lines: Vec<Line> = legacy_lines
                        .iter()
                        .map(|text| {
                            Line::from(Span::styled(text.clone(), Style::default().fg(theme::WARN)))
                        })
                        .collect();
                    frame.render_widget(
                        Paragraph::new(lines)
                            .block(theme::framed("Пакеты из архива прошлых выпусков", theme::WARN)),
                        rows[2],
                    );
                }

                if !plan.warnings.is_empty() {
                    let warnings: Vec<Line> = plan
                        .warnings
                        .iter()
                        .map(|text| {
                            Line::from(Span::styled(text.clone(), Style::default().fg(theme::WARN)))
                        })
                        .collect();
                    frame.render_widget(
                        Paragraph::new(warnings).block(theme::framed("Предупреждения", theme::WARN)),
                        rows[3],
                    );
                }
            })?;

            match super::read_key()? {
                Key::Enter => return Ok(true),
                Key::Escape => return Ok(false),
                key if hotkey(key) == Some('q') => return Ok(false),
                _ => {}
            }
        }
    }

    /// Запускает установку в рабочем потоке и рисует прогресс, пока она идёт.
    pub fn execute(
        &mut self,
        session: &mut Session,
        plan: Plan,
        user: String,
    ) -> Result<install::Outcome> {
        let (sender, receiver): (Sender<Event>, Receiver<Event>) = mpsc::channel();
        let worker_sender = sender.clone();
        let worker_plan = plan.clone();

        let worker = std::thread::spawn(move || {
            let mut progress = ChannelProgress { sender: worker_sender.clone() };
            let result = install::execute(&worker_plan, &user, &mut progress)
                .map_err(|error| format!("{error:#}"));
            let _ = worker_sender.send(Event::Finished(result));
        });

        let total = plan.steps();
        let mut step = 0usize;
        let mut caption = String::from("подготовка");
        let mut log: VecDeque<(Level, String)> = VecDeque::with_capacity(LOG_CAPACITY);
        let mut finished: Option<Result<install::Outcome, String>> = None;

        while finished.is_none() {
            while let Ok(event) = receiver.try_recv() {
                match event {
                    Event::Step(title) => {
                        step += 1;
                        caption = title;
                    }
                    Event::Line(level, text) => {
                        if log.len() == LOG_CAPACITY {
                            log.pop_front();
                        }
                        log.push_back((level, text));
                    }
                    Event::Finished(result) => finished = Some(result),
                }
            }

            session.terminal.draw(|frame| {
                draw_progress(frame, step, total, &caption, &log, &self.log_path)
            })?;
            std::thread::sleep(std::time::Duration::from_millis(60));
        }

        let _ = worker.join();
        match finished.expect("цикл завершается только с результатом") {
            Ok(outcome) => Ok(outcome),
            Err(message) => {
                self.show_failure(session, &message, &log)?;
                anyhow::bail!("{message}")
            }
        }
    }

    fn show_failure(
        &self,
        session: &mut Session,
        message: &str,
        log: &VecDeque<(Level, String)>,
    ) -> Result<()> {
        loop {
            session.terminal.draw(|frame| {
                let area = frame.area();
                draw_progress(frame, 0, 1, "установка прервана", log, &self.log_path);
                let rect = modal(frame, area, 84, 9);
                let body = vec![
                    Line::from(Span::styled(message.to_string(), theme::text())),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Все изменённые файлы возвращены в исходное состояние.",
                        Style::default().fg(theme::OK),
                    )),
                    Line::from(Span::styled(
                        format!("Подробный журнал: {}", self.log_path),
                        theme::dim(),
                    )),
                ];
                frame.render_widget(
                    Paragraph::new(body).block(theme::framed("Установка прервана", theme::ERROR)),
                    rect,
                );
            })?;
            match super::read_key()? {
                Key::Enter | Key::Escape => return Ok(()),
                _ => {}
            }
        }
    }

    /// Итоговый экран с параметрами доступа.
    pub fn summary(&self, session: &mut Session, outcome: &install::Outcome) -> Result<()> {
        loop {
            session.terminal.draw(|frame| {
                let chrome = Chrome {
                    title: format!("установка v{}", env!("CARGO_PKG_VERSION")),
                    subtitle: "завершено".into(),
                    hint: "ENTER выйти".into(),
                    toast: Some(Toast::ok("Управление сервером: команда atlas")),
                };
                let body = chrome.render(frame, frame.area());
                let rows = Layout::vertical([
                    Constraint::Length(2),
                    Constraint::Length(8),
                    Constraint::Min(3),
                ])
                .split(body);

                frame.render_widget(
                    super::chrome::centered("УСТАНОВКА ЗАВЕРШЕНА", theme::bold(theme::OK)),
                    rows[0],
                );

                let mut access = vec![
                    theme::field("IP сервера", outcome.public_ip.to_string(), theme::TEXT),
                    theme::field("Логин", outcome.user.clone(), theme::TEXT),
                    theme::field("Пароль", outcome.password.clone(), theme::TEXT),
                ];
                if outcome.installed.contains(&Protocol::L2tpIpsec) {
                    access.push(theme::field("PSK", outcome.psk.clone(), theme::TEXT));
                }
                if outcome
                    .installed
                    .iter()
                    .any(|protocol| protocol.needs_ca_certificate())
                {
                    let path = crate::model::state::ca_certificate()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "не найден".into());
                    access.push(theme::field("CA-сертификат", path, theme::TEXT));
                    access.push(Line::from(Span::styled(
                        "Установите CA-сертификат на клиент перед подключением",
                        Style::default().fg(theme::WARN),
                    )));
                }
                if outcome.installed.contains(&Protocol::Sstp) {
                    match outcome.certificate.domain() {
                        Some(domain) => {
                            access.push(theme::field("SSTP-домен", domain.to_string(), theme::TEXT));
                            access.push(Line::from(Span::styled(
                                "Сертификат доверенный, продление автоматическое",
                                Style::default().fg(theme::OK),
                            )));
                        }
                        None => access.push(Line::from(Span::styled(
                            "SSTP: самоподписанный сертификат — импортируйте его на клиенте",
                            Style::default().fg(theme::WARN),
                        ))),
                    }
                }
                if outcome.installed.contains(&Protocol::OpenVpn) {
                    access.push(theme::field(
                        "Профиль OpenVPN",
                        format!("/etc/atlastunnel/clients/{}.ovpn", outcome.user),
                        theme::TEXT,
                    ));
                }
                frame.render_widget(
                    Paragraph::new(access).block(theme::framed("Доступ", theme::OK)),
                    rows[1],
                );

                let installed: Vec<Line> = outcome
                    .installed
                    .iter()
                    .map(|protocol| {
                        Line::from(Span::styled(
                            format!("{} — {}", protocol.display(), protocol.summary()),
                            theme::text(),
                        ))
                    })
                    .collect();
                frame.render_widget(
                    Paragraph::new(installed).block(theme::panel("Установленные протоколы")),
                    rows[2],
                );
            })?;
            match super::read_key()? {
                Key::Enter | Key::Escape => return Ok(()),
                _ => {}
            }
        }
    }
}

fn draw_progress(
    frame: &mut Frame,
    step: usize,
    total: usize,
    caption: &str,
    log: &VecDeque<(Level, String)>,
    log_path: &str,
) {
    let chrome = Chrome {
        title: format!("установка v{}", env!("CARGO_PKG_VERSION")),
        subtitle: format!("шаг {step}/{total}"),
        hint: format!("идёт установка, не прерывайте · журнал: {log_path}"),
        toast: None,
    };
    let body = chrome.render(frame, frame.area());
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(1),
    ])
    .split(body);

    let ratio = if total == 0 {
        0.0
    } else {
        (step as f64 / total as f64).clamp(0.0, 1.0)
    };
    frame.render_widget(
        Gauge::default()
            .gauge_style(Style::default().fg(theme::ACCENT))
            .ratio(ratio)
            .label(format!("{}%", (ratio * 100.0) as u16)),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("  {caption}"),
            theme::bold(theme::TEXT),
        ))),
        rows[1],
    );

    let visible = rows[2].height as usize;
    let lines: Vec<Line> = log
        .iter()
        .rev()
        .take(visible)
        .rev()
        .map(|(level, text)| {
            let (glyph, color) = match level {
                Level::Ok => ("✓", theme::OK),
                Level::Warn => ("!", theme::WARN),
                Level::Info => ("·", theme::DIM),
            };
            Line::from(vec![
                Span::styled(format!("   {glyph} "), Style::default().fg(color)),
                Span::styled(text.clone(), theme::text()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rows[2]);
}
