use anyhow::Result;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::chrome::{modal, Chrome, Toast};
use super::{hotkey, move_cursor, theme, Key, Session};
use crate::doctor::{self, Finding, Severity};
use crate::install;
use crate::install::tx::Silent;
use crate::model::protocol::Protocol;
use crate::model::secrets::{validate_login, Client, Store};
use crate::model::state::{self, random_password, Marker};
use crate::sys::systemd;

enum Screen {
    Dashboard,
    Protocol(Protocol),
    Clients(Protocol),
    Certificate(Protocol),
    Doctor(Vec<Finding>),
}

enum Overlay {
    None,
    Message {
        title: String,
        lines: Vec<String>,
        color: Color,
    },
    Confirm {
        title: String,
        lines: Vec<String>,
        accept: String,
        decline: String,
        choice: bool,
        action: Pending,
    },
    Input {
        title: String,
        label: String,
        hint: String,
        value: String,
        action: Pending,
    },
}

#[derive(Clone)]
enum Pending {
    AddClient(Protocol),
    RemoveClient(Protocol, String),
    Uninstall(Protocol),
}

pub struct Manager {
    screen: Screen,
    overlay: Overlay,
    cursor: usize,
    stack: Vec<usize>,
    protocols: Vec<Protocol>,
    clients: Vec<Client>,
    reveal: bool,
    toast: Option<Toast>,
    public_ip: String,
    running: bool,
}

impl Manager {
    pub fn new(public_ip: String) -> Self {
        Self {
            screen: Screen::Dashboard,
            overlay: Overlay::None,
            cursor: 0,
            stack: Vec::new(),
            protocols: state::installed_protocols(),
            clients: Vec::new(),
            reveal: false,
            toast: None,
            public_ip,
            running: true,
        }
    }

    pub fn run(mut self, session: &mut Session) -> Result<()> {
        while self.running {
            session.terminal.draw(|frame| self.draw(frame))?;
            let key = super::read_key()?;
            if key == Key::Resize {
                continue;
            }
            self.handle(key)?;
        }
        Ok(())
    }

    fn refresh(&mut self) {
        self.protocols = state::installed_protocols();
        if let Screen::Clients(protocol) = self.screen {
            self.clients = Store::list(protocol).unwrap_or_default();
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chrome = Chrome {
            title: self.title(),
            subtitle: self.subtitle(),
            hint: self.hint().into(),
            toast: self.toast.clone(),
        };
        let body = chrome.render(frame, frame.area());

        match &self.screen {
            Screen::Dashboard => self.draw_dashboard(frame, body),
            Screen::Protocol(protocol) => self.draw_protocol(frame, body, *protocol),
            Screen::Clients(protocol) => self.draw_clients(frame, body, *protocol),
            Screen::Certificate(protocol) => self.draw_certificate(frame, body, *protocol),
            Screen::Doctor(findings) => draw_doctor(frame, body, findings, self.cursor),
        }

        self.draw_overlay(frame, frame.area());
    }

    fn title(&self) -> String {
        match &self.screen {
            Screen::Dashboard => "панель управления".into(),
            Screen::Protocol(protocol) => protocol.display().into(),
            Screen::Clients(protocol) => format!("{} · клиенты", protocol.display()),
            Screen::Certificate(protocol) => format!("{} · CA-сертификат", protocol.display()),
            Screen::Doctor(_) => "диагностика".into(),
        }
    }

    fn subtitle(&self) -> String {
        match &self.screen {
            Screen::Dashboard => format!("протоколов: {}", self.protocols.len()),
            Screen::Protocol(_) => "управление протоколом".into(),
            Screen::Clients(_) => format!("всего: {}", self.clients.len()),
            Screen::Certificate(_) => "установка на клиентское устройство".into(),
            Screen::Doctor(findings) => format!("проверок: {}", findings.len()),
        }
    }

    fn hint(&self) -> &'static str {
        if !matches!(self.overlay, Overlay::None) {
            return match self.overlay {
                Overlay::Confirm { .. } => "←→ выбор · ENTER подтвердить · ESC отмена",
                Overlay::Input { .. } => "ENTER подтвердить · ESC отмена",
                _ => "ENTER продолжить",
            };
        }
        match self.screen {
            Screen::Dashboard => {
                "ENTER открыть · S запустить все · T остановить все · R перезапустить · D диагностика · Q выход"
            }
            Screen::Protocol(_) => "↑↓ выбор · ENTER выполнить · ESC назад",
            Screen::Clients(_) => {
                "A добавить · D удалить · P новый пароль · M показать пароли · ESC назад"
            }
            Screen::Certificate(_) | Screen::Doctor(_) => "↑↓ прокрутка · ESC назад",
        }
    }

    fn draw_dashboard(&self, frame: &mut Frame, area: Rect) {
        if self.protocols.is_empty() {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Ни один протокол не установлен.",
                        theme::bold(theme::WARN),
                    )),
                    Line::from(Span::styled(
                        "  Выполните: atlas install",
                        theme::dim(),
                    )),
                ]),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = self
            .protocols
            .iter()
            .map(|protocol| {
                let active = protocol
                    .units()
                    .iter()
                    .all(|unit| systemd::state(unit).is_active());
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<18}", protocol.display()), theme::text()),
                    theme::running(active),
                    Span::styled(
                        format!("   {}", protocol.summary()),
                        theme::dim(),
                    ),
                ]))
            })
            .collect();
        render_list(frame, area, items, self.cursor);
    }

    fn draw_protocol(&self, frame: &mut Frame, area: Rect, protocol: Protocol) {
        let actions = protocol_actions(protocol);

        let mut lines = Vec::new();
        for unit in protocol.units() {
            let state = systemd::state(unit);
            lines.push(Line::from(vec![
                Span::styled(format!("{unit:<22}"), theme::dim()),
                Span::styled(
                    state.label(),
                    Style::default().fg(if state.is_active() {
                        theme::OK
                    } else {
                        theme::ERROR
                    }),
                ),
            ]));
        }
        lines.push(theme::field("IP сервера", self.public_ip.clone(), theme::TEXT));
        if let Ok(Some(marker)) = Marker::load(protocol) {
            if let Some(psk) = marker.psk {
                lines.push(theme::field(
                    "PSK",
                    if self.reveal { psk } else { "•".repeat(12) },
                    theme::TEXT,
                ));
            }
        }
        if protocol.needs_ca_certificate() {
            let path = state::ca_certificate()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "не найден".into());
            lines.push(theme::field("CA-сертификат", path, theme::TEXT));
        }

        let rows = Layout::vertical([
            Constraint::Length(lines.len() as u16 + 2),
            Constraint::Min(1),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new(lines).block(theme::panel("Состояние")),
            rows[0],
        );

        let items: Vec<ListItem> = actions
            .iter()
            .map(|action| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<26}", action.label), theme::text()),
                    Span::styled(action.detail, theme::dim()),
                ]))
            })
            .collect();
        render_list(frame, rows[1], items, self.cursor);
    }

    fn draw_clients(&self, frame: &mut Frame, area: Rect, protocol: Protocol) {
        if protocol.secrets_kind().is_none() {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "  Управление клиентами для этого протокола не поддерживается.",
                    theme::bold(theme::WARN),
                ))),
                area,
            );
            return;
        }
        if self.clients.is_empty() {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Нет добавленных клиентов — нажмите A.",
                        theme::dim(),
                    )),
                ]),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = self
            .clients
            .iter()
            .enumerate()
            .map(|(index, client)| {
                let password = if self.reveal {
                    client.password.clone()
                } else {
                    "•".repeat(client.password.chars().count().min(16))
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:>3}. ", index + 1), theme::dim()),
                    Span::styled(format!("{:<24}", client.login), theme::text()),
                    Span::styled(password, theme::accent()),
                ]))
            })
            .collect();
        render_list(frame, area, items, self.cursor);
    }

    fn draw_certificate(&self, frame: &mut Frame, area: Rect, _protocol: Protocol) {
        let path = state::ca_certificate()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "не найден".into());
        let mut lines = vec![
            Line::from(Span::styled(
                format!("  Файл на сервере: {path}"),
                theme::bold(theme::ACCENT),
            )),
            Line::from(""),
        ];
        for (platform, steps) in CA_STEPS {
            lines.push(Line::from(Span::styled(
                format!("  {platform}"),
                theme::bold(theme::TEXT),
            )));
            for step in *steps {
                lines.push(Line::from(Span::styled(format!("    {step}"), theme::dim())));
            }
            lines.push(Line::from(""));
        }
        let offset = self.cursor.min(lines.len().saturating_sub(1));
        frame.render_widget(
            Paragraph::new(lines).scroll((offset as u16, 0)),
            area,
        );
    }

    fn draw_overlay(&self, frame: &mut Frame, area: Rect) {
        match &self.overlay {
            Overlay::None => {}
            Overlay::Message { title, lines, color } => {
                let rect = modal(frame, area, 76, lines.len() as u16 + 4);
                let body: Vec<Line> = lines
                    .iter()
                    .map(|line| Line::from(Span::styled(line.clone(), Style::default().fg(*color))))
                    .collect();
                frame.render_widget(
                    Paragraph::new(body).block(theme::framed(title, *color)),
                    rect,
                );
            }
            Overlay::Confirm { title, lines, accept, decline, choice, .. } => {
                let rect = modal(frame, area, 76, lines.len() as u16 + 6);
                let mut body: Vec<Line> = lines
                    .iter()
                    .map(|line| Line::from(Span::styled(line.clone(), theme::text())))
                    .collect();
                body.push(Line::from(""));
                body.push(Line::from(vec![
                    Span::styled(
                        format!("  {accept}  "),
                        if *choice { theme::selected() } else { theme::dim() },
                    ),
                    Span::raw("   "),
                    Span::styled(
                        format!("  {decline}  "),
                        if *choice { theme::dim() } else { theme::selected() },
                    ),
                ]));
                frame.render_widget(
                    Paragraph::new(body).block(theme::framed(title, theme::WARN)),
                    rect,
                );
            }
            Overlay::Input { title, label, hint, value, .. } => {
                let rect = modal(frame, area, 76, 7);
                let body = vec![
                    Line::from(Span::styled(label.clone(), theme::bold(theme::ACCENT))),
                    Line::from(Span::styled(hint.clone(), theme::dim())),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(value.clone(), theme::bold(theme::TEXT)),
                        Span::styled("▏", theme::accent()),
                    ]),
                ];
                frame.render_widget(
                    Paragraph::new(body).block(theme::framed(title, theme::ACCENT)),
                    rect,
                );
            }
        }
    }

    fn handle(&mut self, key: Key) -> Result<()> {
        if !matches!(self.overlay, Overlay::None) {
            return self.handle_overlay(key);
        }
        self.toast = None;
        match &self.screen {
            Screen::Dashboard => self.handle_dashboard(key),
            Screen::Protocol(protocol) => self.handle_protocol(key, *protocol),
            Screen::Clients(protocol) => self.handle_clients(key, *protocol),
            Screen::Certificate(_) | Screen::Doctor(_) => {
                if key == Key::Escape || hotkey(key) == Some('q') {
                    self.pop();
                } else {
                    self.cursor = match key {
                        Key::Up => self.cursor.saturating_sub(1),
                        Key::Down => self.cursor + 1,
                        Key::PageUp => self.cursor.saturating_sub(10),
                        Key::PageDown => self.cursor + 10,
                        Key::Home => 0,
                        _ => self.cursor,
                    };
                }
                Ok(())
            }
        }
    }

    fn push(&mut self, screen: Screen) {
        self.stack.push(self.cursor);
        self.screen = screen;
        self.cursor = 0;
        self.refresh();
    }

    fn pop(&mut self) {
        self.screen = match self.screen {
            Screen::Clients(protocol)
            | Screen::Certificate(protocol) => Screen::Protocol(protocol),
            _ => Screen::Dashboard,
        };
        self.cursor = self.stack.pop().unwrap_or(0);
        self.refresh();
    }

    fn handle_dashboard(&mut self, key: Key) -> Result<()> {
        self.cursor = move_cursor(self.cursor, self.protocols.len(), key, 5);
        match (key, hotkey(key)) {
            (Key::Enter, _) if !self.protocols.is_empty() => {
                let protocol = self.protocols[self.cursor];
                self.push(Screen::Protocol(protocol));
            }
            (_, Some('s')) => self.bulk("запуск", systemd::start)?,
            (_, Some('t')) => self.bulk("остановка", systemd::stop)?,
            (_, Some('r')) => self.bulk("перезапуск", systemd::restart)?,
            (_, Some('d')) => {
                let findings = doctor::run();
                self.push(Screen::Doctor(findings));
            }
            (Key::Escape, _) | (_, Some('q')) => self.running = false,
            _ => {}
        }
        Ok(())
    }

    fn bulk(&mut self, what: &str, action: fn(&str) -> Result<()>) -> Result<()> {
        let mut failed = Vec::new();
        for protocol in self.protocols.clone() {
            for unit in protocol.units() {
                if action(unit).is_err() {
                    failed.push(unit.to_string());
                }
            }
        }
        self.toast = Some(if failed.is_empty() {
            Toast::ok(format!("{what}: выполнено для всех протоколов"))
        } else {
            Toast::error(format!("{what}: ошибки в юнитах {}", failed.join(", ")))
        });
        Ok(())
    }

    fn handle_protocol(&mut self, key: Key, protocol: Protocol) -> Result<()> {
        let actions = protocol_actions(protocol);
        self.cursor = move_cursor(self.cursor, actions.len(), key, 5);
        if key == Key::Escape || hotkey(key) == Some('q') {
            self.pop();
            return Ok(());
        }
        if key != Key::Enter {
            return Ok(());
        }

        match actions[self.cursor].kind {
            ActionKind::Start => self.service(protocol, "запущен", systemd::start),
            ActionKind::Stop => self.service(protocol, "остановлен", systemd::stop),
            ActionKind::Restart => self.service(protocol, "перезапущен", systemd::restart),
            ActionKind::Clients => self.push(Screen::Clients(protocol)),
            ActionKind::Certificate => self.push(Screen::Certificate(protocol)),
            ActionKind::Uninstall => {
                self.overlay = Overlay::Confirm {
                    title: "Удаление протокола".into(),
                    lines: vec![
                        format!("Удалить {} с сервера?", protocol.display()),
                        String::new(),
                        "Службы будут остановлены, правила iptables сняты,".into(),
                        "учётные записи протокола удалены.".into(),
                    ],
                    accept: "Удалить".into(),
                    decline: "Отмена".into(),
                    choice: false,
                    action: Pending::Uninstall(protocol),
                };
            }
            ActionKind::Back => self.pop(),
        }
        Ok(())
    }

    fn service(&mut self, protocol: Protocol, verb: &str, action: fn(&str) -> Result<()>) {
        let mut error = None;
        for unit in protocol.units() {
            if let Err(err) = action(unit) {
                error = Some(format!("{unit}: {err:#}"));
                break;
            }
        }
        self.toast = Some(match error {
            None => Toast::ok(format!("{} {verb}", protocol.display())),
            Some(text) => Toast::error(text),
        });
    }

    fn handle_clients(&mut self, key: Key, protocol: Protocol) -> Result<()> {
        self.cursor = move_cursor(self.cursor, self.clients.len(), key, 8);
        match (key, hotkey(key)) {
            (Key::Escape, _) => self.pop(),
            (_, Some('m')) => {
                self.reveal = !self.reveal;
                self.toast = Some(Toast::info(if self.reveal {
                    "Пароли показаны"
                } else {
                    "Пароли скрыты"
                }));
            }
            (_, Some('a')) => {
                self.overlay = Overlay::Input {
                    title: format!("{} · новый клиент", protocol.display()),
                    label: "Введите логин клиента".into(),
                    hint: "3–32 символа: латинские буквы, цифры, дефис, подчёркивание".into(),
                    value: String::new(),
                    action: Pending::AddClient(protocol),
                };
            }
            (_, Some('d')) if !self.clients.is_empty() => {
                let login = self.clients[self.cursor].login.clone();
                self.overlay = Overlay::Confirm {
                    title: "Удаление клиента".into(),
                    lines: vec![format!(
                        "Удалить клиента «{login}» из {}?",
                        protocol.display()
                    )],
                    accept: "Удалить".into(),
                    decline: "Отмена".into(),
                    choice: false,
                    action: Pending::RemoveClient(protocol, login),
                };
            }
            (_, Some('p')) if !self.clients.is_empty() => {
                let login = self.clients[self.cursor].login.clone();
                let password = random_password();
                match Store::upsert(protocol, &login, &password) {
                    Ok(()) => {
                        reload(protocol);
                        self.refresh();
                        self.overlay = Overlay::Message {
                            title: "Пароль изменён".into(),
                            lines: vec![
                                format!("Логин: {login}"),
                                format!("Новый пароль: {password}"),
                            ],
                            color: theme::OK,
                        };
                    }
                    Err(error) => self.toast = Some(Toast::error(format!("{error:#}"))),
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_overlay(&mut self, key: Key) -> Result<()> {
        match &mut self.overlay {
            Overlay::None => Ok(()),
            Overlay::Message { .. } => {
                if matches!(key, Key::Enter | Key::Escape) || hotkey(key) == Some('q') {
                    self.overlay = Overlay::None;
                }
                Ok(())
            }
            Overlay::Confirm { choice, action, .. } => {
                match key {
                    Key::Left | Key::Right | Key::Tab => *choice = !*choice,
                    Key::Escape => self.overlay = Overlay::None,
                    Key::Enter => {
                        let accepted = *choice;
                        let action = action.clone();
                        self.overlay = Overlay::None;
                        if accepted {
                            self.commit(action)?;
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
            Overlay::Input { value, action, .. } => {
                match key {
                    Key::Escape => self.overlay = Overlay::None,
                    Key::Backspace => {
                        value.pop();
                    }
                    Key::Char(ch) => value.push(ch),
                    Key::Enter if !value.is_empty() => {
                        let entered = value.clone();
                        let action = action.clone();
                        self.overlay = Overlay::None;
                        self.commit_input(action, entered)?;
                    }
                    _ => {}
                }
                Ok(())
            }
        }
    }

    fn commit(&mut self, action: Pending) -> Result<()> {
        match action {
            Pending::RemoveClient(protocol, login) => match Store::remove(protocol, &login) {
                Ok(()) => {
                    reload(protocol);
                    self.refresh();
                    self.cursor = self.cursor.min(self.clients.len().saturating_sub(1));
                    self.toast = Some(Toast::warn(format!("Клиент «{login}» удалён")));
                }
                Err(error) => self.toast = Some(Toast::error(format!("{error:#}"))),
            },
            Pending::Uninstall(protocol) => {
                match install::uninstall(protocol, &mut Silent) {
                    Ok(()) => {
                        self.screen = Screen::Dashboard;
                        self.cursor = 0;
                        self.stack.clear();
                        self.refresh();
                        self.toast =
                            Some(Toast::warn(format!("{} удалён", protocol.display())));
                    }
                    Err(error) => self.toast = Some(Toast::error(format!("{error:#}"))),
                }
            }
            Pending::AddClient(_) => {}
        }
        Ok(())
    }

    fn commit_input(&mut self, action: Pending, value: String) -> Result<()> {
        let Pending::AddClient(protocol) = action else {
            return Ok(());
        };
        if let Err(error) = validate_login(&value) {
            self.overlay = Overlay::Message {
                title: "Неверный логин".into(),
                lines: vec![format!("{error:#}")],
                color: theme::ERROR,
            };
            return Ok(());
        }
        if Store::exists(protocol, &value)? {
            self.overlay = Overlay::Message {
                title: "Логин занят".into(),
                lines: vec![format!("Клиент «{value}» уже существует.")],
                color: theme::ERROR,
            };
            return Ok(());
        }
        let password = random_password();
        match Store::upsert(protocol, &value, &password) {
            Ok(()) => {
                reload(protocol);
                self.refresh();
                self.overlay = Overlay::Message {
                    title: "Клиент добавлен".into(),
                    lines: vec![
                        format!("Логин: {value}"),
                        format!("Пароль: {password}"),
                    ],
                    color: theme::OK,
                };
            }
            Err(error) => self.toast = Some(Toast::error(format!("{error:#}"))),
        }
        Ok(())
    }
}

fn reload(protocol: Protocol) {
    if protocol.uses_ipsec() {
        systemd::reload_or_restart("strongswan-starter");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    Start,
    Stop,
    Restart,
    Clients,
    Certificate,
    Uninstall,
    Back,
}

struct Action {
    kind: ActionKind,
    label: &'static str,
    detail: &'static str,
}

fn protocol_actions(protocol: Protocol) -> Vec<Action> {
    let mut actions = vec![
        Action { kind: ActionKind::Start, label: "Запустить сервер", detail: "systemctl start" },
        Action { kind: ActionKind::Stop, label: "Остановить сервер", detail: "systemctl stop" },
        Action { kind: ActionKind::Restart, label: "Перезапустить сервер", detail: "systemctl restart" },
    ];
    if protocol.secrets_kind().is_some() {
        actions.push(Action {
            kind: ActionKind::Clients,
            label: "Клиенты",
            detail: "добавить, удалить, сменить пароль",
        });
    }
    if protocol.needs_ca_certificate() {
        actions.push(Action {
            kind: ActionKind::Certificate,
            label: "CA-сертификат",
            detail: "инструкции по установке на клиент",
        });
    }
    actions.push(Action {
        kind: ActionKind::Uninstall,
        label: "Удалить протокол",
        detail: "остановить службы и снять правила",
    });
    actions.push(Action {
        kind: ActionKind::Back,
        label: "Назад",
        detail: "к списку протоколов",
    });
    actions
}

fn render_list(frame: &mut Frame, area: Rect, items: Vec<ListItem>, cursor: usize) {
    let mut state = ListState::default();
    state.select(Some(cursor.min(items.len().saturating_sub(1))));
    let list = List::new(items)
        .highlight_style(theme::selected())
        .highlight_symbol(" ▸ ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_doctor(frame: &mut Frame, area: Rect, findings: &[Finding], cursor: usize) {
    let mut lines = Vec::new();
    for finding in findings {
        let color = match finding.severity {
            Severity::Ok => theme::OK,
            Severity::Warning => theme::WARN,
            Severity::Error => theme::ERROR,
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  [{}] ", finding.severity.label()), theme::bold(color)),
            Span::styled(finding.subject.clone(), theme::bold(theme::TEXT)),
        ]));
        lines.push(Line::from(Span::styled(
            format!("      {}", finding.detail),
            theme::text(),
        )));
        if let Some(remedy) = &finding.remedy {
            lines.push(Line::from(Span::styled(
                format!("      → {remedy}"),
                theme::dim(),
            )));
        }
        lines.push(Line::from(""));
    }
    let offset = cursor.min(lines.len().saturating_sub(1));
    frame.render_widget(Paragraph::new(lines).scroll((offset as u16, 0)), area);
}

const CA_STEPS: &[(&str, &[&str])] = &[
    (
        "Windows",
        &[
            "Откройте ca-cert.pem → Установить сертификат → Локальный компьютер",
            "Хранилище: Доверенные корневые центры сертификации",
        ],
    ),
    (
        "macOS / iOS",
        &[
            "Откройте ca-cert.pem и добавьте в Связку ключей",
            "Настройки → Основные → Профили VPN → Доверять сертификату",
        ],
    ),
    (
        "Android",
        &[
            "Настройки → Безопасность → Установить из хранилища",
            "Выберите ca-cert.pem и укажите использование для VPN",
        ],
    ),
    (
        "Linux",
        &[
            "sudo cp ca-cert.pem /usr/local/share/ca-certificates/atlas-ca.crt",
            "sudo update-ca-certificates",
        ],
    ),
];
