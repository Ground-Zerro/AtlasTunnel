pub mod chrome;
pub mod installer;
pub mod manager;
pub mod theme;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use std::fs::{File, OpenOptions};
use std::time::Duration;

pub type Terminal = ratatui::Terminal<CrosstermBackend<File>>;

/// Рисование идёт напрямую в /dev/tty, а не в stdout: установщик может быть
/// запущен с перенаправленным выводом, и интерфейс от этого не должен ломаться.
pub struct Session {
    pub terminal: Terminal,
    restored: bool,
}

impl Session {
    pub fn open() -> Result<Self> {
        let tty = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("интерфейс требует терминал (/dev/tty недоступен)")?;

        terminal::enable_raw_mode().context("перевод терминала в raw-режим")?;
        let mut backend = CrosstermBackend::new(tty);
        execute!(
            backend,
            terminal::EnterAlternateScreen,
            crossterm::cursor::Hide
        )?;

        let terminal = ratatui::Terminal::new(backend)?;
        Ok(Self { terminal, restored: false })
    }

    pub fn close(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            crossterm::cursor::Show,
            terminal::LeaveAlternateScreen
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// Нормализованное событие клавиатуры: экранам не нужно знать про модификаторы
/// и повторные события нажатия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Escape,
    Space,
    Backspace,
    Tab,
    Char(char),
    Resize,
}

pub fn poll_key(timeout: Duration) -> Result<Option<Key>> {
    if !event::poll(timeout)? {
        return Ok(None);
    }
    Ok(match event::read()? {
        Event::Resize(_, _) => Some(Key::Resize),
        Event::Key(key) if key.kind != KeyEventKind::Release => translate(key),
        _ => None,
    })
}

pub fn read_key() -> Result<Key> {
    loop {
        if let Some(key) = poll_key(Duration::from_millis(200))? {
            return Ok(key);
        }
    }
}

fn translate(key: KeyEvent) -> Option<Key> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') => Some(Key::Escape),
            _ => None,
        };
    }
    Some(match key.code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Escape,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Tab => Key::Tab,
        KeyCode::Char(' ') => Key::Space,
        KeyCode::Char(ch) => Key::Char(ch),
        _ => return None,
    })
}

/// Латинская буква для «горячей» клавиши, устойчивая к русской раскладке:
/// пользователь нередко забывает переключить её перед нажатием.
pub fn hotkey(key: Key) -> Option<char> {
    let Key::Char(ch) = key else { return None };
    let lower = ch.to_lowercase().next()?;
    Some(match lower {
        'ф' => 'a',
        'в' => 'd',
        'з' => 'p',
        'ы' => 's',
        'е' => 't',
        'к' => 'r',
        'й' => 'q',
        'ь' => 'm',
        other => other,
    })
}

/// Курсорная навигация по списку известной длины.
pub fn move_cursor(index: usize, len: usize, key: Key, page: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let last = len - 1;
    match key {
        Key::Up => index.saturating_sub(1),
        Key::Down => (index + 1).min(last),
        Key::PageUp => index.saturating_sub(page.max(1)),
        Key::PageDown => (index + page.max(1)).min(last),
        Key::Home => 0,
        Key::End => last,
        _ => index.min(last),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_stays_in_range() {
        assert_eq!(move_cursor(0, 3, Key::Up, 5), 0);
        assert_eq!(move_cursor(2, 3, Key::Down, 5), 2);
        assert_eq!(move_cursor(0, 3, Key::End, 5), 2);
        assert_eq!(move_cursor(2, 3, Key::PageUp, 5), 0);
        assert_eq!(move_cursor(5, 3, Key::Down, 5), 2);
        assert_eq!(move_cursor(0, 0, Key::Down, 5), 0);
    }

    #[test]
    fn hotkeys_survive_russian_layout() {
        assert_eq!(hotkey(Key::Char('ф')), Some('a'));
        assert_eq!(hotkey(Key::Char('A')), Some('a'));
        assert_eq!(hotkey(Key::Char('й')), Some('q'));
        assert_eq!(hotkey(Key::Enter), None);
    }
}
