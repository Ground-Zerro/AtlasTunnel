use anyhow::{Context, Result};
use std::path::Path;

use crate::fsx::{self, snapshot::Snapshot};

/// Отчёт о ходе установки. Позволяет одному и тому же коду установки
/// работать под TUI и в неинтерактивном режиме.
pub trait Progress {
    fn step(&mut self, title: &str);
    fn info(&mut self, text: &str);
    fn ok(&mut self, text: &str);
    fn warn(&mut self, text: &str);
}

pub struct Silent;

impl Progress for Silent {
    fn step(&mut self, _title: &str) {}
    fn info(&mut self, _text: &str) {}
    fn ok(&mut self, _text: &str) {}
    fn warn(&mut self, _text: &str) {}
}

pub struct Console;

impl Progress for Console {
    fn step(&mut self, title: &str) {
        println!("\n== {title}");
    }
    fn info(&mut self, text: &str) {
        println!("   · {text}");
    }
    fn ok(&mut self, text: &str) {
        println!("   ✓ {text}");
    }
    fn warn(&mut self, text: &str) {
        eprintln!("   ! {text}");
    }
}

/// Транзакция изменения системных файлов: всё, что переписывается, сначала
/// попадает в снимок, поэтому обрыв на середине откатывается целиком.
pub struct Transaction {
    snapshot: Snapshot,
    committed: bool,
}

impl Transaction {
    pub fn new() -> Self {
        Self { snapshot: Snapshot::new(), committed: false }
    }

    pub fn touched(&self) -> usize {
        self.snapshot.len()
    }

    /// Запоминает файл и записывает новое содержимое атомарно.
    pub fn write(&mut self, path: impl AsRef<Path>, contents: &str, mode: u32) -> Result<()> {
        let path = path.as_ref();
        self.snapshot.capture(path)?;
        fsx::write_atomic(path, contents, mode)
            .with_context(|| format!("запись конфигурации {}", path.display()))
    }

    /// Запоминает файл, который будет изменён сторонней командой.
    pub fn guard(&mut self, path: impl AsRef<Path>) -> Result<()> {
        self.snapshot.capture(path.as_ref())
    }


    pub fn commit(mut self) {
        self.committed = true;
    }

    /// Возвращает файлы в исходное состояние и отдаёт список неудавшихся откатов.
    pub fn rollback(mut self) -> Vec<String> {
        self.committed = true;
        std::mem::take(&mut self.snapshot).rollback()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed && !self.snapshot.is_empty() {
            // Паника или ранний выход по `?` мимо явного rollback: возвращаем
            // файлы, иначе система осталась бы в наполовину изменённом виде.
            let failures = std::mem::take(&mut self.snapshot).rollback();
            for failure in failures {
                crate::sys::cmd::note(&format!("[откат не удался] {failure}"));
            }
        }
    }
}
