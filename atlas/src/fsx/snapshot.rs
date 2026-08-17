use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{mode_of, set_mode};

#[derive(Debug)]
enum Original {
    Absent,
    Present { bytes: Vec<u8>, mode: u32 },
}

/// Снимок файлов до изменения. Позволяет вернуть систему в исходное состояние,
/// если установка оборвалась на середине.
#[derive(Debug, Default)]
pub struct Snapshot {
    entries: BTreeMap<PathBuf, Original>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Запоминает файл, если он ещё не в снимке. Повторный вызов не перезаписывает
    /// исходное состояние, поэтому несколько правок одного файла откатятся к самому первому.
    pub fn capture(&mut self, path: &Path) -> Result<()> {
        if self.entries.contains_key(path) {
            return Ok(());
        }
        let original = match fs::read(path) {
            Ok(bytes) => Original::Present {
                bytes,
                mode: mode_of(path).unwrap_or(0o644),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Original::Absent,
            Err(err) => {
                return Err(err).with_context(|| format!("снимок {}", path.display()))
            }
        };
        self.entries.insert(path.to_path_buf(), original);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }


    /// Восстанавливает все запомненные файлы. Ошибки отдельных файлов накапливаются,
    /// но не прерывают откат остальных.
    pub fn rollback(self) -> Vec<String> {
        let mut failures = Vec::new();
        for (path, original) in self.entries {
            let outcome = match original {
                Original::Absent => super::remove_if_exists(&path),
                Original::Present { bytes, mode } => restore(&path, &bytes, mode),
            };
            if let Err(err) = outcome {
                failures.push(format!("{}: {err:#}", path.display()));
            }
        }
        failures
    }
}

fn restore(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes).with_context(|| format!("восстановление {}", path.display()))?;
    set_mode(path, mode)
}
