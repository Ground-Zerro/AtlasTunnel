use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Межпроцессная блокировка: не даёт двум копиям atlas одновременно править
/// файлы учётных записей и конфигурацию.
pub struct Lock {
    file: File,
}

impl Lock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("открытие файла блокировки {}", path.display()))?;

        if file.try_lock_exclusive().is_err() {
            anyhow::bail!(
                "другой экземпляр atlas уже выполняется (блокировка {})",
                path.display()
            );
        }
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}
