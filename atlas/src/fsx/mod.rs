pub mod lock;
pub mod snapshot;

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("установка прав {mode:o} на {}", path.display()))
}

/// Запись через временный файл в том же каталоге и `rename` — операция атомарна,
/// частично записанный конфиг не может оказаться на месте рабочего.
pub fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("нет родительского каталога у {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("создание каталога {}", parent.display()))?;

    let mut temp = tempfile::Builder::new()
        .prefix(".atlas-")
        .tempfile_in(parent)
        .with_context(|| format!("временный файл в {}", parent.display()))?;

    use std::io::Write;
    temp.write_all(contents.as_bytes())
        .with_context(|| format!("запись {}", path.display()))?;
    temp.as_file().sync_all()?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;

    temp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("замена {}", path.display()))?;
    Ok(())
}

pub fn read_opt(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("чтение {}", path.display())),
    }
}

pub fn mode_of(path: &Path) -> Option<u32> {
    fs::metadata(path).ok().map(|meta| meta.permissions().mode() & 0o7777)
}

pub fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("удаление {}", path.display())),
    }
}
