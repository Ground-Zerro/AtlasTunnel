use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::sync::Mutex;
use std::sync::OnceLock;

static TRANSCRIPT: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn transcript() -> &'static Mutex<Option<File>> {
    TRANSCRIPT.get_or_init(|| Mutex::new(None))
}

pub fn open_transcript(path: &Path) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("создание каталога журнала {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("открытие журнала {}", path.display()))?;
    crate::fsx::set_mode(path, 0o600)?;
    *transcript().lock().unwrap() = Some(file);
    Ok(path.to_path_buf())
}

pub fn note(text: &str) {
    if let Some(file) = transcript().lock().unwrap().as_mut() {
        let _ = writeln!(file, "{text}");
    }
}

#[derive(Debug)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    /// Необработанные байты stdout. `ipsec pki --pub` по умолчанию отдаёт DER,
    /// и конвертация в UTF-8 портит ключ, поэтому конвейеры используют байты.
    pub stdout_bytes: Vec<u8>,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    pub fn trimmed(&self) -> &str {
        self.stdout.trim()
    }

    /// Последняя содержательная строка stderr — для краткого сообщения об ошибке.
    pub fn failure_reason(&self) -> String {
        self.stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("код выхода {}", self.status))
    }
}

/// Верхняя граница для любой команды. Установка пакетов и генерация параметров
/// Диффи-Хеллмана занимают минуты, поэтому запас большой — задача предела не
/// торопить работу, а не дать зависшему процессу заморозить установку навсегда.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(900);

pub struct Cmd {
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    stdin_data: Option<Vec<u8>>,
    timeout: Duration,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            stdin_data: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Отдельный предел для команд, которые обязаны отвечать быстро:
    /// обращения к сети и опросы состояния.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout = Duration::from_secs(seconds);
        self
    }

    pub fn arg(mut self, value: impl AsRef<OsStr>) -> Self {
        self.args.push(value.as_ref().to_string_lossy().into_owned());
        self
    }

    pub fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for value in values {
            self.args.push(value.as_ref().to_string_lossy().into_owned());
        }
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    pub fn stdin(mut self, data: Vec<u8>) -> Self {
        self.stdin_data = Some(data);
        self
    }

    fn rendered(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            line.push_str(arg);
        }
        line
    }

    /// Запускает команду и возвращает результат независимо от кода выхода.
    pub fn capture(self) -> Result<Output> {
        let rendered = self.rendered();
        note(&format!("$ {rendered}"));

        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(if self.stdin_data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in &self.envs {
            command.env(key, value);
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("не удалось запустить: {rendered}"))?;

        if let Some(data) = &self.stdin_data {
            child
                .stdin
                .as_mut()
                .context("нет канала stdin")?
                .write_all(data)?;
        }
        drop(child.stdin.take());

        // Потоки-читатели нужны, чтобы процесс не встал на переполненном пайпе,
        // пока мы ждём его завершения по таймеру.
        let mut out_pipe = child.stdout.take().context("нет канала stdout")?;
        let mut err_pipe = child.stderr.take().context("нет канала stderr")?;
        let out_reader = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = out_pipe.read_to_end(&mut buffer);
            buffer
        });
        let err_reader = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = err_pipe.read_to_end(&mut buffer);
            buffer
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait()? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    note(&format!("[превышен предел {} с]", self.timeout.as_secs()));
                    bail!(
                        "команда не завершилась за {} с и была прервана: {rendered}",
                        self.timeout.as_secs()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };

        let stdout_bytes = out_reader.join().unwrap_or_default();
        let stderr_bytes = err_reader.join().unwrap_or_default();

        let output = Output {
            status: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            stdout_bytes,
        };

        if !output.stdout.trim().is_empty() {
            note(&output.stdout);
        }
        if !output.stderr.trim().is_empty() {
            note(&output.stderr);
        }
        if !output.ok() {
            note(&format!("[код выхода {}]", output.status));
        }
        Ok(output)
    }

    /// Запускает команду и превращает ненулевой код выхода в ошибку с текстом stderr.
    pub fn run(self) -> Result<Output> {
        let rendered = self.rendered();
        let output = self.capture()?;
        if !output.ok() {
            bail!("{rendered}: {}", output.failure_reason());
        }
        Ok(output)
    }

    /// Только признак успеха: для проверок, где ненулевой код — штатный ответ.
    pub fn succeeded(self) -> bool {
        matches!(self.capture(), Ok(output) if output.ok())
    }

    pub fn stdout(self) -> Result<String> {
        Ok(self.run()?.trimmed().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hanging_command_is_interrupted_not_awaited_forever() {
        let started = Instant::now();
        let result = Cmd::new("sleep").arg("60").timeout(1).capture();
        assert!(result.is_err(), "зависшая команда должна дать ошибку");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "предел не сработал: прошло {:?}",
            started.elapsed()
        );
        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("не завершилась"), "неинформативно: {message}");
    }

    #[test]
    fn output_is_captured_in_full_despite_reader_threads() {
        let output = Cmd::new("sh")
            .arg("-c")
            .arg("seq 1 5000")
            .timeout(30)
            .capture()
            .expect("команда должна отработать");
        assert!(output.ok());
        assert_eq!(output.stdout.lines().count(), 5000);
    }

    #[test]
    fn stderr_and_exit_code_survive() {
        let output = Cmd::new("sh")
            .arg("-c")
            .arg("echo беда >&2; exit 3")
            .timeout(30)
            .capture()
            .expect("команда должна отработать");
        assert_eq!(output.status, 3);
        assert!(output.failure_reason().contains("беда"));
    }
}

pub fn which(program: &str) -> bool {
    Cmd::new("sh").arg("-c").arg(format!("command -v {program}")).succeeded()
}
