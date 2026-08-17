use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "atlas",
    version,
    about = "AtlasTunnel — установка и управление VPN-сервером",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Вывести результат в JSON вместо текста
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Установить протоколы (без аргументов — интерфейс выбора)
    Install(InstallArgs),
    /// Удалить протокол вместе с правилами и службами
    Uninstall {
        protocol: String,
        /// Не спрашивать подтверждение
        #[arg(long)]
        yes: bool,
    },
    /// Показать установленные протоколы и их состояние
    List,
    /// Запустить службы протокола (или всех)
    Start { protocol: Option<String> },
    /// Остановить службы протокола (или всех)
    Stop { protocol: Option<String> },
    /// Перезапустить службы протокола (или всех)
    Restart { protocol: Option<String> },
    /// Управление учётными записями
    #[command(subcommand)]
    Client(ClientCommand),
    /// Сверить заявленное состояние с фактическим
    Doctor,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Список протоколов через запятую, например pptp,l2tp-ipsec
    #[arg(long, value_delimiter = ',')]
    pub protocols: Vec<String>,

    /// Совместимый набор всех протоколов
    #[arg(long, conflicts_with = "protocols")]
    pub all: bool,

    /// Имя первой учётной записи
    #[arg(long, default_value = "vpnuser")]
    pub user: String,

    /// Не запрашивать подтверждение — режим для автоматизации
    #[arg(long)]
    pub yes: bool,

    /// Запретить загрузку пакетов из архивов прошлых выпусков Ubuntu
    #[arg(long)]
    pub no_legacy_packages: bool,

    /// Домен для доверенного сертификата SSTP через Let's Encrypt.
    /// Без него выпускается самоподписанный, требующий импорта на клиенте.
    #[arg(long, value_name = "FQDN")]
    pub domain: Option<String>,

    /// Адрес для уведомлений Let's Encrypt об истечении сертификата
    #[arg(long, value_name = "EMAIL", requires = "domain")]
    pub email: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ClientCommand {
    /// Показать учётные записи протокола
    List {
        protocol: String,
        /// Показать пароли открытым текстом
        #[arg(long)]
        reveal: bool,
    },
    /// Добавить учётную запись со случайным паролем
    Add { protocol: String, login: String },
    /// Удалить учётную запись
    Remove { protocol: String, login: String },
    /// Сгенерировать новый пароль
    Passwd { protocol: String, login: String },
}
