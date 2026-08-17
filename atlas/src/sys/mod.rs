pub mod cmd;
pub mod legacy;
pub mod net;
pub mod pkg;
pub mod systemd;

use anyhow::{bail, Result};

pub fn require_root() -> Result<()> {
    let uid = cmd::Cmd::new("id").arg("-u").stdout()?;
    if uid.trim() != "0" {
        bail!("требуется root: запустите через sudo");
    }
    Ok(())
}
