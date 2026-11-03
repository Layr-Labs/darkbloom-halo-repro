//! A swtpm process for tests and demos.

use crate::Error;
use db_tpmdev::Device;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const START_POLLS: usize = 100;
const POLL: Duration = Duration::from_millis(50);
const STOP_GRACE: Duration = Duration::from_secs(3);

/// A running `swtpm socket --tpm2` with its state in `<dir>/state`.
/// Restarting with the same directory simulates a reboot of the same chip.
/// Stopped (SIGINT, then SIGKILL after 3 s) on drop.
#[derive(Debug)]
pub struct Swtpm {
    dir: PathBuf,
    sock: PathBuf,
    child: Option<Child>,
    // Unix socket paths are limited to ~104 bytes on macOS, so sockets live
    // in a short directory under /tmp; the TPM state stays in `dir`.
    sock_dir: tempfile::TempDir,
}

fn is_executable(p: &Path) -> bool {
    match std::fs::metadata(p) {
        #[cfg(unix)]
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt as _;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

impl Swtpm {
    /// The swtpm binary: `$SWTPM`, else `swtpm` on `PATH`.
    pub fn binary() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("SWTPM").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).map(|d| d.join("swtpm")).find(|p| is_executable(p))
    }

    /// Starts swtpm with its state in `<dir>/state` (created 0700).
    pub fn start(dir: &Path) -> Result<Swtpm, Error> {
        let bin = Self::binary().ok_or(Error::NotInstalled)?;
        let state = dir.join("state");
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(&state).map_err(Error::io(format!("create {}", state.display())))?;
        let sock_dir = tempfile::Builder::new().prefix("dbtpm").tempdir_in("/tmp").map_err(Error::io("socket directory"))?;
        let sock = sock_dir.path().join("swtpm.sock");
        let ctrl = sock_dir.path().join("swtpm.ctrl");
        let mut child = Command::new(&bin)
            .arg("socket")
            .arg("--tpm2")
            .arg("--server")
            .arg(format!("type=unixio,path={}", sock.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}", ctrl.display()))
            .arg("--tpmstate")
            .arg(format!("dir={}", state.display()))
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .stdin(Stdio::null())
            .spawn()
            .map_err(Error::io(format!("start {}", bin.display())))?;
        for _ in 0..START_POLLS {
            if sock.exists() {
                return Ok(Swtpm { dir: dir.to_owned(), sock, child: Some(child), sock_dir });
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(Error::setup(format!("swtpm exited during startup ({status})")));
            }
            std::thread::sleep(POLL);
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(Error::setup(format!("swtpm did not create {}", sock.display())))
    }

    /// The `Device::open` spec for this swtpm.
    pub fn spec(&self) -> String {
        format!("swtpm:unix:{}", self.sock.display())
    }

    /// The directory holding the TPM state (`<dir>/state`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The server socket.
    pub fn socket(&self) -> &Path {
        &self.sock
    }

    /// The directory holding the sockets.
    pub fn socket_dir(&self) -> &Path {
        self.sock_dir.path()
    }

    /// Opens the TPM, retrying for up to two seconds while swtpm starts
    /// listening (it serves one connection at a time).
    pub fn open_device(&self) -> Result<Arc<Device>, Error> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match Device::open(&self.spec()) {
                Ok(d) => return Ok(d),
                Err(e @ db_tpmdev::Error::Io { .. }) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(Error::setup(e)),
            }
        }
    }

    /// The swtpm process ID, while running.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Terminates swtpm: SIGINT (via `kill -INT`), then SIGKILL if it has
    /// not exited within 3 seconds. Idempotent.
    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        let _ = Command::new("kill").arg("-INT").arg(child.id().to_string()).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        self.stop();
    }
}
