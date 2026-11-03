//! TPM transports: the kernel character device (`/dev/tpmrm0`) and swtpm's
//! raw command channel over a Unix or TCP socket.

use crate::{Error, Mode, Result};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Largest response accepted from a socket (Go's rawConn limit).
pub const MAX_SOCKET_RESPONSE: usize = 1 << 20;
/// Read buffer for the character device (one read returns one response).
pub const DEVICE_BUFFER: usize = 64 << 10;
const HEADER: usize = 10;
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends one TPM command and returns its complete response.
pub trait Transport: Send {
    /// Writes `cmd` and reads the response (header size checked).
    fn send(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>>;

    /// Drops the connection, if any (sockets redial on the next command).
    fn close(&mut self) {}
}

fn bad_data(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The size field of a response header.
fn header_size(hdr: &[u8]) -> Option<usize> {
    let b: [u8; 4] = hdr.get(2..6)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(b)).ok()
}

/// A TPM character device such as `/dev/tpmrm0` (the kernel resource
/// manager): one write per command, one read per response.
#[derive(Debug)]
pub struct CharDevice {
    file: std::fs::File,
    path: PathBuf,
}

impl CharDevice {
    /// Opens the device read-write.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file, path: path.to_owned() })
    }
}

impl Transport for CharDevice {
    fn send(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        self.file.write_all(cmd)?;
        let mut buf = vec![0u8; DEVICE_BUFFER];
        let n = self.file.read(&mut buf)?;
        buf.truncate(n);
        match header_size(&buf) {
            Some(size) if n >= HEADER && size == n => Ok(buf),
            Some(size) => Err(bad_data(format!("{}: response header says {size} bytes, read {n}", self.path.display()))),
            None => Err(bad_data(format!("{}: short response ({n} bytes)", self.path.display()))),
        }
    }
}

#[derive(Debug, Clone)]
enum Addr {
    #[cfg(unix)]
    Unix(PathBuf),
    Tcp(String),
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Unix(p) => write!(f, "{}", p.display()),
            Self::Tcp(a) => f.write_str(a),
        }
    }
}

#[derive(Debug)]
enum Stream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Tcp(TcpStream),
}

impl Stream {
    fn exchange(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => exchange(s, cmd),
            Self::Tcp(s) => exchange(s, cmd),
        }
    }
}

/// Writes a command and reads one response: a 10-byte header whose size
/// field (10 bytes to 1 MiB) gives the rest.
fn exchange<S: Read + Write>(s: &mut S, cmd: &[u8]) -> io::Result<Vec<u8>> {
    s.write_all(cmd)?;
    let mut hdr = [0u8; HEADER];
    s.read_exact(&mut hdr)?;
    let size = header_size(&hdr).unwrap_or(0);
    if !(HEADER..=MAX_SOCKET_RESPONSE).contains(&size) {
        return Err(bad_data(format!("tpmdev: bad response size {size}")));
    }
    let mut rsp = vec![0u8; size];
    let (head, rest) = rsp.split_at_mut(HEADER);
    head.copy_from_slice(&hdr);
    s.read_exact(rest)?;
    Ok(rsp)
}

/// swtpm's server channel (`swtpm socket --server type=unixio|tcp`): a raw
/// TPM command in, a raw response out. On any I/O error the connection is
/// dropped and the next command redials (Go's `rawConn`).
#[derive(Debug)]
pub struct RawSocket {
    addr: Addr,
    conn: Option<Stream>,
}

impl RawSocket {
    /// Connects to a Unix socket.
    #[cfg(unix)]
    pub fn unix(path: &Path) -> io::Result<Self> {
        Self::connect(Addr::Unix(path.to_owned()))
    }

    /// Connects to `host:port`.
    pub fn tcp(addr: &str) -> io::Result<Self> {
        Self::connect(Addr::Tcp(addr.to_owned()))
    }

    fn connect(addr: Addr) -> io::Result<Self> {
        let mut s = Self { addr, conn: None };
        s.dial()?;
        Ok(s)
    }

    fn dial(&mut self) -> io::Result<()> {
        let stream = match &self.addr {
            #[cfg(unix)]
            Addr::Unix(p) => {
                let s = std::os::unix::net::UnixStream::connect(p)?;
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                Stream::Unix(s)
            }
            Addr::Tcp(a) => {
                let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{a}: no address"));
                let mut found = None;
                for sa in a.to_socket_addrs()? {
                    match TcpStream::connect_timeout(&sa, DIAL_TIMEOUT) {
                        Ok(s) => {
                            found = Some(s);
                            break;
                        }
                        Err(e) => last = e,
                    }
                }
                let s = found.ok_or(last)?;
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                Stream::Tcp(s)
            }
        };
        self.conn = Some(stream);
        Ok(())
    }
}

impl Transport for RawSocket {
    fn send(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        if self.conn.is_none() {
            self.dial()?;
        }
        let Some(conn) = self.conn.as_mut() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "tpmdev: not connected"));
        };
        let r = conn.exchange(cmd);
        if r.is_err() {
            // The stream may be out of sync: start over on the next command.
            self.conn = None;
        }
        r
    }

    fn close(&mut self) {
        self.conn = None;
    }
}

/// Opens a TPM transport:
///
/// ```text
/// /dev/tpmrm0                  the platform TPM through the kernel resource manager
/// swtpm:unix:/path/to/socket   swtpm socket --server type=unixio
/// swtpm:tcp:127.0.0.1:2321     swtpm socket --server type=tcp
/// ```
pub fn open(spec: &str) -> Result<(Box<dyn Transport>, Mode)> {
    let io = |context: String| move |source: io::Error| Error::Io { context, source };
    if spec.starts_with("/dev/") {
        let t = CharDevice::open(Path::new(spec)).map_err(io(format!("open {spec}")))?;
        return Ok((Box::new(t), Mode::Hardware));
    }
    if let Some(path) = spec.strip_prefix("swtpm:unix:") {
        #[cfg(unix)]
        {
            let t = RawSocket::unix(Path::new(path)).map_err(io(format!("connect to swtpm at {path}")))?;
            return Ok((Box::new(t), Mode::Swtpm));
        }
        #[cfg(not(unix))]
        return Err(Error::invalid(format!("Unix sockets are not supported here ({path})")));
    }
    if let Some(addr) = spec.strip_prefix("swtpm:tcp:") {
        let t = RawSocket::tcp(addr).map_err(io(format!("connect to swtpm at {addr}")))?;
        return Ok((Box::new(t), Mode::Swtpm));
    }
    Err(Error::invalid(format!("unknown TPM {spec:?}")))
}
