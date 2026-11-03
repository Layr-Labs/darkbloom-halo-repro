//! HTTPS and WSS for the coordinator: a listener for `axum::serve` that
//! completes rustls handshakes (TLS 1.3 only, see `db_tls::server_config`)
//! before handing connections to the router. Handshakes run concurrently,
//! each bounded in time, so a slow or silent client cannot hold up accepts.

use db_log::{Logger, logf};
use db_tls::rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; further connections wait in the backlog.
const MAX_HANDSHAKES: usize = 256;

/// Accepts TCP connections and yields them once the TLS handshake is done.
/// Failed handshakes are logged and dropped.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    accept: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener").field("local", &self.local).finish_non_exhaustive()
    }
}

impl TlsListener {
    /// Starts accepting on `listener` (call inside a tokio runtime).
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>, logger: Logger) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        let accept = tokio::spawn(accept_loop(listener, TlsAcceptor::from(config), tx, logger));
        Ok(Self { rx, local, accept })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>, logger: Logger) {
    let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else { return };
        let (tcp, addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                // As axum does: connection errors are the peer's problem;
                // anything else (e.g. out of file descriptors) backs off.
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
                ) {
                    logf!(logger, "accept: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        if tx.is_closed() {
            return;
        }
        let (acceptor, tx, logger) = (acceptor.clone(), tx.clone(), logger.clone());
        tokio::spawn(async move {
            let res = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
            drop(slot);
            match res {
                Ok(Ok(tls)) => {
                    let _ = tx.send((tls, addr)).await;
                }
                Ok(Err(e)) => logf!(logger, "TLS handshake with {addr} failed: {e}"),
                Err(_) => logf!(logger, "TLS handshake with {addr} timed out"),
            }
        });
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept loop only ends when this listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
