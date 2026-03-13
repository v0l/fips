//! Tor Transport Implementation
//!
//! Provides Tor-based transport for FIPS peer communication via SOCKS5
//! proxy. Enables anonymous outbound connections to both clearnet peers
//! and .onion hidden services.
//!
//! ## Architecture
//!
//! Like TCP, each peer has its own connection through the SOCKS5 proxy.
//! The transport reuses FMP stream framing from `tcp::stream` and follows
//! the same connection pool pattern as the TCP transport.
//!
//! ## Phase 1: Outbound SOCKS5 Only
//!
//! This implementation covers outbound connections through a local Tor
//! daemon's SOCKS5 port. Inbound via onion service is Phase 2.

pub mod stats;

#[cfg(test)]
mod mock_socks5;

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::TorConfig;
use crate::transport::tcp::stream::read_fmp_packet;
use stats::TorStats;

use futures::FutureExt;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Tor Address Types
// ============================================================================

/// Tor-specific address type for SOCKS5 CONNECT.
#[derive(Clone, Debug)]
pub enum TorAddr {
    /// .onion hidden service address (hostname, port).
    Onion(String, u16),
    /// Clearnet address routed through Tor (IP, port).
    Clearnet(SocketAddr),
}

/// Parse a TransportAddr string into a TorAddr.
///
/// If the address contains ".onion:", parse as an onion address.
/// Otherwise, attempt to parse as a socket address for clearnet.
fn parse_tor_addr(addr: &TransportAddr) -> Result<TorAddr, TransportError> {
    let s = addr.as_str().ok_or_else(|| {
        TransportError::InvalidAddress("Tor address must be a valid UTF-8 string".into())
    })?;

    if s.contains(".onion:") {
        // Parse "hostname.onion:port"
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("invalid onion address: {}", s))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            TransportError::InvalidAddress(format!("invalid port in onion address: {}", s))
        })?;
        Ok(TorAddr::Onion(host.to_string(), port))
    } else {
        // Parse as clearnet IP:port
        let socket_addr: SocketAddr = s.parse().map_err(|_| {
            TransportError::InvalidAddress(format!("invalid clearnet address: {}", s))
        })?;
        Ok(TorAddr::Clearnet(socket_addr))
    }
}

// ============================================================================
// Connection Pool
// ============================================================================

/// State for a single Tor connection to a peer.
struct TorConnection {
    /// Write half of the split stream.
    writer: Arc<Mutex<OwnedWriteHalf>>,
    /// Receive task for this connection.
    recv_task: JoinHandle<()>,
    /// MTU for this connection.
    #[allow(dead_code)]
    mtu: u16,
    /// When the connection was established.
    #[allow(dead_code)]
    established_at: Instant,
}

/// Shared connection pool.
type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, TorConnection>>>;

/// A pending background connection attempt.
///
/// Holds the JoinHandle for a spawned SOCKS5 connect task. The task
/// produces a configured `TcpStream` and MTU on success.
struct ConnectingEntry {
    /// Background task performing SOCKS5 connect + socket configuration.
    task: JoinHandle<Result<(TcpStream, u16), TransportError>>,
}

/// Map of addresses with background connection attempts in progress.
type ConnectingPool = Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>;

// ============================================================================
// Tor Transport
// ============================================================================

/// Tor transport for FIPS.
///
/// Provides connection-oriented, reliable byte stream delivery over Tor
/// via SOCKS5 proxy. Each peer has its own connection through the proxy;
/// links are managed per-connection with a connection pool keyed by
/// `TransportAddr`.
pub struct TorTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: TorConfig,
    /// Current state.
    state: TransportState,
    /// Connection pool: addr -> per-connection state.
    pool: ConnectionPool,
    /// Pending connection attempts: addr -> background connect task.
    connecting: ConnectingPool,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Transport statistics.
    stats: Arc<TorStats>,
}

impl TorTransport {
    /// Create a new Tor transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: TorConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            pool: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            stats: Arc::new(TorStats::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<TorStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// Validates configuration and transitions to Up state.
    /// Phase 1 is outbound-only — no listener is started.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Validate SOCKS5 address format (IP:port or host:port)
        let socks5_addr = self.config.socks5_addr();
        if socks5_addr.parse::<SocketAddr>().is_err() {
            // Not a raw IP:port — check it's at least host:port format
            let parts: Vec<&str> = socks5_addr.rsplitn(2, ':').collect();
            if parts.len() != 2
                || parts[0].parse::<u16>().is_err()
                || parts[1].is_empty()
            {
                return Err(TransportError::StartFailed(format!(
                    "invalid socks5_addr '{}': expected host:port or IP:port",
                    socks5_addr
                )));
            }
        }

        // Validate mode
        if self.config.mode() != "socks5" {
            return Err(TransportError::StartFailed(format!(
                "unsupported Tor mode '{}' (only 'socks5' is supported)",
                self.config.mode()
            )));
        }

        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                socks5_addr = %socks5_addr,
                mtu = self.config.mtu(),
                "Tor transport started"
            );
        } else {
            info!(
                socks5_addr = %socks5_addr,
                mtu = self.config.mtu(),
                "Tor transport started"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort pending connection attempts
        let mut connecting = self.connecting.lock().await;
        for (addr, entry) in connecting.drain() {
            entry.task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Tor connect aborted (transport stopping)"
            );
        }
        drop(connecting);

        // Close all connections
        let mut pool = self.pool.lock().await;
        for (addr, conn) in pool.drain() {
            conn.recv_task.abort();
            let _ = conn.recv_task.await;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Tor connection closed (transport stopping)"
            );
        }
        drop(pool);

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "Tor transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// If no connection exists to the given address, performs connect-on-send:
    /// establishes a new connection through the SOCKS5 proxy, configures
    /// socket options, splits the stream, spawns a receive task, and stores
    /// the connection in the pool.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Pre-send MTU check
        let mtu = self.config.mtu() as usize;
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        // Get or create connection
        let writer = {
            let pool = self.pool.lock().await;
            pool.get(addr).map(|c| c.writer.clone())
        };

        let writer = match writer {
            Some(w) => w,
            None => {
                // Connect-on-send
                self.connect(addr).await?
            }
        };

        // Write packet directly (no framing transformation needed)
        let mut w = writer.lock().await;
        match w.write_all(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                trace!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    bytes = data.len(),
                    "Tor packet sent"
                );
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                drop(w);
                // Remove failed connection from pool
                let mut pool = self.pool.lock().await;
                if let Some(conn) = pool.remove(addr) {
                    conn.recv_task.abort();
                }
                Err(TransportError::SendFailed(format!("{}", e)))
            }
        }
    }

    /// Establish a new connection through the SOCKS5 proxy.
    ///
    /// Performs SOCKS5 CONNECT to the target via the proxy, configures
    /// socket options, splits the stream, spawns a receive task, and
    /// stores in the pool.
    async fn connect(
        &self,
        addr: &TransportAddr,
    ) -> Result<Arc<Mutex<OwnedWriteHalf>>, TransportError> {
        let tor_addr = parse_tor_addr(addr)?;
        let proxy_addr = self.config.socks5_addr();
        let timeout_ms = self.config.connect_timeout_ms();

        info!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            proxy = %proxy_addr,
            timeout_secs = timeout_ms / 1000,
            "Connecting via Tor SOCKS5"
        );

        // SOCKS5 CONNECT through proxy with timeout
        let connect_start = Instant::now();
        let socks_result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            match &tor_addr {
                TorAddr::Onion(host, port) => {
                    Socks5Stream::connect(proxy_addr, (host.as_str(), *port)).await
                }
                TorAddr::Clearnet(socket_addr) => {
                    Socks5Stream::connect(proxy_addr, *socket_addr).await
                }
            }
        })
        .await;

        let stream = match socks_result {
            Ok(Ok(socks_stream)) => socks_stream.into_inner(),
            Ok(Err(e)) => {
                self.stats.record_socks5_error();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    error = %e,
                    elapsed_secs = connect_start.elapsed().as_secs(),
                    "Tor SOCKS5 connection failed"
                );
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %addr,
                    timeout_secs = timeout_ms / 1000,
                    "Tor SOCKS5 connection timed out"
                );
                return Err(TransportError::Timeout);
            }
        };

        // Configure socket options via socket2
        let std_stream = stream
            .into_std()
            .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
        configure_socket(&std_stream, &self.config)?;

        // Convert back to tokio
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

        // Split and spawn receive task
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();
        let mtu = self.config.mtu();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let conn = TorConnection {
            writer: writer.clone(),
            recv_task,
            mtu,
            established_at: Instant::now(),
        };

        let mut pool = self.pool.lock().await;
        pool.insert(addr.clone(), conn);

        self.stats.record_connection_established();

        info!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            elapsed_secs = connect_start.elapsed().as_secs(),
            "Tor circuit established via SOCKS5"
        );

        Ok(writer)
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// Spawns a background task that performs SOCKS5 connect with timeout,
    /// configures socket options, and returns the configured stream. The
    /// connection becomes available for `send_async()` once the task
    /// completes successfully.
    ///
    /// Poll `connection_state_sync()` to check progress.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Already established?
        {
            let pool = self.pool.lock().await;
            if pool.contains_key(addr) {
                return Ok(());
            }
        }

        // Already connecting?
        {
            let connecting = self.connecting.lock().await;
            if connecting.contains_key(addr) {
                return Ok(());
            }
        }

        let tor_addr = parse_tor_addr(addr)?;
        let proxy_addr = self.config.socks5_addr().to_string();
        let timeout_ms = self.config.connect_timeout_ms();
        let transport_id = self.transport_id;
        let remote_addr = addr.clone();
        let config = self.config.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            timeout_ms,
            "Initiating background Tor SOCKS5 connect"
        );

        let task = tokio::spawn(async move {
            // SOCKS5 CONNECT through proxy with timeout
            let socks_result = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                async {
                    match &tor_addr {
                        TorAddr::Onion(host, port) => {
                            Socks5Stream::connect(proxy_addr.as_str(), (host.as_str(), *port)).await
                        }
                        TorAddr::Clearnet(socket_addr) => {
                            Socks5Stream::connect(proxy_addr.as_str(), *socket_addr).await
                        }
                    }
                },
            )
            .await;

            let stream = match socks_result {
                Ok(Ok(socks_stream)) => socks_stream.into_inner(),
                Ok(Err(e)) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        "Background Tor SOCKS5 connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Background Tor SOCKS5 connect timed out"
                    );
                    return Err(TransportError::Timeout);
                }
            };

            // Configure socket options via socket2
            let std_stream = stream
                .into_std()
                .map_err(|e| TransportError::StartFailed(format!("into_std: {}", e)))?;
            configure_socket(&std_stream, &config)?;

            let mtu = config.mtu();

            // Convert back to tokio
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| TransportError::StartFailed(format!("from_std: {}", e)))?;

            Ok((stream, mtu))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection to a remote address.
    ///
    /// Checks both established and connecting pools. If a background
    /// connect task has completed, promotes it to the established pool
    /// (spawning a receive loop) or reports the failure.
    ///
    /// This method is synchronous but uses `try_lock` internally.
    /// Returns `ConnectionState::Connecting` if locks can't be acquired.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool first
        if let Ok(pool) = self.pool.try_lock() {
            if pool.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting; // can't tell, assume still going
        }

        // Check connecting pool
        let mut connecting = match self.connecting.try_lock() {
            Ok(c) => c,
            Err(_) => return ConnectionState::Connecting,
        };

        let entry = match connecting.get_mut(addr) {
            Some(e) => e,
            None => return ConnectionState::None,
        };

        // Check if the background task has completed
        if !entry.task.is_finished() {
            return ConnectionState::Connecting;
        }

        // Task is done — take the result and remove from connecting pool.
        let addr_clone = addr.clone();
        let task = connecting.remove(&addr_clone).unwrap().task;

        // Since the task is finished, we can safely poll it with now_or_never.
        match task.now_or_never() {
            Some(Ok(Ok((stream, mtu)))) => {
                // Promote to established pool
                self.promote_connection(addr, stream, mtu);
                ConnectionState::Connected
            }
            Some(Ok(Err(e))) => ConnectionState::Failed(format!("{}", e)),
            Some(Err(e)) => {
                // JoinError (panic or cancel)
                ConnectionState::Failed(format!("task failed: {}", e))
            }
            None => {
                // Shouldn't happen since is_finished() was true
                ConnectionState::Connecting
            }
        }
    }

    /// Promote a completed background connection to the established pool.
    ///
    /// Splits the stream, spawns a receive loop, and inserts into the pool.
    /// Called from `connection_state_sync()` when a background task completes.
    fn promote_connection(&self, addr: &TransportAddr, stream: TcpStream, mtu: u16) {
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let pool = self.pool.clone();
        let recv_stats = self.stats.clone();
        let remote_addr = addr.clone();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                transport_id,
                remote_addr.clone(),
                packet_tx,
                pool,
                mtu,
                recv_stats,
            )
            .await;
        });

        let conn = TorConnection {
            writer,
            recv_task,
            mtu,
            established_at: Instant::now(),
        };

        // Use try_lock since we're in a sync context and the pool
        // should be available (connection_state_sync already checked it)
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.insert(addr.clone(), conn);
            self.stats.record_connection_established();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Tor connection established (background connect)"
            );
        } else {
            // Pool locked — abort the recv task, connection will be retried
            conn.recv_task.abort();
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Failed to promote Tor connection (pool locked)"
            );
        }
    }

    /// Close a specific connection asynchronously.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            conn.recv_task.abort();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "Tor connection closed"
            );
        }
    }
}

impl Transport for TorTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::TOR
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for Tor transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for Tor transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for Tor transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn accept_connections(&self) -> bool {
        // Phase 1 is outbound only
        false
    }
}

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection Tor receive loop.
///
/// Reads complete FMP packets using the stream reader, delivers them to
/// the node via the packet channel. On error or EOF, removes the
/// connection from the pool and exits.
async fn tor_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
    stats: Arc<TorStats>,
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Tor receive loop starting"
    );

    loop {
        match read_fmp_packet(&mut reader, mtu).await {
            Ok(data) => {
                stats.record_recv(data.len());

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "Tor packet received"
                );

                let packet = ReceivedPacket::new(transport_id, remote_addr.clone(), data);

                if packet_tx.send(packet).await.is_err() {
                    info!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping Tor receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "Tor receive error, removing connection"
                );
                break;
            }
        }
    }

    // Clean up: remove ourselves from the pool
    let mut pool_guard = pool.lock().await;
    pool_guard.remove(&remote_addr);

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Tor receive loop stopped"
    );
}

// ============================================================================
// Socket Configuration
// ============================================================================

/// Configure socket options on a SOCKS5-connected stream.
///
/// Sets TCP_NODELAY and keepalive on the underlying TCP connection.
fn configure_socket(
    stream: &std::net::TcpStream,
    _config: &TorConfig,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream);

    // TCP_NODELAY — always enable for FIPS (latency-sensitive protocol messages)
    socket
        .set_tcp_nodelay(true)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // TCP keepalive (30s default, matching TCP transport)
    let keepalive_secs = 30u64;
    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_channel;

    fn make_config() -> TorConfig {
        TorConfig {
            socks5_addr: Some("127.0.0.1:19050".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_tor_addr_onion() {
        let addr = TransportAddr::from_string("abcdef1234567890.onion:2121");
        let tor_addr = parse_tor_addr(&addr).unwrap();
        match tor_addr {
            TorAddr::Onion(host, port) => {
                assert_eq!(host, "abcdef1234567890.onion");
                assert_eq!(port, 2121);
            }
            _ => panic!("expected Onion variant"),
        }
    }

    #[test]
    fn test_parse_tor_addr_clearnet() {
        let addr = TransportAddr::from_string("192.168.1.1:8080");
        let tor_addr = parse_tor_addr(&addr).unwrap();
        match tor_addr {
            TorAddr::Clearnet(socket_addr) => {
                assert_eq!(socket_addr, "192.168.1.1:8080".parse::<SocketAddr>().unwrap());
            }
            _ => panic!("expected Clearnet variant"),
        }
    }

    #[test]
    fn test_parse_tor_addr_invalid() {
        let addr = TransportAddr::from_string("not-a-valid-address");
        assert!(parse_tor_addr(&addr).is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = TorConfig::default();
        assert_eq!(config.mode(), "socks5");
        assert_eq!(config.socks5_addr(), "127.0.0.1:9050");
        assert_eq!(config.connect_timeout_ms(), 120000);
        assert_eq!(config.mtu(), 1400);
    }

    #[tokio::test]
    async fn test_start_stop() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);

        transport.stop_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
    }

    #[tokio::test]
    async fn test_double_start_fails() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        transport.start_async().await.unwrap();
        assert!(transport.start_async().await.is_err());
    }

    #[tokio::test]
    async fn test_stop_not_started_fails() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        assert!(transport.stop_async().await.is_err());
    }

    #[tokio::test]
    async fn test_send_not_started() {
        let (tx, _rx) = packet_channel(32);
        let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        let addr = TransportAddr::from_string("127.0.0.1:2121");
        let result = transport.send_async(&addr, &[0u8; 10]).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_type() {
        let (tx, _rx) = packet_channel(32);
        let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        let tt = transport.transport_type();
        assert_eq!(tt.name, "tor");
        assert!(tt.connection_oriented);
        assert!(tt.reliable);
    }

    #[test]
    fn test_sync_methods_return_not_supported() {
        let (tx, _rx) = packet_channel(32);
        let mut transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        assert!(transport.start().is_err());
        assert!(transport.stop().is_err());
        let addr = TransportAddr::from_string("127.0.0.1:2121");
        assert!(transport.send(&addr, &[0u8; 10]).is_err());
    }

    #[test]
    fn test_accept_connections_false() {
        let (tx, _rx) = packet_channel(32);
        let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        assert!(!transport.accept_connections());
    }

    #[test]
    fn test_discover_returns_empty() {
        let (tx, _rx) = packet_channel(32);
        let transport = TorTransport::new(TransportId::new(1), None, make_config(), tx);

        assert!(transport.discover().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_invalid_socks5_addr_start_fails() {
        let (tx, _rx) = packet_channel(32);
        let config = TorConfig {
            socks5_addr: Some("not-a-socket-addr".to_string()),
            ..Default::default()
        };
        let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
        assert!(transport.start_async().await.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_mode_start_fails() {
        let (tx, _rx) = packet_channel(32);
        let config = TorConfig {
            mode: Some("embedded".to_string()),
            socks5_addr: Some("127.0.0.1:9050".to_string()),
            ..Default::default()
        };
        let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
        assert!(transport.start_async().await.is_err());
    }

    // ========================================================================
    // Integration tests using MockSocks5Server
    // ========================================================================

    use mock_socks5::MockSocks5Server;
    use crate::transport::tcp::TcpTransport;
    use crate::config::TcpConfig;

    /// msg1 wire size: 4 prefix + 4 sender_idx + 106 noise_msg1 = 114 bytes.
    const MSG1_WIRE_SIZE: usize = 114;
    /// msg1 payload_len: sender_idx(4) + noise_msg1(106) = 110.
    const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - 4) as u16;

    /// Build a msg1 frame (114 bytes) for testing.
    fn build_msg1_frame() -> Vec<u8> {
        let mut frame = vec![0xAA; MSG1_WIRE_SIZE];
        frame[0] = 0x01; // ver=0, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    #[tokio::test]
    async fn test_send_recv_via_socks5() {
        // Set up a TCP transport as the "destination" with a listener
        let (dest_tx, mut dest_rx) = packet_channel(32);
        let dest_config = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        };
        let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
        dest.start_async().await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        // Set up the mock SOCKS5 proxy pointing at the destination
        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy_handle = mock.spawn();

        // Set up the Tor transport pointing at the mock proxy
        let (tor_tx, _tor_rx) = packet_channel(32);
        let tor_config = TorConfig {
            socks5_addr: Some(proxy_addr.to_string()),
            ..Default::default()
        };
        let mut tor = TorTransport::new(TransportId::new(200), None, tor_config, tor_tx);
        tor.start_async().await.unwrap();

        // Send a valid FMP frame (msg1) through the Tor transport
        let frame = build_msg1_frame();
        let target = TransportAddr::from_string(&dest_addr.to_string());
        tor.send_async(&target, &frame).await.unwrap();

        // Receive it on the destination
        let received = tokio::time::timeout(
            Duration::from_secs(5),
            dest_rx.recv(),
        )
        .await
        .expect("timeout waiting for packet")
        .expect("channel closed");

        assert_eq!(received.data, frame);

        // Clean up
        tor.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_proxy_down() {
        // No SOCKS5 server running on this port
        let (tx, _rx) = packet_channel(32);
        let config = TorConfig {
            socks5_addr: Some("127.0.0.1:19999".to_string()),
            connect_timeout_ms: Some(2000),
            ..Default::default()
        };
        let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();

        let addr = TransportAddr::from_string("192.168.1.1:2121");
        let result = transport.send_async(&addr, &build_msg1_frame()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        // Use a non-routable address as the SOCKS5 proxy to trigger timeout
        let (tx, _rx) = packet_channel(32);
        let config = TorConfig {
            // 192.0.2.1 is TEST-NET, should be non-routable and timeout
            socks5_addr: Some("192.0.2.1:9050".to_string()),
            connect_timeout_ms: Some(500),
            ..Default::default()
        };
        let mut transport = TorTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();

        let addr = TransportAddr::from_string("10.0.0.1:2121");
        let result = transport.send_async(&addr, &build_msg1_frame()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_connection() {
        // Set up destination + mock proxy
        let (dest_tx, _dest_rx) = packet_channel(32);
        let dest_config = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        };
        let mut dest = TcpTransport::new(TransportId::new(100), None, dest_config, dest_tx);
        dest.start_async().await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let mock = MockSocks5Server::new(dest_addr).await.unwrap();
        let proxy_addr = mock.addr();
        let _proxy_handle = mock.spawn();

        let (tor_tx, _tor_rx) = packet_channel(32);
        let tor_config = TorConfig {
            socks5_addr: Some(proxy_addr.to_string()),
            ..Default::default()
        };
        let mut tor = TorTransport::new(TransportId::new(200), None, tor_config, tor_tx);
        tor.start_async().await.unwrap();

        // Send to establish a connection
        let target = TransportAddr::from_string(&dest_addr.to_string());
        tor.send_async(&target, &build_msg1_frame()).await.unwrap();

        // Verify pool has the connection
        {
            let pool = tor.pool.lock().await;
            assert_eq!(pool.len(), 1);
        }

        // Close the connection
        tor.close_connection_async(&target).await;

        // Verify pool is empty
        {
            let pool = tor.pool.lock().await;
            assert_eq!(pool.len(), 0);
        }

        tor.stop_async().await.unwrap();
        dest.stop_async().await.unwrap();
    }
}
