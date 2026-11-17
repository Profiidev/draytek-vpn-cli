//! Userspace TCP/IP stack (smoltcp) on top of the PPP tunnel, plus local TCP port forwards.

use bytes::{Buf, Bytes};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, error::TryRecvError, error::TrySendError};
use tokio::sync::Notify;
use tracing::{debug, warn};

const TCP_BUF: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
/// Chunks buffered per direction per connection; bounded for backpressure.
const CHANNEL_CAP: usize = 8;

/// IP packets queued between the tunnel and smoltcp.
pub struct PacketQueue {
  pub rx: VecDeque<Vec<u8>>,
  pub tx: VecDeque<Vec<u8>>,
  mtu: usize,
}

impl phy::Device for PacketQueue {
  type RxToken<'a> = RxToken;
  type TxToken<'a> = TxToken<'a>;

  fn receive(&mut self, _: SmolInstant) -> Option<(RxToken, TxToken<'_>)> {
    let packet = self.rx.pop_front()?;
    Some((RxToken(packet), TxToken(&mut self.tx)))
  }

  fn transmit(&mut self, _: SmolInstant) -> Option<TxToken<'_>> {
    Some(TxToken(&mut self.tx))
  }

  fn capabilities(&self) -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ip;
    caps.max_transmission_unit = self.mtu;
    caps
  }
}

pub struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
  fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
    f(&self.0)
  }
}

pub struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
  fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
    let mut buf = vec![0; len];
    let r = f(&mut buf);
    self.0.push_back(buf);
    r
  }
}

/// One forwarded connection: a smoltcp socket bridged to a local TCP stream.
struct Conn {
  handle: SocketHandle,
  from_local: mpsc::Receiver<Bytes>,
  to_local: Option<mpsc::Sender<Bytes>>,
  pending: Option<Bytes>,
  local_eof: bool,
  fin_sent: bool,
  target: SocketAddrV4,
  established: bool,
}

pub struct NetStack {
  pub dev: PacketQueue,
  iface: Interface,
  sockets: SocketSet<'static>,
  conns: Vec<Conn>,
  next_port: u16,
  pub wake: Arc<Notify>,
}

impl NetStack {
  pub fn new(local_ip: Ipv4Addr, remote_ip: Ipv4Addr, mtu: u16) -> Self {
    let mut dev = PacketQueue {
      rx: VecDeque::new(),
      tx: VecDeque::new(),
      mtu: mtu as usize,
    };
    let mut iface = Interface::new(
      Config::new(HardwareAddress::Ip),
      &mut dev,
      SmolInstant::now(),
    );
    iface.update_ip_addrs(|addrs| {
      addrs
        .push(IpCidr::new(IpAddress::Ipv4(local_ip), 32))
        .expect("one address fits");
    });
    iface
      .routes_mut()
      .add_default_ipv4_route(remote_ip)
      .expect("route table has room");
    NetStack {
      dev,
      iface,
      sockets: SocketSet::new(vec![]),
      conns: Vec::new(),
      next_port: 49152,
      wake: Arc::new(Notify::new()),
    }
  }

  /// Open a tunnel connection to `target` and bridge it to `stream`.
  pub fn add_connection(&mut self, stream: TcpStream, target: SocketAddrV4) {
    let mut socket = tcp::Socket::new(
      tcp::SocketBuffer::new(vec![0; TCP_BUF]),
      tcp::SocketBuffer::new(vec![0; TCP_BUF]),
    );
    let port = self.next_port;
    self.next_port = if port == u16::MAX { 49152 } else { port + 1 };
    if let Err(e) = socket.connect(
      self.iface.context(),
      (IpAddress::Ipv4(*target.ip()), target.port()),
      port,
    ) {
      warn!("Connect to {target} failed: {e}");
      return;
    }
    let handle = self.sockets.add(socket);

    let (up_tx, up_rx) = mpsc::channel(CHANNEL_CAP);
    let (down_tx, down_rx) = mpsc::channel(CHANNEL_CAP);
    tokio::spawn(bridge(stream, up_tx, down_rx, self.wake.clone()));
    self.conns.push(Conn {
      handle,
      from_local: up_rx,
      to_local: Some(down_tx),
      pending: None,
      local_eof: false,
      fin_sent: false,
      target,
      established: false,
    });
    debug!("Forwarding new connection to {target} (local port {port})");
  }

  /// Run smoltcp and move data between sockets and local streams.
  /// Outgoing IP packets end up in `dev.tx`.
  pub fn poll(&mut self) {
    let now = SmolInstant::now();
    self.iface.poll(now, &mut self.dev, &mut self.sockets);
    let sockets = &mut self.sockets;
    self.conns.retain_mut(|c| {
      let keep = pump(c, sockets.get_mut::<tcp::Socket>(c.handle));
      if !keep {
        sockets.remove(c.handle);
      }
      keep
    });
    self.iface.poll(now, &mut self.dev, &mut self.sockets);
  }

  /// How long until smoltcp needs to be polled again (timers, retransmits).
  pub fn poll_delay(&mut self) -> Duration {
    self
      .iface
      .poll_delay(SmolInstant::now(), &self.sockets)
      .map(|d| Duration::from_micros(d.total_micros()))
      .unwrap_or(Duration::from_secs(1))
  }
}

/// Returns false once the connection is finished and its socket can be removed.
fn pump(c: &mut Conn, s: &mut tcp::Socket) -> bool {
  if !c.established && s.state() == tcp::State::Established {
    c.established = true;
    debug!("Connected to {}", c.target);
  }
  // local -> tunnel
  loop {
    if c.pending.is_none() {
      match c.from_local.try_recv() {
        Ok(b) => c.pending = Some(b),
        Err(TryRecvError::Empty) => break,
        Err(TryRecvError::Disconnected) => {
          c.local_eof = true;
          break;
        }
      }
    }
    if !s.can_send() {
      break;
    }
    let p = c.pending.as_mut().expect("set above");
    match s.send_slice(p) {
      Ok(n) => p.advance(n),
      Err(_) => break,
    }
    if p.is_empty() {
      c.pending = None;
    } else {
      break;
    }
  }
  if c.local_eof && c.pending.is_none() && !c.fin_sent {
    s.close();
    c.fin_sent = true;
  }

  // tunnel -> local
  if let Some(tx) = &c.to_local {
    while s.can_recv() {
      match tx.try_reserve() {
        Ok(permit) => {
          let data = s
            .recv(|b| (b.len(), Bytes::copy_from_slice(b)))
            .unwrap_or_default();
          permit.send(data);
        }
        // local side is slow; data stays in the socket buffer, window closes
        Err(TrySendError::Full(())) => break,
        Err(TrySendError::Closed(())) => {
          s.abort();
          break;
        }
      }
    }
    let peer_fin = matches!(
      s.state(),
      tcp::State::CloseWait
        | tcp::State::LastAck
        | tcp::State::Closing
        | tcp::State::TimeWait
        | tcp::State::Closed
    );
    if peer_fin && !s.can_recv() {
      c.to_local = None; // EOF towards the local client
    }
  }

  let done = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait);
  if done && !c.established {
    warn!("Connection to {} failed (reset or timeout)", c.target);
  } else if done {
    debug!("Connection to {} closed", c.target);
  }
  !done
}

/// Copy between a local TCP stream and the main loop's channels.
async fn bridge(
  stream: TcpStream,
  to_main: mpsc::Sender<Bytes>,
  mut from_main: mpsc::Receiver<Bytes>,
  wake: Arc<Notify>,
) {
  let (mut r, mut w) = stream.into_split();
  let up_wake = wake.clone();
  let up = async move {
    let mut buf = vec![0u8; CHUNK];
    loop {
      match r.read(&mut buf).await {
        Ok(0) | Err(_) => break,
        Ok(n) => {
          if to_main
            .send(Bytes::copy_from_slice(&buf[..n]))
            .await
            .is_err()
          {
            break;
          }
          up_wake.notify_one();
        }
      }
    }
    drop(to_main);
    up_wake.notify_one();
  };
  let down = async move {
    while let Some(b) = from_main.recv().await {
      // freed a channel slot: let the main loop move more data
      wake.notify_one();
      if w.write_all(&b).await.is_err() {
        break;
      }
    }
    let _ = w.shutdown().await;
    wake.notify_one();
  };
  tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn connect_emits_syn() {
    let mut stack = NetStack::new(
      Ipv4Addr::new(192, 168, 2, 230),
      Ipv4Addr::new(192, 168, 2, 1),
      1280,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
      .await
      .unwrap();
    stack.add_connection(client, "192.168.2.6:22".parse().unwrap());
    assert_eq!(stack.conns.len(), 1, "connect failed");
    stack.poll();
    let syn = stack.dev.tx.pop_front().expect("no SYN sent");
    assert_eq!(&syn[16..20], &[192, 168, 2, 6]); // IPv4 destination
  }
}
