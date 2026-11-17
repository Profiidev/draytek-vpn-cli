//! Headless DrayTek SSL VPN client: connects, then exposes remote TCP services
//! as local port forwards through a userspace TCP/IP stack (no TUN, no root).

mod netstack;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::ExitCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use draytek_vpn_cli::connection;
use draytek_vpn_cli::constants::*;
use draytek_vpn_cli::engine_common::{execute_actions, send_ppp_frame, PingKeeper};
use draytek_vpn_cli::keepalive::KeepaliveTracker;
use draytek_vpn_cli::negotiate::{self, NegotiationStatus};
use draytek_vpn_cli::protocol::fsm::FsmEvent;
use draytek_vpn_cli::protocol::ppp::PppFrame;
use draytek_vpn_cli::protocol::ppp_control::PppControlFrame;
use draytek_vpn_cli::protocol::sstp::SstpPacket;
use draytek_vpn_cli::types::ConnectionProfile;

use netstack::NetStack;

const USAGE: &str = "\
Usage: draytek-vpn-cli -L [bind:]lport:host:rport [-L ...]

Connects to a DrayTek SSL VPN and forwards local TCP ports to hosts behind it.
Prints \"ready\" on stdout once all forwards are listening.

Environment:
  DRAYTEK_SERVER       host[:port] of the VPN server (port defaults to 443)
  DRAYTEK_USER         VPN username
  DRAYTEK_PASSWORD     VPN password
  DRAYTEK_CERT_SHA256  SHA-256 fingerprint of the server certificate (required)
  RUST_LOG             log level (default: info)

Example:
  draytek-vpn-cli -L 2222:192.168.2.6:22 -L 8443:192.168.2.6:443";

const READ_BUF_SIZE: usize = 16 * 1024;

#[derive(Debug, PartialEq)]
struct Forward {
  bind: SocketAddr,
  target: SocketAddrV4,
}

/// Parse `[bind:]lport:host:rport`. Bind defaults to 127.0.0.1, host must be an IPv4 address.
fn parse_forward(spec: &str) -> Result<Forward> {
  let parts: Vec<&str> = spec.split(':').collect();
  let (bind, lport, host, rport) = match parts.as_slice() {
    [l, h, r] => ("127.0.0.1", *l, *h, *r),
    [b, l, h, r] => (*b, *l, *h, *r),
    _ => bail!("invalid forward {spec:?}, expected [bind:]lport:host:rport"),
  };
  let bind: Ipv4Addr = bind
    .parse()
    .with_context(|| format!("invalid bind address in {spec:?}"))?;
  let lport: u16 = lport
    .parse()
    .with_context(|| format!("invalid local port in {spec:?}"))?;
  let host: Ipv4Addr = host
    .parse()
    .with_context(|| format!("target host in {spec:?} must be an IPv4 address"))?;
  let rport: u16 = rport
    .parse()
    .with_context(|| format!("invalid remote port in {spec:?}"))?;
  Ok(Forward {
    bind: SocketAddr::from((bind, lport)),
    target: SocketAddrV4::new(host, rport),
  })
}

fn parse_server(s: &str) -> Result<(String, u16)> {
  match s.rsplit_once(':') {
    Some((host, port)) => Ok((
      host.to_string(),
      port
        .parse()
        .with_context(|| format!("invalid port in DRAYTEK_SERVER {s:?}"))?,
    )),
    None => Ok((s.to_string(), SSL_PORT)),
  }
}

fn env(name: &str) -> Result<String> {
  match std::env::var(name) {
    Ok(v) if !v.is_empty() => Ok(v),
    _ => bail!("{name} is not set"),
  }
}

fn parse_config() -> Result<(ConnectionProfile, Vec<Forward>)> {
  let mut forwards = Vec::new();
  let mut args = std::env::args().skip(1);
  while let Some(arg) = args.next() {
    match arg.as_str() {
      "-L" => forwards.push(parse_forward(
        &args.next().context("-L needs an argument")?,
      )?),
      "-h" | "--help" => {
        println!("{USAGE}");
        std::process::exit(0);
      }
      other => bail!("unknown argument {other:?}"),
    }
  }
  if forwards.is_empty() {
    bail!("at least one -L forward is required");
  }

  let (server, port) = parse_server(&env("DRAYTEK_SERVER")?)?;
  let profile = ConnectionProfile {
    name: "cli".to_string(),
    server,
    port,
    username: env("DRAYTEK_USER")?,
    password: env("DRAYTEK_PASSWORD")?,
    accept_self_signed: false,
    // mandatory: credentials are only sent to the pinned server
    cert_sha256: Some(env("DRAYTEK_CERT_SHA256")?),
    default_gateway: false,
    route_remote_network: false,
    routes: Vec::new(),
    keepalive: true,
    mru: 0,
  };
  Ok((profile, forwards))
}

struct LogStatus;

impl NegotiationStatus for LogStatus {
  fn on_negotiating_lcp(&self) {
    info!("Negotiating LCP");
  }
  fn on_authenticating(&self) {
    info!("Authenticating");
  }
  fn on_negotiating_ipcp(&self) {
    info!("Negotiating IPCP");
  }
  fn on_auth_failed(&self) {
    error!("Authentication failed");
  }
  fn on_disconnecting(&self) {
    info!("Disconnecting");
  }
  fn check_disconnect(&self) -> bool {
    false
  }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
  tracing_subscriber::fmt()
    .with_writer(std::io::stderr)
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    )
    .init();

  let (profile, forwards) = match parse_config() {
    Ok(c) => c,
    Err(e) => {
      eprintln!("Error: {e:#}\n\n{USAGE}");
      return ExitCode::from(2);
    }
  };

  match run(profile, forwards).await {
    Ok(()) => ExitCode::SUCCESS,
    Err(e) => {
      error!("{e:#}");
      ExitCode::FAILURE
    }
  }
}

async fn run(profile: ConnectionProfile, forwards: Vec<Forward>) -> Result<()> {
  let mut tls = connection::connect(
    &profile.server,
    profile.port,
    &profile.username,
    &profile.password,
    profile.accept_self_signed,
    profile.cert_sha256.as_deref(),
  )
  .await?;

  let neg = negotiate::negotiate(&profile, &mut tls, &LogStatus)
    .await?
    .context("negotiation aborted")?;
  info!(
    "Tunnel up: local={}, remote={}, mtu={}",
    neg.local_ip, neg.remote_ip, neg.mtu
  );

  let mut stack = NetStack::new(neg.local_ip, neg.remote_ip, neg.mtu);
  let mut lcp = neg.lcp_fsm;
  let mut ipcp = neg.ipcp_fsm;
  let mut socket_buf: BytesMut = neg.socket_buf;

  // Listeners only start once the tunnel is up, so "ready" means usable.
  let (new_conn_tx, mut new_conn_rx) = mpsc::channel::<(TcpStream, SocketAddrV4)>(16);
  for fwd in forwards {
    let listener = TcpListener::bind(fwd.bind)
      .await
      .with_context(|| format!("failed to listen on {}", fwd.bind))?;
    info!("Forwarding {} -> {}", fwd.bind, fwd.target);
    let tx = new_conn_tx.clone();
    tokio::spawn(async move {
      loop {
        match listener.accept().await {
          Ok((stream, _)) => {
            if tx.send((stream, fwd.target)).await.is_err() {
              break;
            }
          }
          Err(e) => warn!("accept on {} failed: {e}", fwd.bind),
        }
      }
    });
  }
  println!("ready");
  let _ = std::io::stdout().flush();

  let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler")?;
  let mut keepalive = KeepaliveTracker::new();
  let mut ping = PingKeeper::new(neg.local_ip, neg.remote_ip);
  ping.set_enabled(true);
  let mut read_buf = vec![0u8; READ_BUF_SIZE];
  let wake = stack.wake.clone();

  loop {
    stack.poll();
    while let Some(packet) = stack.dev.tx.pop_front() {
      keepalive.mark_tun_activity();
      send_ppp_frame(&PppFrame::ipv4(packet), &mut tls)
        .await
        .context("failed to send IP packet")?;
    }
    let delay = stack.poll_delay().min(keepalive.next_check_duration());

    tokio::select! {
      n = tls.read(&mut read_buf) => {
        let n = n.context("TLS read failed")?;
        if n == 0 {
          bail!("TLS connection closed by server");
        }
        keepalive.mark_socket_activity();
        socket_buf.extend_from_slice(&read_buf[..n]);

        while let Some(sstp) = SstpPacket::parse_from_buf(&mut socket_buf)? {
          if sstp.is_close() {
            bail!("server closed the tunnel");
          }
          if sstp.is_reply() {
            keepalive.received_reply();
            continue;
          }
          if sstp.is_request() {
            continue;
          }
          if !sstp.is_data() {
            bail!("unexpected SSTP command 0x{:02X}", sstp.command);
          }

          let ppp = PppFrame::parse(&sstp.data)?;
          if ppp.is_ipv4() {
            stack.dev.rx.push_back(ppp.information);
          } else if ppp.is_lcp() {
            let ctrl = PppControlFrame::parse(&ppp.information)?;
            if ctrl.code == PPP_TERMINATE_REQ {
              let ack = PppControlFrame::terminate_ack(ctrl.identifier);
              send_ppp_frame(&PppFrame::new(PPP_LCP, ack.to_bytes()), &mut tls).await?;
              bail!("server terminated the tunnel (LCP)");
            }
            let actions = lcp.handle_event(FsmEvent::ReceiveFrame(ctrl));
            execute_actions(&actions, PPP_LCP, lcp.tag, &mut tls).await?;
          } else if ppp.is_ipcp() {
            let ctrl = PppControlFrame::parse(&ppp.information)?;
            let actions = ipcp.handle_event(FsmEvent::ReceiveFrame(ctrl));
            execute_actions(&actions, PPP_IPCP, ipcp.tag, &mut tls).await?;
          } else if ppp.is_ccp() {
            let ctrl = PppControlFrame::parse(&ppp.information)?;
            if ctrl.code == PPP_CONFIG_REQ {
              let reject = PppControlFrame::config_reject(ctrl.identifier, &ctrl.parse_options()?);
              send_ppp_frame(&PppFrame::new(PPP_CCP, reject.to_bytes()), &mut tls).await?;
            }
          } else {
            debug!("Ignoring PPP protocol 0x{:04X}", ppp.protocol);
          }
        }
      }

      Some((stream, target)) = new_conn_rx.recv() => {
        stack.add_connection(stream, target);
      }

      _ = wake.notified() => {}

      _ = tokio::time::sleep(delay) => {
        if let Some(counter) = keepalive.should_send_request() {
          tls.write_all(&SstpPacket::keepalive_request(counter).to_bytes()).await?;
        }
        if keepalive.is_dead() {
          bail!("keepalive timeout");
        }
        if let Some(frame) = ping.maybe_send() {
          send_ppp_frame(&frame, &mut tls).await?;
        }
      }

      _ = tokio::signal::ctrl_c() => break,
      _ = sigterm.recv() => break,
    }
  }

  info!("Shutting down");
  let actions = lcp.handle_event(FsmEvent::Close);
  execute_actions(&actions, PPP_LCP, lcp.tag, &mut tls).await?;
  tls.write_all(&SstpPacket::close().to_bytes()).await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn forward_parsing() {
    assert_eq!(
      parse_forward("2222:192.168.2.6:22").unwrap(),
      Forward {
        bind: "127.0.0.1:2222".parse().unwrap(),
        target: "192.168.2.6:22".parse().unwrap(),
      }
    );
    assert_eq!(
      parse_forward("0.0.0.0:8443:192.168.2.6:443").unwrap().bind,
      "0.0.0.0:8443".parse::<SocketAddr>().unwrap()
    );
    assert!(parse_forward("2222:example.com:22").is_err());
    assert!(parse_forward("2222:192.168.2.6").is_err());
    assert!(parse_forward("99999:192.168.2.6:22").is_err());
    assert!(parse_forward("a:b:c:d:e").is_err());
  }

  #[test]
  fn server_parsing() {
    assert_eq!(
      parse_server("vpn.example").unwrap(),
      ("vpn.example".into(), 443)
    );
    assert_eq!(
      parse_server("vpn.example:4433").unwrap(),
      ("vpn.example".into(), 4433)
    );
    assert!(parse_server("vpn.example:x").is_err());
  }
}
