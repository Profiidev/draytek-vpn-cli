/// TLS connection and HTTP CONNECT handshake.
use anyhow::{bail, Context, Result};
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::{debug, info};

use crate::constants::CLIENT_NAME;

/// Establish a TLS connection and perform the HTTP CONNECT handshake.
///
/// Returns the TLS stream ready for binary SSTP framing.
pub async fn connect(
  server: &str,
  port: u16,
  username: &str,
  password: &str,
  accept_self_signed: bool,
  cert_sha256: Option<&str>,
) -> Result<SslStream<TcpStream>> {
  let pin = cert_sha256.map(normalize_pin).transpose()?;

  // Step 1: TCP connection
  let addr = format!("{server}:{port}");
  info!("Connecting to {addr}");
  let tcp_stream = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    TcpStream::connect(&addr),
  )
  .await
  .context("TCP connect timeout")?
  .context("TCP connect failed")?;

  tcp_stream
    .set_nodelay(true)
    .context("Failed to set TCP_NODELAY")?;

  // Step 2: TLS handshake
  info!("Starting TLS handshake");
  let mut builder =
    SslConnector::builder(SslMethod::tls()).context("Failed to create SSL connector")?;
  // DrayTek routers require legacy TLS renegotiation
  builder.set_options(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  // A pin replaces CA verification: the leaf cert is checked by fingerprint below
  if accept_self_signed || pin.is_some() {
    builder.set_verify(SslVerifyMode::NONE);
  }

  let connector = builder.build();
  let ssl = connector
    .configure()
    .context("Failed to configure SSL")?
    .into_ssl(server)
    .context("Failed to create SSL instance")?;

  let mut tls_stream = SslStream::new(ssl, tcp_stream).context("Failed to create SslStream")?;

  Pin::new(&mut tls_stream)
    .connect()
    .await
    .context("TLS handshake failed")?;

  // Check the pin before any credentials are sent
  if let Some(want) = pin {
    let cert = tls_stream
      .ssl()
      .peer_certificate()
      .context("Server sent no certificate")?;
    let got: String = cert
      .digest(MessageDigest::sha256())
      .context("Failed to hash server certificate")?
      .iter()
      .map(|b| format!("{b:02x}"))
      .collect();
    if got != want {
      bail!("Server certificate SHA-256 {got} does not match pinned {want}");
    }
    info!("Server certificate matches pinned SHA-256");
  } else if accept_self_signed {
    tracing::warn!("Certificate not verified: set cert-sha256 to pin the server certificate");
  }

  info!("TLS connection established");

  // Step 3: HTTP CONNECT handshake
  let credentials =
    base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));

  let request = format!(
    "CONNECT / HTTP/1.0\r\n\
         Host:{server}\r\n\
         Agent: {CLIENT_NAME}\r\n\
         Authorization: Basic {credentials}\r\n\
         \r\n"
  );

  debug!("Sending HTTP CONNECT");
  Pin::new(&mut tls_stream)
    .write_all(request.as_bytes())
    .await
    .context("Failed to send HTTP CONNECT")?;

  // Read HTTP response line
  let mut response_buf = Vec::with_capacity(256);
  let mut byte = [0u8; 1];
  loop {
    Pin::new(&mut tls_stream)
      .read_exact(&mut byte)
      .await
      .context("Failed to read HTTP response")?;
    response_buf.push(byte[0]);
    // Look for \r\n\r\n (end of HTTP headers)
    if response_buf.len() >= 4
      && response_buf[response_buf.len() - 4..] == [b'\r', b'\n', b'\r', b'\n']
    {
      break;
    }
    if response_buf.len() > 4096 {
      bail!("HTTP response too large");
    }
  }

  let response_str = String::from_utf8_lossy(&response_buf);
  debug!("HTTP response: {}", response_str.trim());

  // Parse status code from first line
  let first_line = response_str.lines().next().unwrap_or("");
  let status_code = parse_http_status(first_line)?;

  if status_code != 200 {
    bail!("HTTP CONNECT failed with status {status_code}: {first_line}");
  }

  info!("HTTP CONNECT successful, switching to binary mode");
  Ok(tls_stream)
}

/// Parse status code from an HTTP response line like "HTTP/1.0 200 OK".
fn parse_http_status(line: &str) -> Result<u16> {
  let re = regex::Regex::new(r"HTTP/[\d.]+ (\d+)").unwrap();
  let caps = re.captures(line).context("Invalid HTTP response line")?;
  let code: u16 = caps[1].parse().context("Invalid status code")?;
  Ok(code)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_http_status() {
    assert_eq!(parse_http_status("HTTP/1.0 200 OK").unwrap(), 200);
    assert_eq!(parse_http_status("HTTP/1.1 403 Forbidden").unwrap(), 403);
    assert_eq!(
      parse_http_status("HTTP/1.0 500 Internal Server Error").unwrap(),
      500
    );
    assert!(parse_http_status("garbage").is_err());
  }
}

/// Normalize a SHA-256 pin to 64 lowercase hex chars (accepts `AA:BB:..` from `openssl x509 -fingerprint`).
fn normalize_pin(pin: &str) -> Result<String> {
  let hex: String = pin
    .chars()
    .filter(|c| *c != ':' && !c.is_whitespace())
    .collect::<String>()
    .to_ascii_lowercase();
  if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
    bail!("cert-sha256 must be 64 hex chars (colons optional), got {pin:?}");
  }
  Ok(hex)
}

#[cfg(test)]
mod pin_tests {
  use super::normalize_pin;

  #[test]
  fn normalizes_and_rejects() {
    let colon = ["AB"; 32].join(":");
    assert_eq!(normalize_pin(&colon).unwrap(), "ab".repeat(32));
    assert_eq!(normalize_pin(&"0f".repeat(32)).unwrap(), "0f".repeat(32));
    assert!(normalize_pin("").is_err());
    assert!(normalize_pin(&"zz".repeat(32)).is_err());
    assert!(normalize_pin(&"ab".repeat(31)).is_err());
  }
}
