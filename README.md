# draytek-vpn-cli

Headless client for the DrayTek SSL VPN (the "SSL" profile type of the DrayTek Smart VPN Client).
It connects to a Vigor router and exposes hosts behind it as **local TCP port forwards**.
The forwards go through a userspace TCP/IP stack ([smoltcp](https://github.com/smoltcp-rs/smoltcp)),
so it needs no root, no `NET_ADMIN` and no `/dev/net/tun`. That makes it usable in unprivileged CI
runners such as GitLab shared runners.

The binary is static and needs nothing else at runtime.

## Usage

```sh
export DRAYTEK_SERVER=vpn.example.com          # host[:port], port defaults to 443
export DRAYTEK_USER=me
export DRAYTEK_PASSWORD=secret
export DRAYTEK_CERT_SHA256=A8C622FC...5DC802AF # required, see below

draytek-vpn-cli -L 2222:192.168.2.6:22 -L 8443:192.168.2.6:443
```

- `-L [bind:]lport:host:rport` forwards `bind:lport` (bind defaults to `127.0.0.1`) to `host:rport`
  behind the VPN. It can be repeated. `host` must be an IPv4 address: there is no DNS inside the tunnel.
- `ready` is printed on stdout once the tunnel is up and every forward is listening. Logs go to stderr
  (`RUST_LOG` sets the level).
- SIGINT and SIGTERM close the tunnel cleanly. If the tunnel is lost, the process exits with status 1.
- Only TCP is forwarded. ICMP (ping) and UDP are not.

### Certificate pin

Vigor routers usually serve a self-signed certificate, so normal CA verification is impossible.
Instead, the certificate's SHA-256 fingerprint is **required**. It is checked before any credentials
are sent. Read it once from a network you trust:

```sh
openssl s_client -legacy_renegotiation -connect vpn.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Colons and case don't matter.

## GitLab CI

Store `DRAYTEK_USER` and `DRAYTEK_PASSWORD` as masked and protected CI/CD variables.

```yaml
deploy:
  image: alpine:3
  variables:
    DRAYTEK_SERVER: vpn.example.com
    DRAYTEK_CERT_SHA256: A8C622FC50D4C311CF338D086E72B52905E7CD18835F5F7F45339A1F5DC802AF
  script:
    - apk add --no-cache curl openssh-client rsync
    - curl -fsSLo /usr/local/bin/draytek-vpn-cli https://github.com/Profiidev/draytek-vpn-cli/releases/download/v0.1.0/draytek-vpn-cli-x86_64-linux
    - chmod +x /usr/local/bin/draytek-vpn-cli
    - draytek-vpn-cli -L 2222:192.168.2.6:22 -L 8443:192.168.2.6:443 > vpn.log 2>&1 &
    - timeout 30 sh -c 'until grep -q ready vpn.log; do sleep 1; done' || (cat vpn.log; exit 1)
    - rsync -e "ssh -p 2222" ./dist/ deploy@127.0.0.1:/srv/app/
    - curl --resolve app.internal:8443:127.0.0.1 https://app.internal:8443/health
```

To bake the binary into your own image instead:

```dockerfile
COPY --from=ghcr.io/profiidev/draytek-vpn-cli/draytek-vpn-cli:latest /draytek-vpn-cli /usr/local/bin/
```

## Releases

- The `Release Version` workflow (manual) bumps `Cargo.toml` and opens a release PR, which merges itself.
- Merging tags the version. The tag builds the `linux/amd64` and `linux/arm64` image
  `ghcr.io/profiidev/draytek-vpn-cli/draytek-vpn-cli` and attaches the static binaries
  (`draytek-vpn-cli-{x86_64,aarch64}-linux`) to the GitHub release.

## Credits and license

The protocol implementation (`src/` except `main.rs` and `netstack.rs`) is copied from
[julianjc84/draytek-ssl-vpn-client-linux](https://github.com/julianjc84/draytek-ssl-vpn-client-linux)
at `3f4666f`. It is extended with SHA-256 certificate pinning.

Licensed under GPL-3.0, like upstream. See [LICENSE](LICENSE).
