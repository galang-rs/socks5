<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT" />
  <img src="https://img.shields.io/badge/Platform-Cross%20Platform-blueviolet?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status" />
</p>

<h1 align="center">🧦 SOCKS5 Proxy Go</h1>

<p align="center">
  <strong>A modular, pure-Go SOCKS5 proxy server with multi-tunnel VPN backend support.</strong><br/>
  No CGo. No system drivers. Route traffic through WireGuard, OpenVPN, or direct connections.
</p>

<p align="center">
  <em>Full RFC 1928 (CONNECT) and RFC 1929 (username/password auth) implementation — with pluggable VPN backends, multi-credential authentication, and a custom lightweight userspace TCP/IP stack for tunnel connectivity. No gVisor dependency.</em>
</p>

---

## ✨ Features

### 🛡️ Full SOCKS5 Protocol
- **RFC 1928 Compliance** — Complete SOCKS5 CONNECT command implementation
- **RFC 1929 Authentication** — Username/password authentication support
- **Method Negotiation** — Proper SOCKS5 auth method negotiation handshake
- **Error Handling** — Standard SOCKS5 reply codes for all error conditions
- **Graceful Shutdown** — Context-aware server with clean connection teardown

### 🔐 Multi-Credential Authentication
- **Multiple Passwords Per User** — Same username can authenticate with different passwords
- **Variadic Credential Setup** — Flexible `auth.Credential()` functional builder
- **Concurrent Safe** — Thread-safe credential validation for high-throughput proxying

### 🌐 Pluggable VPN Backends
- **Direct Backend** — No VPN, straightforward `net.Dialer` connections
- **WireGuard Backend** — Route all proxied traffic through a WireGuard tunnel
- **OpenVPN Backend** — Route all proxied traffic through an OpenVPN tunnel
- **Backend Interface** — Clean `backend.Backend` interface for custom implementations
- **Hot-swappable** — Switch backends without modifying proxy server code

### 🔧 Custom Virtual NetStack
- **Lightweight TCP/IP Stack** — Userspace network stack for VPN tunnel I/O
- **DNS Resolution** — Sends DNS queries as UDP packets through the tunnel
- **TCP Handshake** — Full 3-way handshake via raw IP packets over TUN
- **Data Relay** — TCP segmentation and reassembly through the tunnel
- **Connection Teardown** — Proper FIN/ACK sequence for clean disconnects
- **Zero gVisor Dependency** — Custom implementation, no heavy external stacks

### ⚙️ Architecture
- **Functional Options Pattern** — `socks5.WithAddr()`, `socks5.WithAuth()`, `socks5.WithBackend()`
- **Modular Package Design** — Separated `auth`, `backend`, `netstack`, `socks5` packages
- **Concurrent Connection Handling** — Each SOCKS5 connection handled in its own goroutine
- **Context-Aware** — Full `context.Context` support for cancellation and timeouts

---

## 📦 Installation

```bash
go get github.com/galang-rs/socks5
```

---

## 🚀 How to Use

### Full Example (WireGuard Backend)

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/galang-rs/socks5/auth"
    "github.com/galang-rs/socks5/backend"
    "github.com/galang-rs/socks5/socks5"
)

func main() {
    ctx, stop := signal.NotifyContext(context.Background(),
        os.Interrupt, syscall.SIGTERM)
    defer stop()

    // Multi-auth: same user can have multiple passwords
    authenticator := auth.New(
        auth.Credential("user1", "pass1"),
        auth.Credential("user1", "pass2"),
        auth.Credential("admin", "secret"),
    )

    // Start WireGuard backend
    be, err := backend.NewWireGuard(ctx, backend.WireGuardConfig{
        ConfigFile: "wg0.conf",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer be.Close()

    // Start SOCKS5 proxy
    srv := socks5.New(
        socks5.WithAddr(":1080"),
        socks5.WithAuth(authenticator),
        socks5.WithBackend(be),
    )

    log.Println("SOCKS5 proxy starting on :1080")
    if err := srv.ListenAndServe(ctx); err != nil {
        log.Fatal(err)
    }
}
```

### Direct Backend (No VPN)

```go
be := backend.NewDirect()

srv := socks5.New(
    socks5.WithAddr(":1080"),
    socks5.WithAuth(authenticator),
    socks5.WithBackend(be),
)
```

### WireGuard Backend

```go
be, err := backend.NewWireGuard(ctx, backend.WireGuardConfig{
    ConfigFile: "wg0.conf",
    DNSServers: []string{"1.1.1.1", "8.8.8.8"}, // optional
})
if err != nil {
    log.Fatal(err)
}
defer be.Close()
```

### OpenVPN Backend

```go
be, err := backend.NewOpenVPN(ctx, backend.OpenVPNConfig{
    ConfigFile: "config.ovpn",
    AuthFile:   "auth.txt", // optional
    DNSServers: []string{"1.1.1.1"}, // optional
})
if err != nil {
    log.Fatal(err)
}
defer be.Close()
```

### Running Tests

```bash
# Build
go build ./...

# Test with curl (direct backend)
curl --socks5 user1:pass1@localhost:1080 https://ifconfig.me

# Test with curl (VPN backend — should show VPN exit IP)
curl --socks5 admin:secret@localhost:1080 https://ifconfig.me
```

---

## 🏗️ Project Structure

```
socks5/
├── auth/
│   └── auth.go                  # Multi-credential SOCKS5 authenticator
├── backend/
│   ├── backend.go               # Backend interface definition
│   ├── direct.go                # Direct (no VPN) backend
│   ├── wireguard.go             # WireGuard tunnel backend
│   └── openvpn.go               # OpenVPN tunnel backend
├── netstack/
│   ├── stack.go                 # Virtual TCP/IP stack controller
│   ├── conn.go                  # net.Conn implementation over netstack
│   ├── dns.go                   # DNS resolver via UDP over tunnel
│   ├── ip.go                    # IPv4 packet builder & parser
│   ├── tcp.go                   # TCP segment builder & parser
│   └── udp.go                   # UDP datagram builder & parser
├── socks5/
│   └── server.go                # SOCKS5 proxy server (RFC 1928/1929)
├── test/
│   └── socks5_test.go           # Integration tests
├── go.mod
└── go.sum
```

---

## 🏛️ Architecture

```
SOCKS5 Client
      │
      ▼
┌─────────────┐
│  auth.Multi │  ← Multi-credential username/password authentication
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ socks5.Server│  ← RFC 1928 CONNECT handler
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ backend.Backend  │  ← Pluggable backend interface
└──────┬───────────┘
       │
       ├─────────────────┬─────────────────┐
       ▼                 ▼                 ▼
┌────────────┐   ┌──────────────┐   ┌─────────────┐
│   Direct   │   │  WireGuard   │   │   OpenVPN   │
│ net.Dialer │   │ TUN+netstack │   │ TUN+netstack│
└────────────┘   └──────────────┘   └─────────────┘
```

The `netstack` package implements a lightweight virtual TCP/IP stack that bridges SOCKS5 TCP connections to raw IP packets for the TUN device:

1. **DNS Resolution** — Sends DNS queries as UDP through the tunnel
2. **TCP Handshake** — 3-way handshake via raw IP packets
3. **Data Relay** — Segments TCP data into IP packets through TUN
4. **Connection Teardown** — Proper FIN/ACK sequence

---

## 🔧 Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/galang-rs/wireguard` | WireGuard VPN tunnel implementation |
| `github.com/galang-rs/ovpn` | OpenVPN tunnel implementation |
| `golang.org/x/crypto` | Cryptographic primitives (indirect) |

---

## 📄 License

```
MIT License

Copyright (c) 2026 Galang Reisduanto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

ADDITIONAL TERMS:

1. Attribution — If you use this software in a product, an acknowledgment
   in the product documentation or "About" section would be appreciated
   but is not required.

2. Non-Endorsement — The name "galang-rs" or "Galang Reisduanto" may not
   be used to endorse or promote products derived from this software without
   specific prior written permission.

3. Good Faith — This software is shared in good faith for the benefit of
   the open-source community. Commercial use is permitted and encouraged.
```

---

## 📬 Feature Requests & Contact

Have an idea, bug report, or custom feature request? Feel free to reach out!

<p align="center">
  <a href="mailto:galangreisduanto@gmail.com">
    <img src="https://img.shields.io/badge/Email-galangreisduanto%40gmail.com-red?style=for-the-badge&logo=gmail&logoColor=white" alt="Email" />
  </a>
</p>

<p align="center">
  📧 <strong>Email:</strong> <a href="mailto:galangreisduanto@gmail.com">galangreisduanto@gmail.com</a>
</p>

---

## ☕ Support & Donate

If this project helped you, consider buying me a coffee! Your support helps keep the project active and maintained.

<p align="center">
  <a href="https://www.paypal.com/paypalme/SAMdues">
    <img src="https://img.shields.io/badge/Donate-PayPal-blue?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate via PayPal" />
  </a>
</p>

<p align="center">
  📧 <strong>PayPal:</strong> <a href="https://paypal.me/SAMdues">galangreisduanto1@gmail.com</a>
</p>

<p align="center">
  Every donation, no matter how small, is greatly appreciated and motivates continued development. 🙏
</p>

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/galang-rs">Galang Reisduanto</a>
</p>
