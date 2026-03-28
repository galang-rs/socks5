module github.com/galang-rs/socks5

go 1.25.0

require (
	github.com/galang-rs/ovpn v0.0.0
	github.com/galang-rs/wireguard v0.0.0
)

require (
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace (
	github.com/galang-rs/ovpn => ../ovpn
	github.com/galang-rs/wireguard => ../wiregaurd
)
