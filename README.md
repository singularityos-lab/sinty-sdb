# Sinty Debug Bridge

The debug bridge for Sinty OS: a development host connects to a device over the
network, with paired-key authentication instead of a cable.

It ships two binaries from one source tree:

| Binary | Runs on | Purpose |
|---|---|---|
| `sdbd` | the device | daemon that accepts paired hosts and serves a local control API for the on-device UI |
| `sdb` | the development host | client that pairs with a device, lists paired devices, and revokes a pairing |

Unlike a USB debug bridge, `sdbd` works over TCP, so it fits a laptop with no
device-mode USB controller. The first connection to a device is authorised by a
one-time code shown on the device's own screen; every later connection uses the
stored key alone, with no code.

## Availability

The bridge is a development-image feature and is off by default. `sdbd` refuses
to start unless both markers are present:

- `/etc/atom/dev.enabled`, the development image gate
- `/var/lib/sinty-sdb/enabled`, the per-bridge opt-in

The two are deliberately separate: turning the bridge off must not disable
developer mode, and it must not disable the control that turns the bridge back
on. An absent marker means off, so a fresh image carries no listener until it is
asked for one.

## Security model

- Transport is TLS 1.3 with ed25519 device and host keys, pinned on both sides.
  Identity is the SHA-256 of the key, not a certificate chain.
- Pairing needs a short-lived, single-use code read from the device screen, plus
  the host key fingerprint shown on the device so it can be checked by eye. The
  code proves physical presence; the fingerprint prevents trusting an interposed
  key. Both are required.
- After pairing, a connection authenticates by the stored key only. An unknown
  key is refused. There is no first-connection grace.
- Pairing is rate limited with progressive backoff. An absent or damaged keystore
  trusts nobody.
- The daemon holds no privilege of its own; privileged actions belong to a later
  phase and are mediated by the system's own broker, not by this daemon.

## Build

Go 1.26, no third-party dependencies.

```sh
go build ./...
```

## Test

```sh
go test ./...
```

## License

GPL-3.0-or-later, see [LICENSE](LICENSE).
