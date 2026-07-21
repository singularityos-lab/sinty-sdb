# Sinty Debug Bridge

The debug bridge for Sinty OS: a development host connects to a device over the
network, with paired-key authentication instead of a cable.

It ships two binaries from one source tree:

| Binary | Runs on | Purpose |
|---|---|---|
| `sdbd` | the device | daemon that accepts paired hosts and serves a local control API for the on-device UI |
| `sdb` | the development host | client that pairs with a device and runs shell, file transfer, port forwarding and log commands over the pairing |

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

## Commands

Pairing and keyring management:

```sh
sdb pair <address>       pair with a device using the code on its screen
sdb devices              list the devices this host is paired with
sdb revoke <label>       remove a paired host from a device's keyring
```

Working with a paired device, each over one multiplexed session:

```sh
sdb shell [--root] [cmd...]     run a command or a shell; --root asks the device
sdb push <local> <remote>       copy a file to the device
sdb pull <remote> <local>       copy a file from the device
sdb logs [unit]                 stream a unit's captured logs
sdb forward <local> <device>    tunnel a local address to a device address
sdb forward -R <bind> <target>  reverse: the device binds and tunnels to the host
```

A shell runs as an unprivileged bridge user by default. A root shell, a write
outside that user's home, and binding a low port are each granted only after the
device's owner confirms the action on the device screen, one confirmation per
action. A refusal, or no owner present, leaves the request unprivileged.

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
- The daemon runs commands as a dedicated unprivileged user with no access to the
  owner's encrypted home or to the display seat. Every privileged action is
  mediated per action by the system's own broker, which asks the owner to confirm
  on the device; the daemon grants nothing on its own and fails closed.
- Paths in file transfer are confined and never follow a symlink out of their
  root, and every transfer is verified against a hash at its destination.

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
