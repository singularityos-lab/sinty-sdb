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

The bridge is off by default and never runs on its own. `sdbd` starts only when
the owner switches the bridge on in Settings, which creates the persistent
device-policy marker `/var/lib/sinty-sdb/enabled`. Switching it off removes the
marker and stops the daemon, so a device carries no network listener until the
owner asks for one.

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
sdb assist                      run a read-only diagnostic session in memory
```

A shell runs at one of three tiers. By default it is the logged-in user, since a
paired host is the owner's own machine on the owner's own device; with no one
logged in it falls back to an isolated bridge account. `--root` is a root shell,
allowed only on a device the owner has deliberately unlocked and only after a
per-action confirmation, and it fails closed to a non-root shell otherwise. A
write outside the transfer sandbox and binding a low port are likewise confirmed
per action. Ordinary commands from a paired host do not ask again; the broker is
used only for privileged actions. `sdb assist` is the assistance tier: a
bounded, non-root session for
remote support that needs no rooting. Its diagnostic tool is embedded in the
signed daemon, run from an anonymous in-memory file for the session only, and
executed as the isolated bridge account, so it reads diagnostics without the
owner's data, without root, and without leaving a privileged binary on the disk.

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
- The daemon drops privilege for every shell. Root is never the default and never
  reachable without the owner both unlocking the device and confirming the action;
  the isolated bridge account, used for assistance and as the no-login fallback,
  carries no privileged groups and cannot read the owner's encrypted home or reach
  the display seat. Every privileged action is confirmed by the owner on the
  device before it runs; the daemon grants nothing on its own and fails closed.
- Assistance tools are embedded in the signed daemon and executed from an
  anonymous, sealed in-memory file, never written to disk, so a privileged helper
  exists as an attack surface only while an authorized session holds it in memory.
- Relative file transfers are confined to `/var/lib/sinty-sdb/files`, separate
  from the device identity and paired-host keystore. Paths never follow a
  symlink out of that root, and every transfer is verified against a hash at its
  destination.

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

## Use of Generative AI

Maintainers may use generative AI tools as assistants while working on sinty-sdb. Non-trivial assisted commits disclose the tool, model, and scope of the work.

AI tools may assist with code comments, documentation, repetitive code, and issue triage. Maintainers make project decisions and review every assisted change before it is merged.

Use these trailers for non-trivial assisted commits:

```plain
Assisted-by: <tool>:<model-version>
AI-Scope: <what the tool generated and the prompt or a short prompt summary>
```

Single-line completions, renames, and formatting changes do not need trailers.

Coding agents must also follow [AGENTS.md](AGENTS.md) before changing files,
creating commits, or opening pull requests.
