# Contributing to sinty-sdb

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-sdb
cd sinty-sdb
go build ./...
go test ./...
```

## Guidelines

- Keep changes additive and tested. sinty-sdb is a privileged bridge onto a device, so a
  regression can widen the attack surface; prefer small, verifiable commits over large rewrites.
- Match the surrounding style. Comments explain WHY, not WHAT.
- The assistance probe (`internal/assist/probe.bin`) is a generated artifact embedded in the
  daemon. After changing anything under `internal/assist/probe`, rebuild it with
  `go generate ./internal/assist` and commit the refreshed binary.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-or-later.
