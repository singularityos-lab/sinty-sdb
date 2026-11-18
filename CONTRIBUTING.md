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

## Device- and environment-specific code

Code that exists only because of a specific device, architecture, firmware or environment must be marked on the line above it:

```
DEVICE-FIX(<scope>): <what breaks without this>
```

- `<scope>` is one of: `arm64`, `x86_64`, `uno-q`, `jetson`, `msm`, `nvidia`, `intel`, `amd`, `no-tpm`, `vm`, `u-boot`, `uefi`. A new scope is added to this list in the same pull request that first uses it.
- The text states what fails on that device without the code, not what the code does.
- Use the comment syntax of the file's language.
- This covers driver names, hardware probes, architecture constants, firmware quirks, boot-chain differences and anything gated on a specific environment.
- A pull request that adds or changes such code without the marker is not merged.
- `git grep -n "DEVICE-FIX("` lists every marker in the repository.
