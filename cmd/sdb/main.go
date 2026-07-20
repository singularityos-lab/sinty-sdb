// Command sdb is the host side of the Sinty Debug Bridge.
//
// Phase 1 carries no useful command on purpose: it builds the door, not what
// goes through it. Only pairing, listing and revocation are here, so that the
// authentication underneath them is settled before anything is built on top.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/client"
	"github.com/singularityos-lab/sinty-sdb/internal/keys"
)

func main() { os.Exit(run(os.Args[1:])) }

const usage = `sdb is the Sinty Debug Bridge client.

usage:
  sdb pair <address>      pair this machine with a device
  sdb devices             list the devices this machine is paired with
  sdb revoke <label>      remove a paired host from a device's keyring
`

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "pair":
		return cmdPair(args[1:])
	case "devices":
		return cmdDevices(args[1:])
	case "revoke":
		return cmdRevoke(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sdb: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// configDir is where the host identity and the paired device record live.
func configDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate configuration directory: %w", err)
	}
	return filepath.Join(base, "sinty-sdb"), nil
}

func defaultLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unnamed-host"
}

func cmdPair(args []string) int {
	fs := flag.NewFlagSet("sdb pair", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	label := fs.String("label", defaultLabel(), "name this machine will carry in the device's keyring")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "sdb pair: one device address is required")
		return 2
	}
	addr := fs.Arg(0)

	cfg, err := configDir(*dir)
	if err != nil {
		return fail(err)
	}
	id, err := keys.LoadOrCreate(cfg, "host")
	if err != nil {
		return fail(err)
	}
	known, err := client.OpenKnown(filepath.Join(cfg, "devices.json"))
	if err != nil {
		return fail(err)
	}

	c := client.New(id)
	conn, err := c.Dial(addr, "")
	if err != nil {
		return fail(err)
	}
	defer conn.Close()

	deviceFP, err := client.PairBegin(conn, *label)
	if err != nil {
		return fail(err)
	}

	fmt.Println("This machine's key fingerprint:")
	fmt.Println("  " + keys.Display(c.Fingerprint()))
	fmt.Println()
	fmt.Println("Check that the device screen shows the same fingerprint before you continue.")
	fmt.Println("If it shows anything else, stop: something is answering in the device's place.")
	fmt.Println()
	fmt.Println("Device key fingerprint:")
	fmt.Println("  " + keys.Display(deviceFP))
	fmt.Println()
	fmt.Print("Pairing code shown on the device: ")

	code, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(code) == "" {
		return fail(errors.New("no pairing code was entered"))
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return fail(errors.New("no pairing code was entered"))
	}

	if err := client.PairSubmit(conn, *label, code); err != nil {
		return fail(err)
	}
	if err := known.Add(client.Device{
		Address:     addr,
		Fingerprint: deviceFP,
		Label:       *label,
		PairedAt:    time.Now(),
	}); err != nil {
		return fail(err)
	}
	fmt.Println()
	fmt.Println("Paired. Later connections use the key alone, with no code.")
	return 0
}

func cmdDevices(args []string) int {
	fs := flag.NewFlagSet("sdb devices", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	offline := fs.Bool("offline", false, "list the record without contacting the devices")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := configDir(*dir)
	if err != nil {
		return fail(err)
	}
	known, err := client.OpenKnown(filepath.Join(cfg, "devices.json"))
	if err != nil {
		return fail(err)
	}
	devices := known.List()
	if len(devices) == 0 {
		fmt.Println("No paired devices. Run: sdb pair <address>")
		return 0
	}
	id, err := keys.LoadOrCreate(cfg, "host")
	if err != nil {
		return fail(err)
	}
	c := client.New(id)
	for _, d := range devices {
		state := "not checked"
		if !*offline {
			state = probe(c, d)
		}
		fmt.Printf("%-24s %-14s %s\n", d.Address, state, keys.Display(d.Fingerprint))
	}
	return 0
}

// probe opens a key-only connection, which is the whole of level 2: no code is
// offered and none is accepted.
func probe(c *client.Client, d client.Device) string {
	conn, err := c.Dial(d.Address, d.Fingerprint)
	if err != nil {
		return "offline"
	}
	defer conn.Close()
	if err := client.Hello(conn); err != nil {
		return "refused"
	}
	return "paired"
}

func cmdRevoke(args []string) int {
	fs := flag.NewFlagSet("sdb revoke", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "sdb revoke: one host label is required")
		return 2
	}
	label := fs.Arg(0)

	cfg, err := configDir(*dir)
	if err != nil {
		return fail(err)
	}
	known, err := client.OpenKnown(filepath.Join(cfg, "devices.json"))
	if err != nil {
		return fail(err)
	}
	var target client.Device
	if *addr == "" {
		target, err = known.Only()
	} else {
		target, err = known.Lookup(*addr)
	}
	if err != nil {
		return fail(err)
	}
	id, err := keys.LoadOrCreate(cfg, "host")
	if err != nil {
		return fail(err)
	}
	conn, err := client.New(id).Dial(target.Address, target.Fingerprint)
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	if err := client.Revoke(conn, label); err != nil {
		return fail(err)
	}
	fmt.Printf("Revoked %s on %s.\n", label, target.Address)
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "sdb:", err)
	return 1
}
